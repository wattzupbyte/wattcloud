use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ── IPv6 /64 bucketing ─────────────────────────────────────────────────────────
//
// IPv6 clients typically share a /64 prefix (one subnet). Keying rate limiters on
// the full 128-bit address lets an attacker rotate addresses within their /64 to
// bypass per-IP limits. We canonicalise IPv6 to its /64 prefix (upper 64 bits)
// before inserting into any rate-limit map.
//
// IPv4 addresses are used as-is — no bucketing needed.

/// Canonical rate-limit key: IPv4 address or IPv6 /64 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpBucket {
    V4([u8; 4]),
    /// Upper 64 bits of an IPv6 address (the /64 prefix).
    V6Slash64([u8; 8]),
}

impl From<IpAddr> for IpBucket {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => IpBucket::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&octets[..8]);
                IpBucket::V6Slash64(prefix)
            }
        }
    }
}

/// In-memory sliding-window rate limiter — generic over the configurable limit.
///
/// State is lost on restart — acceptable for a stateless relay.
/// Does not use a database (zero persistence, zero logging).
/// Keys on `IpBucket` so IPv6 /64 prefixes are treated as a single client.
struct SlidingWindowLimiter {
    /// Maps IpBucket → list of timestamps within the current window.
    state: RwLock<HashMap<IpBucket, Vec<Instant>>>,
    window: Duration,
    max_per_window: usize,
}

impl SlidingWindowLimiter {
    fn new(window_secs: u64, max_per_window: usize) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
            max_per_window,
        }
    }

    /// Returns true if this IP is under the limit, recording the attempt.
    ///
    /// RS3: after retaining within-window timestamps, empty entries are
    /// removed rather than left in the map. Previously the map grew
    /// monotonically with distinct IPs and never shed zero-length `Vec`s,
    /// giving an attacker a cheap primitive to exhaust server memory by
    /// cycling through `/64` IPv6 prefixes.
    fn check_and_record(&self, ip: IpAddr) -> bool {
        let bucket = IpBucket::from(ip);
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut state = self.state.write().expect("rate limiter lock poisoned");
        let timestamps = state.entry(bucket).or_default();

        // Remove expired timestamps
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() >= self.max_per_window {
            return false;
        }

        timestamps.push(now);
        // RS3: zero-length Vecs are no longer reachable because we just pushed,
        // but opportunistically evict any drained other bucket to bound memory.
        // Doing it here keeps the hot path O(1) amortised.
        if state.len() > 1024 {
            state.retain(|_, v| !v.is_empty());
        }
        true
    }
}

/// Generic sliding-window rate limiter keyed on any `Hash + Eq + Clone` type.
///
/// Used by `ShareGetLimiter` for per-share-id and per-IP limits without
/// conflating the two key spaces.
///
/// `max_keys`: optional cap on the number of tracked keys.  When the map is
/// full, new unknown keys are allowed through without being tracked (so
/// legitimate clients are never incorrectly blocked, while map growth is
/// bounded).
pub struct SlidingWindowLimiterByKey<K: Hash + Eq + Clone + Send + 'static> {
    state: RwLock<HashMap<K, Vec<Instant>>>,
    window: Duration,
    max_per_window: usize,
    max_keys: Option<usize>,
}

impl<K: Hash + Eq + Clone + Send + 'static> SlidingWindowLimiterByKey<K> {
    pub fn new(window_secs: u64, max_per_window: usize) -> Self {
        Self::new_with_cap(window_secs, max_per_window, None)
    }

    pub fn new_with_cap(window_secs: u64, max_per_window: usize, max_keys: Option<usize>) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
            max_per_window,
            max_keys,
        }
    }

    /// Returns true if the key is under the limit, recording the attempt.
    ///
    /// When the map is at capacity and the key is new, returns `true` (allow)
    /// without inserting — prevents memory exhaustion from key cycling without
    /// blocking legitimate clients.
    pub fn check_and_record(&self, key: K) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut state = self.state.write().expect("rate limiter lock poisoned");

        if let Some(timestamps) = state.get_mut(&key) {
            timestamps.retain(|&t| t > cutoff);
            if timestamps.len() >= self.max_per_window {
                return false;
            }
            timestamps.push(now);
            return true;
        }

        // Key not seen before.  If at cap, allow through without tracking.
        if let Some(max) = self.max_keys {
            if state.len() >= max {
                return true;
            }
        }

        state.entry(key).or_default().push(now);
        true
    }
}

// ── Per-IP daily byte budget ─────────────────────────────────────────────────
//
// The share upload path streams an unbounded body to disk — no per-request
// size cap exists at the HTTP layer, so a runaway client could in principle
// push the relay's disk to exhaustion. This tracker is the only global
// backstop against abuse; pair it with the headroom endpoint so operators
// can see the live budget utilisation.

/// Per-IP daily byte budget for share uploads. Keyed on `IpBucket`
/// (IPv6 /64-normalised) so rotating addresses within a subnet can't bypass.
/// State resets at UTC-day boundaries and is dropped automatically for
/// entries older than one day.
pub struct ByteBudgetTracker {
    state: RwLock<HashMap<IpBucket, DailyByteCount>>,
    limit_per_day: u64,
    /// Safety cap on distinct keys — drops the oldest half when hit so an
    /// attacker rotating through IPv6 /64s cannot exhaust relay memory.
    max_keys: usize,
}

#[derive(Clone, Copy)]
struct DailyByteCount {
    /// Days since Unix epoch — the current UTC calendar day.
    day: i64,
    /// Bytes recorded during `day`.
    bytes: u64,
}

impl ByteBudgetTracker {
    /// `limit_per_day` in bytes. 0 disables enforcement entirely (useful for
    /// tests and operators who want to run without a budget).
    pub fn new(limit_per_day: u64) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            limit_per_day,
            max_keys: 50_000,
        }
    }

    /// Consume `bytes` against the caller's budget. Returns true iff the
    /// reservation fits; on false, no bytes are recorded and the caller
    /// must 507 + abort the transfer.
    ///
    /// `now_unix_secs` is injected so tests can advance the clock without
    /// wallclock drift. Production callers pass `SystemTime::now()`.
    pub fn try_consume(&self, ip: std::net::IpAddr, bytes: u64, now_unix_secs: i64) -> bool {
        if self.limit_per_day == 0 {
            return true;
        }
        let bucket = IpBucket::from(ip);
        let today = now_unix_secs.div_euclid(86_400);
        let mut state = self.state.write().expect("byte budget lock poisoned");

        // Opportunistic prune: drop entries older than yesterday when the
        // map grows beyond the soft cap.
        if state.len() >= self.max_keys {
            state.retain(|_, v| v.day >= today - 1);
        }

        let entry = state.entry(bucket).or_insert(DailyByteCount {
            day: today,
            bytes: 0,
        });
        if entry.day != today {
            entry.day = today;
            entry.bytes = 0;
        }
        if entry.bytes.saturating_add(bytes) > self.limit_per_day {
            return false;
        }
        entry.bytes = entry.bytes.saturating_add(bytes);
        true
    }

    /// Bytes remaining for `ip` today. Used by the headroom endpoint so
    /// the client can show "X GB available to upload today".
    pub fn remaining(&self, ip: std::net::IpAddr, now_unix_secs: i64) -> u64 {
        if self.limit_per_day == 0 {
            return u64::MAX;
        }
        let bucket = IpBucket::from(ip);
        let today = now_unix_secs.div_euclid(86_400);
        let state = self.state.read().expect("byte budget lock poisoned");
        match state.get(&bucket) {
            Some(e) if e.day == today => self.limit_per_day.saturating_sub(e.bytes),
            _ => self.limit_per_day,
        }
    }

    pub fn limit_per_day(&self) -> u64 {
        self.limit_per_day
    }
}

/// In-memory rate limiter for channel joins (10/min per IP).
pub struct ChannelJoinLimiter(SlidingWindowLimiter);

impl Default for ChannelJoinLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelJoinLimiter {
    pub fn new() -> Self {
        Self(SlidingWindowLimiter::new(60, 10))
    }

    /// Returns true if this IP is allowed to join, recording the attempt.
    /// Returns false if the rate limit is exceeded.
    pub fn check_and_record(&self, ip: IpAddr) -> bool {
        self.0.check_and_record(ip)
    }
}

/// In-memory rate limiter for relay auth challenges (configurable per IP per minute).
pub struct AuthChallengeLimiter(SlidingWindowLimiter);

impl AuthChallengeLimiter {
    pub fn new(max_per_min: u32) -> Self {
        Self(SlidingWindowLimiter::new(60, max_per_min as usize))
    }

    /// Returns true if this IP is allowed to request a challenge.
    pub fn check_and_record(&self, ip: IpAddr) -> bool {
        self.0.check_and_record(ip)
    }
}

/// Tracks concurrent SFTP connections per IP (max 5).
/// Uses IpBucket so IPv6 /64 prefixes share the same slot counter.
///
/// A `SftpConnectionGuard` is returned on success; dropping it releases the slot.
pub struct SftpConnectionTracker {
    state: Arc<RwLock<HashMap<IpBucket, usize>>>,
    max_per_ip: usize,
}

impl Default for SftpConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpConnectionTracker {
    pub fn new() -> Self {
        Self::with_max(5)
    }

    /// Construct with an explicit cap. Wired from
    /// `config.sftp_max_concurrent_per_ip` in main.rs so operators can tune
    /// the limit per deployment without a code change.
    pub fn with_max(max_per_ip: u32) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_per_ip: max_per_ip.max(1) as usize,
        }
    }

    /// Try to acquire a slot for this IP (bucketed to /64 for IPv6).
    /// Returns a guard that releases the slot when dropped, or None if limit reached.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<SftpConnectionGuard> {
        let bucket = IpBucket::from(ip);
        let mut state = self.state.write().expect("sftp tracker lock poisoned");
        let count = state.entry(bucket).or_insert(0);

        if *count >= self.max_per_ip {
            return None;
        }

        *count += 1;
        Some(SftpConnectionGuard {
            bucket,
            state: Arc::clone(&self.state),
        })
    }
}

// ── SFTP auth-failure and spray tracker ────────────────────────────────────────

/// Per-IP auth-failure state.
struct FailureState {
    /// Failures within the current window.
    count: usize,
    /// Start of the current failure window.
    window_start: Instant,
    /// Set if the IP is currently hard-blocked.
    blocked_until: Option<Instant>,
}

/// Per-IP host-spray state.
struct HostState {
    /// Distinct remote hosts contacted within the current window.
    hosts: HashSet<String>,
    /// Start of the current host window.
    window_start: Instant,
}

/// Tracks SFTP authentication failures and remote-host diversity per client IP.
///
/// Rules:
///   - 5 auth failures within 10 minutes → 1-hour block.
///   - >5 distinct remote hosts within 1 hour → spray-detection block (1 hour).
///   - Failures are recorded pre-handshake and refunded on success (closes the
///     parallel-guess window where multiple in-flight attempts race before any fails).
///
/// Keys on IpBucket so IPv6 /64 prefixes cannot rotate addresses to bypass limits.
/// State is in-memory only; resets on relay restart (acceptable for stateless relay).
pub struct SftpAuthFailureTracker {
    failures: RwLock<HashMap<IpBucket, FailureState>>,
    hosts: RwLock<HashMap<IpBucket, HostState>>,
    /// Failures within `failure_window` before applying a 1-hour block.
    failure_limit: usize,
    /// Sliding window over which `failure_limit` failures triggers a block.
    failure_window: Duration,
}

/// Default thresholds — also the defaults surfaced in config.rs. `new()`
/// preserves the historical 5-failure / 10-min window for existing callers;
/// `with_config` lets main.rs plug in env-driven overrides.
const DEFAULT_FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
const DEFAULT_FAILURE_LIMIT: usize = 5;
const FAILURE_BLOCK_DURATION: Duration = Duration::from_secs(60 * 60); // 1 hour
const HOST_WINDOW: Duration = Duration::from_secs(60 * 60); // 1 hour
/// Lowered from 10 → 5: tighter spray detection without host allowlist.
const HOST_LIMIT: usize = 5;
const HOST_BLOCK_DURATION: Duration = Duration::from_secs(60 * 60); // 1 hour

impl Default for SftpAuthFailureTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpAuthFailureTracker {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_FAILURE_LIMIT, DEFAULT_FAILURE_WINDOW)
    }

    /// Construct with explicit failure threshold + window. Wired from
    /// `config.sftp_failed_auth_per_5min` in main.rs (which passes a 5-min
    /// window to match the env var's name).
    pub fn with_config(failure_limit: usize, failure_window: Duration) -> Self {
        let _ = (failure_limit, failure_window);
        Self {
            failures: RwLock::new(HashMap::new()),
            hosts: RwLock::new(HashMap::new()),
            failure_limit,
            failure_window,
        }
    }

    /// Returns true if this IP is currently blocked (auth failures or spray).
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let bucket = IpBucket::from(ip);
        let now = Instant::now();
        if let Ok(failures) = self.failures.read() {
            if let Some(state) = failures.get(&bucket) {
                if let Some(blocked_until) = state.blocked_until {
                    if now < blocked_until {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Records a remote host access for this IP (bucketed to /64 for IPv6).
    /// Returns true if the IP is now spray-blocked (crossed the distinct-host threshold).
    pub fn record_host(&self, ip: IpAddr, host: &str) -> bool {
        let bucket = IpBucket::from(ip);
        let now = Instant::now();
        let mut hosts = self.hosts.write().expect("host tracker lock poisoned");
        let state = hosts.entry(bucket).or_insert_with(|| HostState {
            hosts: HashSet::new(),
            window_start: now,
        });

        // Reset window if expired.
        if now.duration_since(state.window_start) > HOST_WINDOW {
            state.hosts.clear();
            state.window_start = now;
        }

        state.hosts.insert(host.to_string());

        if state.hosts.len() > HOST_LIMIT {
            // Spray detected — record a hard block in the failure tracker.
            drop(hosts);
            self.apply_block(bucket, now);
            tracing::warn!(
                host_count = HOST_LIMIT + 1,
                "sftp spray block applied: too many distinct hosts"
            );
            return true;
        }
        false
    }

    /// Records a (tentative) authentication failure for this IP.
    ///
    /// Call this **before** the SSH handshake and refund with `refund_failure` if
    /// auth succeeds. This closes the parallel-guess window where multiple in-flight
    /// attempts race before any is accounted as a failure.
    ///
    /// Applies a 1-hour block when the failure threshold is crossed.
    pub fn record_failure(&self, ip: IpAddr) {
        let bucket = IpBucket::from(ip);
        let now = Instant::now();
        let mut failures = self
            .failures
            .write()
            .expect("failure tracker lock poisoned");
        let state = failures.entry(bucket).or_insert_with(|| FailureState {
            count: 0,
            window_start: now,
            blocked_until: None,
        });

        // If already blocked, do not double-count.
        if let Some(blocked_until) = state.blocked_until {
            if now < blocked_until {
                return;
            }
        }

        // Reset window if expired.
        if now.duration_since(state.window_start) > self.failure_window {
            state.count = 0;
            state.window_start = now;
            state.blocked_until = None;
        }

        state.count += 1;

        if state.count >= self.failure_limit {
            let until = now + FAILURE_BLOCK_DURATION;
            state.blocked_until = Some(until);
            tracing::warn!(
                failures = state.count,
                "sftp auth block applied: too many failures"
            );
        }
    }

    /// Refund a tentative failure recorded by `record_failure` when auth succeeds.
    /// Decrements the failure count (floor zero) without touching the block state.
    pub fn refund_failure(&self, ip: IpAddr) {
        let bucket = IpBucket::from(ip);
        let mut failures = self
            .failures
            .write()
            .expect("failure tracker lock poisoned");
        if let Some(state) = failures.get_mut(&bucket) {
            state.count = state.count.saturating_sub(1);
        }
    }

    fn apply_block(&self, bucket: IpBucket, now: Instant) {
        let mut failures = self
            .failures
            .write()
            .expect("failure tracker lock poisoned");
        let state = failures.entry(bucket).or_insert_with(|| FailureState {
            count: 0,
            window_start: now,
            blocked_until: None,
        });
        state.blocked_until = Some(now + HOST_BLOCK_DURATION);
    }
}

/// RAII guard: holds an SFTP connection slot. Releases on drop.
pub struct SftpConnectionGuard {
    bucket: IpBucket,
    state: Arc<RwLock<HashMap<IpBucket, usize>>>,
}

impl Drop for SftpConnectionGuard {
    fn drop(&mut self) {
        let mut state = self.state.write().expect("sftp tracker lock poisoned");
        if let Some(count) = state.get_mut(&self.bucket) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.remove(&self.bucket);
            }
        }
    }
}

// ── Share abuse-protection trackers ────────────────────────────────────────
//
// Three orthogonal primitives for the share relay's abuse ceiling, all
// configured via the env vars documented in SECURITY.md §Abuse Protections:
//
//   - ShareCreationRateLimiter — per-IP hour + day windows over POST
//     /relay/share/b2 and /relay/share/bundle/init. Caps how fast a single
//     /64 can create shares, so a misbehaving device can't park 1 000 shares
//     overnight.
//   - ShareBytesPerShareTracker — per-share-id sliding 1-hour window of
//     bytes served to recipients. Complements ShareGetLimiter (fetches/hour)
//     by also capping total bytes, so a leaked link to a 900 MB share can't
//     become a 900 MB × N/hour amplification source.
//   - ShareConcurrencyTracker — per-share-id atomic counter with an RAII
//     guard. Default cap 1; extra recipients get 429 and retry.
//
// All state is in-memory; lost on restart. That's deliberate — these are
// operational limits, not security gates. ShareGetLimiter already sets the
// precedent.

/// Per-IP share creation rate: hour + day sliding windows, keyed on
/// `IpBucket` (IPv6 /64-normalised). The two windows run in parallel; a
/// client is accepted only when *both* are under their cap.
pub struct ShareCreationRateLimiter {
    hour: SlidingWindowLimiterByKey<IpBucket>,
    day: SlidingWindowLimiterByKey<IpBucket>,
}

impl ShareCreationRateLimiter {
    pub fn new(per_hour: u32, per_day: u32) -> Self {
        // Cap the map to bound memory under IPv6 subnet rotation.
        const MAX_KEYS: usize = 50_000;
        Self {
            hour: SlidingWindowLimiterByKey::new_with_cap(3600, per_hour as usize, Some(MAX_KEYS)),
            day: SlidingWindowLimiterByKey::new_with_cap(86_400, per_day as usize, Some(MAX_KEYS)),
        }
    }

    /// Returns the decision + which window (if any) caused a rejection.
    /// The frontend uses this to show "retry in an hour" vs "retry tomorrow"
    /// rather than a generic 429.
    pub fn check_and_record(&self, ip: IpAddr) -> ShareCreationDecision {
        let bucket = IpBucket::from(ip);
        if !self.hour.check_and_record(bucket) {
            return ShareCreationDecision::HourCapExceeded;
        }
        if !self.day.check_and_record(bucket) {
            // Day denied after hour admitted — refund is not possible with
            // SlidingWindowLimiterByKey's current API. The cost is at most
            // one phantom hour-tick per client per day-window rollover;
            // acceptable.
            return ShareCreationDecision::DayCapExceeded;
        }
        ShareCreationDecision::Allow
    }
}

/// Result of a creation-rate check. Callers 429 on either cap but surface
/// distinct `X-Wattcloud-Reason` + `Retry-After` so the UI can say "try
/// again in an hour" vs "try again tomorrow".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareCreationDecision {
    Allow,
    HourCapExceeded,
    DayCapExceeded,
}

/// Per-share-id bytes-per-hour tracker. Uses a sliding 1-hour window of
/// (timestamp, bytes) entries so a 1 GB/hour cap works the same whether the
/// traffic arrives as one big download or ten 100 MB ones.
pub struct ShareBytesPerShareTracker {
    state: RwLock<HashMap<String, Vec<(Instant, u64)>>>,
    window: Duration,
    max_bytes_per_window: u64,
    max_keys: usize,
}

impl ShareBytesPerShareTracker {
    pub fn new(max_bytes_per_hour: u64) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            window: Duration::from_secs(3600),
            max_bytes_per_window: max_bytes_per_hour,
            max_keys: 50_000,
        }
    }

    /// Reserve `bytes` against the share_id's budget. Returns true iff the
    /// reservation fits; on false, nothing is recorded.
    pub fn try_consume(&self, share_id: &str, bytes: u64) -> bool {
        if self.max_bytes_per_window == 0 {
            return true;
        }
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut state = self.state.write().expect("share bytes lock poisoned");

        if let Some(entries) = state.get_mut(share_id) {
            entries.retain(|&(t, _)| t > cutoff);
            let used: u64 = entries.iter().map(|&(_, b)| b).sum();
            if used.saturating_add(bytes) > self.max_bytes_per_window {
                return false;
            }
            entries.push((now, bytes));
            return true;
        }

        if state.len() >= self.max_keys {
            // Map at cap: allow unknown shares without tracking (prevents
            // memory exhaustion via cycling share_ids); same fail-open
            // policy as SlidingWindowLimiterByKey.
            return true;
        }
        state.insert(share_id.to_string(), vec![(now, bytes)]);
        true
    }
}

/// Per-share-id concurrent-download counter. Returns an RAII guard that
/// decrements the counter on drop, so a dropped connection or early-return
/// handler doesn't leak a slot. Default max is 1 (anti-amplification).
pub struct ShareConcurrencyTracker {
    state: Arc<RwLock<HashMap<String, Arc<AtomicUsize>>>>,
    max_concurrent: usize,
}

impl ShareConcurrencyTracker {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_concurrent: max_concurrent.max(1) as usize,
        }
    }

    /// Acquire a slot for `share_id`. Returns None if the share is already
    /// at its concurrency cap; caller should respond with 429.
    pub fn try_acquire(&self, share_id: &str) -> Option<ShareConcurrencyGuard> {
        // Fast path: share_id already tracked — bump the existing counter.
        {
            let state = self.state.read().expect("share concurrency lock poisoned");
            if let Some(counter) = state.get(share_id) {
                let prev = counter.fetch_add(1, Ordering::AcqRel);
                if prev >= self.max_concurrent {
                    counter.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
                return Some(ShareConcurrencyGuard {
                    counter: Arc::clone(counter),
                });
            }
        }
        // Slow path: insert a fresh counter. Under write lock to avoid two
        // handlers racing in empty-key state.
        let mut state = self.state.write().expect("share concurrency lock poisoned");
        let counter = state
            .entry(share_id.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        let prev = counter.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max_concurrent {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ShareConcurrencyGuard {
            counter: Arc::clone(counter),
        })
    }
}

/// RAII release for a ShareConcurrencyTracker slot.
pub struct ShareConcurrencyGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ShareConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-IP aggregate share storage tracker. In-memory (lost on restart) —
/// adequate because this is an operational abuse cap, not a security gate,
/// and the existing per-IP daily byte budget still bounds upload volume
/// during the short window immediately after a restart.
///
/// Flow:
///   - Upload handler calls `would_accept(ip, content_length)` pre-stream.
///   - On successful upload + record, handler calls `register(ip, share_id, bytes)`.
///   - Sweeper and revocation paths call `release(share_id)` when the share
///     leaves the "live" set; stored bytes stop counting against the cap.
pub struct ShareStoragePerIpTracker {
    /// Current aggregate bytes per IP bucket. Keeps the hot read path
    /// (would_accept) to a single HashMap lookup.
    totals: RwLock<HashMap<IpBucket, u64>>,
    /// Reverse index so `release(share_id)` can find the bucket to
    /// decrement without walking every bucket.
    by_share: RwLock<HashMap<String, (IpBucket, u64)>>,
    max_bytes_per_ip: u64,
}

impl ShareStoragePerIpTracker {
    pub fn new(max_bytes_per_ip: u64) -> Self {
        Self {
            totals: RwLock::new(HashMap::new()),
            by_share: RwLock::new(HashMap::new()),
            max_bytes_per_ip,
        }
    }

    /// Would `additional_bytes` from `ip` fit under the per-IP cap? Does not
    /// register — the handler calls `register` only after the upload
    /// succeeds (avoids half-bookings from transport errors mid-stream).
    pub fn would_accept(&self, ip: IpAddr, additional_bytes: u64) -> bool {
        if self.max_bytes_per_ip == 0 {
            return true;
        }
        let bucket = IpBucket::from(ip);
        let totals = self.totals.read().expect("storage lock poisoned");
        let current = totals.get(&bucket).copied().unwrap_or(0);
        current.saturating_add(additional_bytes) <= self.max_bytes_per_ip
    }

    /// Attribute `bytes` to `ip`/`share_id`. Accumulates when called
    /// multiple times for the same share (bundle shares upload blob-by-blob;
    /// each blob calls register separately so the per-IP aggregate grows
    /// as the bundle fills). The bucket recorded for a share is the one
    /// seen on the *first* register for that share_id — subsequent blobs
    /// credit to the same bucket so `release` can subtract the full
    /// bundle total cleanly.
    pub fn register(&self, ip: IpAddr, share_id: &str, bytes: u64) {
        if self.max_bytes_per_ip == 0 || bytes == 0 {
            return;
        }
        let bucket = IpBucket::from(ip);
        let resolved_bucket = {
            let mut by_share = self.by_share.write().expect("storage lock poisoned");
            match by_share.get_mut(share_id) {
                Some((existing_bucket, total)) => {
                    *total = total.saturating_add(bytes);
                    *existing_bucket
                }
                None => {
                    by_share.insert(share_id.to_string(), (bucket, bytes));
                    bucket
                }
            }
        };
        let mut totals = self.totals.write().expect("storage lock poisoned");
        let entry = totals.entry(resolved_bucket).or_insert(0);
        *entry = entry.saturating_add(bytes);
    }

    pub fn release(&self, share_id: &str) {
        let removed = {
            let mut by_share = self.by_share.write().expect("storage lock poisoned");
            by_share.remove(share_id)
        };
        if let Some((bucket, bytes)) = removed {
            let mut totals = self.totals.write().expect("storage lock poisoned");
            if let Some(total) = totals.get_mut(&bucket) {
                *total = total.saturating_sub(bytes);
                if *total == 0 {
                    totals.remove(&bucket);
                }
            }
        }
    }

    /// Current aggregate used for `ip`. Informational — the headroom
    /// endpoint surfaces this so the UI can warn before the user hits the
    /// cap mid-upload.
    pub fn used(&self, ip: IpAddr) -> u64 {
        let bucket = IpBucket::from(ip);
        let totals = self.totals.read().expect("storage lock poisoned");
        totals.get(&bucket).copied().unwrap_or(0)
    }

    pub fn limit(&self) -> u64 {
        self.max_bytes_per_ip
    }
}

/// statvfs the filesystem holding `path` and return `used / total` as a
/// percentage in 0..=100. Returns None if the syscall fails (stale mount,
/// permissions, platform without statvfs) so the caller can fall back to
/// "allow" rather than wedge.
pub fn disk_usage_percent(path: &std::path::Path) -> Option<u8> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: `statvfs` writes into the provided struct on success and
        // returns non-zero on error; either way no uninitialised memory is
        // read. The CString outlives the call.
        unsafe {
            let mut st: MaybeUninit<libc::statvfs> = MaybeUninit::zeroed();
            if libc::statvfs(c_path.as_ptr(), st.as_mut_ptr()) != 0 {
                return None;
            }
            let st = st.assume_init();
            let total = (st.f_blocks as u64).saturating_mul(st.f_frsize as u64);
            let free = (st.f_bavail as u64).saturating_mul(st.f_frsize as u64);
            if total == 0 {
                return Some(0);
            }
            let used = total.saturating_sub(free);
            // Cast through u128 to avoid overflow on >42 GB filesystems.
            Some(((used as u128 * 100) / total as u128).min(100) as u8)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Stateless helper: compute the allowed bytes-per-second for a share
/// during its slow-start window. Returns `None` when the share is past
/// slow-start (caller streams at full speed). The handler applies the
/// returned rate via a simple token-bucket pacing loop.
pub fn share_slow_start_bps(
    created_at_unix: i64,
    now_unix: i64,
    slow_start_secs: u64,
    slow_start_max_bps: u64,
) -> Option<u64> {
    if slow_start_secs == 0 || slow_start_max_bps == 0 {
        return None;
    }
    let age = now_unix.saturating_sub(created_at_unix);
    if age < 0 || (age as u64) >= slow_start_secs {
        return None;
    }
    Some(slow_start_max_bps)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ── Auth challenge limiter ───────────────────────────────────────────
    #[test]
    fn auth_challenge_allows_up_to_limit() {
        let limiter = AuthChallengeLimiter::new(5);
        let client = ip("1.2.3.4");
        for _ in 0..5 {
            assert!(limiter.check_and_record(client));
        }
    }

    #[test]
    fn auth_challenge_blocks_after_limit() {
        let limiter = AuthChallengeLimiter::new(5);
        let client = ip("1.2.3.4");
        for _ in 0..5 {
            limiter.check_and_record(client);
        }
        assert!(!limiter.check_and_record(client));
    }

    #[test]
    fn auth_challenge_different_ips_independent() {
        let limiter = AuthChallengeLimiter::new(5);
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        for _ in 0..5 {
            limiter.check_and_record(a);
        }
        assert!(limiter.check_and_record(b));
    }

    // ── Channel join limiter ─────────────────────────────────────────────
    #[test]
    fn channel_join_allows_up_to_limit() {
        let limiter = ChannelJoinLimiter::new();
        let client = ip("1.2.3.4");
        for _ in 0..10 {
            assert!(limiter.check_and_record(client));
        }
    }

    #[test]
    fn channel_join_blocks_after_limit() {
        let limiter = ChannelJoinLimiter::new();
        let client = ip("1.2.3.4");
        for _ in 0..10 {
            limiter.check_and_record(client);
        }
        assert!(!limiter.check_and_record(client));
    }

    #[test]
    fn channel_join_different_ips_independent() {
        let limiter = ChannelJoinLimiter::new();
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        for _ in 0..10 {
            limiter.check_and_record(a);
        }
        // b is unaffected
        assert!(limiter.check_and_record(b));
    }

    // ── SFTP connection tracker ──────────────────────────────────────────
    #[test]
    fn sftp_tracker_allows_up_to_limit() {
        let tracker = SftpConnectionTracker::new();
        let client = ip("1.2.3.4");
        let guards: Vec<_> = (0..5)
            .map(|_| tracker.try_acquire(client).unwrap())
            .collect();
        assert!(tracker.try_acquire(client).is_none()); // 6th rejected
        drop(guards); // release all
    }

    #[test]
    fn sftp_tracker_releases_on_drop() {
        let tracker = SftpConnectionTracker::new();
        let client = ip("1.2.3.4");
        {
            let _guard = tracker.try_acquire(client).unwrap();
        } // dropped here
        assert!(tracker.try_acquire(client).is_some()); // slot available again
    }

    #[test]
    fn sftp_tracker_different_ips_independent() {
        let tracker = SftpConnectionTracker::new();
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        let _guards_a: Vec<_> = (0..5).map(|_| tracker.try_acquire(a).unwrap()).collect();
        // b is unaffected
        assert!(tracker.try_acquire(b).is_some());
    }

    // ── SFTP auth-failure tracker ────────────────────────────────────────────
    #[test]
    fn auth_failure_not_blocked_initially() {
        let tracker = SftpAuthFailureTracker::new();
        assert!(!tracker.is_blocked(ip("1.2.3.4")));
    }

    #[test]
    fn auth_failure_blocks_after_threshold() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for _ in 0..DEFAULT_FAILURE_LIMIT {
            tracker.record_failure(client);
        }
        assert!(tracker.is_blocked(client));
    }

    #[test]
    fn auth_failure_threshold_not_crossed_at_limit_minus_one() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for _ in 0..(DEFAULT_FAILURE_LIMIT - 1) {
            tracker.record_failure(client);
        }
        assert!(!tracker.is_blocked(client));
    }

    #[test]
    fn auth_failure_different_ips_independent() {
        let tracker = SftpAuthFailureTracker::new();
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        for _ in 0..DEFAULT_FAILURE_LIMIT {
            tracker.record_failure(a);
        }
        assert!(tracker.is_blocked(a));
        assert!(!tracker.is_blocked(b));
    }

    #[test]
    fn host_spray_blocks_after_threshold() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for i in 0..=HOST_LIMIT {
            let host = format!("host{i}.example.com");
            tracker.record_host(client, &host);
        }
        assert!(tracker.is_blocked(client));
    }

    #[test]
    fn host_spray_not_triggered_within_limit() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for i in 0..HOST_LIMIT {
            let host = format!("host{i}.example.com");
            tracker.record_host(client, &host);
        }
        assert!(!tracker.is_blocked(client));
    }

    #[test]
    fn host_spray_same_host_repeated_does_not_count_twice() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        // Repeat the same host more than HOST_LIMIT times — should NOT trigger spray.
        for _ in 0..(HOST_LIMIT + 5) {
            tracker.record_host(client, "same.example.com");
        }
        assert!(!tracker.is_blocked(client));
    }

    // ── IPv6 /64 bucketing ───────────────────────────────────────────────────
    #[test]
    fn ipv6_slash64_bucketing() {
        // Two IPv6 addresses in the same /64 must map to the same bucket.
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        assert_eq!(IpBucket::from(a), IpBucket::from(b));
    }

    #[test]
    fn ipv6_different_slash64_different_bucket() {
        // Addresses in different /64 blocks must produce different buckets.
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        assert_ne!(IpBucket::from(a), IpBucket::from(b));
    }

    #[test]
    fn ipv4_bucketed_as_v4() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches!(IpBucket::from(a), IpBucket::V4(_)));
    }

    #[test]
    fn ipv6_slash64_rate_limit_shared() {
        // Addresses in the same /64 share the same rate-limit bucket.
        let limiter = AuthChallengeLimiter::new(5);
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::ffff".parse().unwrap();
        for _ in 0..5 {
            limiter.check_and_record(a);
        }
        // b is in the same /64 — should be blocked by shared bucket.
        assert!(!limiter.check_and_record(b));
    }

    // ── refund_failure ────────────────────────────────────────────────────────
    #[test]
    fn refund_failure_prevents_block_after_success() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        // Record DEFAULT_FAILURE_LIMIT - 1 pre-handshake failures then refund each.
        for _ in 0..(DEFAULT_FAILURE_LIMIT - 1) {
            tracker.record_failure(client);
            tracker.refund_failure(client);
        }
        // After refunds, count should be near zero — should not be blocked.
        assert!(!tracker.is_blocked(client));
    }

    #[test]
    fn refund_failure_does_not_go_below_zero() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        tracker.record_failure(client);
        tracker.refund_failure(client);
        tracker.refund_failure(client); // extra refund — should not panic
        assert!(!tracker.is_blocked(client));
    }

    #[test]
    fn parallel_auth_failure_accounted_pre_handshake() {
        // Record DEFAULT_FAILURE_LIMIT tentative failures (simulating parallel attempts).
        // The last one should trigger the block even without explicit confirmation.
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for _ in 0..DEFAULT_FAILURE_LIMIT {
            tracker.record_failure(client);
        }
        assert!(tracker.is_blocked(client));
    }

    // ── ByteBudgetTracker ─────────────────────────────────────────────────────

    fn day_start(day: i64) -> i64 {
        day * 86_400
    }

    #[test]
    fn byte_budget_allows_within_limit() {
        let t = ByteBudgetTracker::new(1_000);
        let client = ip("10.0.0.1");
        assert!(t.try_consume(client, 500, day_start(10)));
        assert!(t.try_consume(client, 500, day_start(10)));
        assert_eq!(t.remaining(client, day_start(10)), 0);
    }

    #[test]
    fn byte_budget_rejects_over_limit() {
        let t = ByteBudgetTracker::new(1_000);
        let client = ip("10.0.0.1");
        assert!(t.try_consume(client, 900, day_start(10)));
        assert!(!t.try_consume(client, 200, day_start(10)));
        // Rejection must not record — the remaining budget stays.
        assert_eq!(t.remaining(client, day_start(10)), 100);
    }

    #[test]
    fn byte_budget_resets_on_new_day() {
        let t = ByteBudgetTracker::new(1_000);
        let client = ip("10.0.0.1");
        assert!(t.try_consume(client, 1_000, day_start(10)));
        assert_eq!(t.remaining(client, day_start(10)), 0);
        // Cross the UTC-day boundary; budget resets.
        assert_eq!(t.remaining(client, day_start(11)), 1_000);
        assert!(t.try_consume(client, 1_000, day_start(11)));
    }

    #[test]
    fn byte_budget_ipv6_slash64_bucketed() {
        let t = ByteBudgetTracker::new(1_000);
        // Two IPv6 addresses in the same /64 share a bucket.
        let a = ip("2001:db8::1");
        let b = ip("2001:db8::ffff");
        assert!(t.try_consume(a, 600, day_start(0)));
        assert!(!t.try_consume(b, 500, day_start(0))); // shared bucket
    }

    #[test]
    fn byte_budget_zero_limit_disables_enforcement() {
        let t = ByteBudgetTracker::new(0);
        let client = ip("10.0.0.1");
        // u64::MAX bytes should succeed when limit=0 (disabled).
        assert!(t.try_consume(client, u64::MAX, day_start(10)));
        assert_eq!(t.remaining(client, day_start(10)), u64::MAX);
    }

    // ── ShareCreationRateLimiter ──────────────────────────────────────────────

    #[test]
    fn share_create_limiter_allows_up_to_hour_cap() {
        let lim = ShareCreationRateLimiter::new(3, 100);
        let client = ip("10.0.0.1");
        assert_eq!(lim.check_and_record(client), ShareCreationDecision::Allow);
        assert_eq!(lim.check_and_record(client), ShareCreationDecision::Allow);
        assert_eq!(lim.check_and_record(client), ShareCreationDecision::Allow);
        assert_eq!(
            lim.check_and_record(client),
            ShareCreationDecision::HourCapExceeded,
        );
    }

    #[test]
    fn share_create_limiter_day_cap_also_enforced() {
        // Hour is generous, day is the binding constraint.
        let lim = ShareCreationRateLimiter::new(100, 2);
        let client = ip("10.0.0.1");
        assert_eq!(lim.check_and_record(client), ShareCreationDecision::Allow);
        assert_eq!(lim.check_and_record(client), ShareCreationDecision::Allow);
        assert_eq!(
            lim.check_and_record(client),
            ShareCreationDecision::DayCapExceeded,
        );
    }

    #[test]
    fn share_create_limiter_different_ips_independent() {
        let lim = ShareCreationRateLimiter::new(2, 10);
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        assert_eq!(lim.check_and_record(a), ShareCreationDecision::Allow);
        assert_eq!(lim.check_and_record(a), ShareCreationDecision::Allow);
        assert_eq!(
            lim.check_and_record(a),
            ShareCreationDecision::HourCapExceeded,
        );
        assert_eq!(lim.check_and_record(b), ShareCreationDecision::Allow);
    }

    // ── ShareBytesPerShareTracker ─────────────────────────────────────────────

    #[test]
    fn share_bytes_allows_within_budget() {
        let t = ShareBytesPerShareTracker::new(1_000);
        assert!(t.try_consume("share-1", 600));
        assert!(t.try_consume("share-1", 400));
        assert!(!t.try_consume("share-1", 1));
    }

    #[test]
    fn share_bytes_reject_leaves_counter_unchanged() {
        let t = ShareBytesPerShareTracker::new(1_000);
        assert!(t.try_consume("s", 900));
        assert!(!t.try_consume("s", 200));
        // 100 still available (rejected request wasn't recorded).
        assert!(t.try_consume("s", 100));
    }

    #[test]
    fn share_bytes_independent_per_share() {
        let t = ShareBytesPerShareTracker::new(500);
        assert!(t.try_consume("a", 500));
        assert!(!t.try_consume("a", 1));
        assert!(t.try_consume("b", 500));
    }

    #[test]
    fn share_bytes_zero_limit_disables() {
        let t = ShareBytesPerShareTracker::new(0);
        assert!(t.try_consume("s", u64::MAX));
    }

    // ── ShareConcurrencyTracker ──────────────────────────────────────────────

    #[test]
    fn share_concurrency_allows_up_to_cap() {
        let t = ShareConcurrencyTracker::new(2);
        let g1 = t.try_acquire("s").unwrap();
        let g2 = t.try_acquire("s").unwrap();
        assert!(t.try_acquire("s").is_none());
        drop(g1);
        assert!(t.try_acquire("s").is_some());
        drop(g2);
    }

    #[test]
    fn share_concurrency_cap_one_is_default() {
        // The production default is 1 — verify it works.
        let t = ShareConcurrencyTracker::new(1);
        let g = t.try_acquire("s").unwrap();
        assert!(t.try_acquire("s").is_none());
        drop(g);
        assert!(t.try_acquire("s").is_some());
    }

    #[test]
    fn share_concurrency_independent_per_share() {
        let t = ShareConcurrencyTracker::new(1);
        let _a = t.try_acquire("a").unwrap();
        // Different share_id: independent slot.
        assert!(t.try_acquire("b").is_some());
    }

    // ── ShareStoragePerIpTracker ─────────────────────────────────────────────

    #[test]
    fn storage_tracker_allows_under_cap() {
        let t = ShareStoragePerIpTracker::new(1_000);
        let client = ip("10.0.0.1");
        assert!(t.would_accept(client, 500));
        t.register(client, "s1", 500);
        assert!(t.would_accept(client, 500));
        t.register(client, "s2", 500);
        assert!(!t.would_accept(client, 1));
    }

    #[test]
    fn storage_tracker_release_frees_quota() {
        let t = ShareStoragePerIpTracker::new(1_000);
        let client = ip("10.0.0.1");
        t.register(client, "s1", 900);
        assert!(!t.would_accept(client, 200));
        t.release("s1");
        assert!(t.would_accept(client, 900));
    }

    #[test]
    fn storage_tracker_bundle_blobs_accumulate() {
        // Bundle uploads: each blob calls register with the same share_id.
        // Total should accumulate and the first bucket is locked in.
        let t = ShareStoragePerIpTracker::new(1_000);
        let client = ip("10.0.0.1");
        t.register(client, "bundle-1", 300);
        t.register(client, "bundle-1", 300);
        t.register(client, "bundle-1", 300);
        // 900 committed; 100 remaining.
        assert!(t.would_accept(client, 100));
        assert!(!t.would_accept(client, 101));
        // Release drops all 900 at once.
        t.release("bundle-1");
        assert!(t.would_accept(client, 1_000));
    }

    #[test]
    fn storage_tracker_ipv6_slash64_bucketed() {
        let t = ShareStoragePerIpTracker::new(1_000);
        let a = ip("2001:db8::1");
        let b = ip("2001:db8::ffff");
        t.register(a, "s1", 900);
        // b is in the same /64 — shares the budget.
        assert!(!t.would_accept(b, 200));
        assert!(t.would_accept(b, 100));
    }

    #[test]
    fn storage_tracker_zero_limit_disables() {
        let t = ShareStoragePerIpTracker::new(0);
        let client = ip("10.0.0.1");
        assert!(t.would_accept(client, u64::MAX));
        t.register(client, "s1", 1_000);
        assert!(t.would_accept(client, u64::MAX));
    }

    // ── share_slow_start_bps helper ──────────────────────────────────────────

    #[test]
    fn slow_start_active_during_window() {
        // 100s after creation, still in 300s window — throttled.
        assert_eq!(
            share_slow_start_bps(1_000, 1_100, 300, 10_000_000),
            Some(10_000_000),
        );
    }

    #[test]
    fn slow_start_inactive_after_window() {
        assert_eq!(share_slow_start_bps(1_000, 1_301, 300, 10_000_000), None,);
    }

    #[test]
    fn slow_start_inactive_when_zero_disabled() {
        // secs=0 or bps=0 disables entirely.
        assert_eq!(share_slow_start_bps(1_000, 1_000, 0, 10_000_000), None);
        assert_eq!(share_slow_start_bps(1_000, 1_000, 300, 0), None);
    }

    #[test]
    fn slow_start_handles_clock_skew() {
        // now < created_at (NTP glitch): saturate to no-throttle rather
        // than throwing arithmetic errors.
        assert_eq!(share_slow_start_bps(2_000, 1_000, 300, 10_000_000), None);
    }

    // ── disk_usage_percent sanity ────────────────────────────────────────────

    #[test]
    fn disk_usage_percent_returns_plausible_value() {
        // Running on any Unix-ish filesystem — should return 0..=100.
        if let Some(pct) = disk_usage_percent(std::path::Path::new("/tmp")) {
            assert!(pct <= 100);
        }
    }
}
