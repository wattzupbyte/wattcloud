use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
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
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_per_ip: 5,
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
}

/// Thresholds (tunable via constants).
const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60); // 10 minutes
const FAILURE_LIMIT: usize = 5;
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
        Self {
            failures: RwLock::new(HashMap::new()),
            hosts: RwLock::new(HashMap::new()),
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
        let mut failures = self.failures.write().expect("failure tracker lock poisoned");
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
        if now.duration_since(state.window_start) > FAILURE_WINDOW {
            state.count = 0;
            state.window_start = now;
            state.blocked_until = None;
        }

        state.count += 1;

        if state.count >= FAILURE_LIMIT {
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
        let mut failures = self.failures.write().expect("failure tracker lock poisoned");
        if let Some(state) = failures.get_mut(&bucket) {
            state.count = state.count.saturating_sub(1);
        }
    }

    fn apply_block(&self, bucket: IpBucket, now: Instant) {
        let mut failures = self.failures.write().expect("failure tracker lock poisoned");
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
        for _ in 0..FAILURE_LIMIT {
            tracker.record_failure(client);
        }
        assert!(tracker.is_blocked(client));
    }

    #[test]
    fn auth_failure_threshold_not_crossed_at_limit_minus_one() {
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for _ in 0..(FAILURE_LIMIT - 1) {
            tracker.record_failure(client);
        }
        assert!(!tracker.is_blocked(client));
    }

    #[test]
    fn auth_failure_different_ips_independent() {
        let tracker = SftpAuthFailureTracker::new();
        let a = ip("1.2.3.4");
        let b = ip("5.6.7.8");
        for _ in 0..FAILURE_LIMIT {
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
        // Record FAILURE_LIMIT - 1 pre-handshake failures then refund each.
        for _ in 0..(FAILURE_LIMIT - 1) {
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
        // Record FAILURE_LIMIT tentative failures (simulating parallel attempts).
        // The last one should trigger the block even without explicit confirmation.
        let tracker = SftpAuthFailureTracker::new();
        let client = ip("1.2.3.4");
        for _ in 0..FAILURE_LIMIT {
            tracker.record_failure(client);
        }
        assert!(tracker.is_blocked(client));
    }
}
