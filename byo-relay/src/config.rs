use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::enrollment::EnrollmentMode;

/// Configuration loaded from environment variables at startup.
/// All required vars cause a panic if missing (matches backend pattern).
pub struct Config {
    /// HMAC-SHA256 key for signing relay_auth cookies (min 32 bytes, base64 or raw).
    /// Used ONLY for JWT signing — never for other HMAC primitives. Domain
    /// separation from share owner tokens prevents a JWT-side key compromise
    /// (e.g., via a parser flaw) from granting the ability to forge arbitrary
    /// share revocations. See `share_signing_key` for the owner-token key.
    pub relay_signing_key: Vec<u8>,
    /// HMAC-SHA256 key for share owner tokens (B1/B2). Separate from
    /// `relay_signing_key` so the two primitives (JWT cookie vs raw-bytes HMAC)
    /// do not share key material (SC1).
    ///
    /// Loaded from `RELAY_SHARE_SIGNING_KEY`. If unset, falls back to
    /// `relay_signing_key` with a loud warning — this preserves compatibility
    /// for existing deployments during the rollout but is not the secure
    /// default; production must set the variable explicitly.
    pub share_signing_key: Vec<u8>,
    /// Bind address, default 0.0.0.0:8443
    pub bind_addr: SocketAddr,
    /// Path to TLS certificate (PEM), optional
    pub tls_cert: Option<PathBuf>,
    /// Path to TLS private key (PEM), optional
    pub tls_key: Option<PathBuf>,
    /// Path to the SPA dist/ directory, default ./dist
    pub spa_dir: PathBuf,
    /// BYO server domain (e.g. byo.example.com) — used in CSP wss:// directive
    pub domain: String,
    /// SFTP host allowlist. Empty = all hosts permitted (default-allow; SSRF protection still enforced).
    /// Set to restrict SFTP connections to known hosts. Supports exact hostnames and `*.example.com` wildcards.
    pub sftp_host_allowlist: Vec<String>,
    /// SFTP destination-port allowlist. Only these ports may be relayed.
    /// Default: [22, 2022, 2222]. Set SFTP_ALLOWED_PORTS to a comma-separated list to override.
    pub sftp_allowed_ports: Vec<u16>,
    /// Relay cookie TTL in seconds (default 600 = 10 minutes).
    pub relay_cookie_ttl_secs: u64,
    /// IP addresses of trusted upstream proxies (Traefik, load balancer).
    /// When the TCP peer is listed here, `X-Forwarded-For` is consulted to
    /// resolve the real client IP for rate limiting, PoW binding, and auth
    /// tracking. Untrusted peers cannot spoof their source IP via headers.
    /// Configured via `TRUSTED_PROXY_IPS` (comma-separated). Empty = direct
    /// bind (use TCP peer as client IP).
    pub trusted_proxies: Vec<IpAddr>,
    /// PoW difficulty: number of required leading zero bits in sha256 preimage (default 18 ≈ 0.5–1 s on mobile).
    pub pow_difficulty_bits: u32,
    /// Challenge rate limit: max challenges per IP per minute (default 10).
    pub auth_challenge_per_min: u32,

    // ── Share storage ──────────────────────────────────────────────────────
    /// Directory holding per-share ciphertext blobs. Default
    /// `/var/lib/byo-relay/shares`. The relay creates this lazily at startup.
    pub share_storage_dir: PathBuf,
    /// SQLite path for the share metadata index. Default
    /// `/var/lib/byo-relay/shares.sqlite3`.
    pub share_db_path: PathBuf,
    /// Per-IP daily ingress byte budget for share uploads (bytes). 0 disables
    /// enforcement. Only abuse backstop since no per-request size cap exists
    /// at the HTTP layer; keyed on IPv6 /64 / IPv4. Default 50 GB.
    pub share_daily_bytes_per_ip: u64,

    // ── Share abuse protections (env-overridable) ───────────────────────────
    //
    // All per-IP — the relay's cookie auth is purposefully device-agnostic,
    // so the only reliable identifier is the client IP (bucketed to /64 for
    // IPv6). SECURITY.md §Abuse Protections documents the threat model,
    // every env var, and the rationale for each default.
    /// Max size of a single share blob (bytes). Enforced at upload start via
    /// Content-Length so a runaway client cannot start a 100 GB body and
    /// drain the disk mid-stream. Default 1 GB.
    pub share_max_blob_bytes: u64,
    /// Per-IP share creations per hour. Default 10.
    pub share_create_per_hour_per_ip: u32,
    /// Per-IP share creations per day. Default 50.
    pub share_create_per_day_per_ip: u32,
    /// Per-IP aggregate bytes of *active* (non-revoked, non-expired) shares.
    /// Blocks the "use relay as free durable hosting" mode. Enforced at
    /// create time; existing shares carry on. Default 5 GB.
    pub share_total_storage_per_ip_bytes: u64,
    /// Per-share download GETs per hour (recipient side). Default 10.
    pub share_download_per_hour_per_share: u32,
    /// Per-share download bytes per hour. Complements the fetch limit so a
    /// single-large-file share isn't also an amplification vector. Default 1 GB.
    pub share_download_bytes_per_hour_per_share: u64,
    /// Max concurrent downloads per share_id. Anti-amplification brake.
    /// Default 1 — extra recipients get 429 and retry with backoff.
    pub share_max_concurrent_downloads: u32,
    /// Slow-start window after share creation during which downloads are
    /// rate-capped server-side. Buys operator reaction time for a viral
    /// leak. Default 300 s.
    pub share_slow_start_secs: u64,
    /// Slow-start bandwidth cap in bytes/second. Default 10 MB/s.
    pub share_slow_start_max_bps: u64,
    /// Disk-usage watermark as a percentage [0–100]. New share creations
    /// are rejected with 507 when the share_storage_dir filesystem is at
    /// or above this fraction full. Default 80%.
    pub disk_watermark_percent: u8,

    // ── SFTP abuse protections ──────────────────────────────────────────────
    /// Per-IP (/64-bucketed) concurrent SFTP connection cap. Default 8.
    pub sftp_max_concurrent_per_ip: u32,
    /// SFTP failed-auth attempts per 5 minutes before a 1-hour block.
    /// Default 5.
    pub sftp_failed_auth_per_5min: u32,

    // ── Small-body request size caps ────────────────────────────────────────
    // Tight ceilings on JSON-only endpoints that inherit axum's loose 2 MB
    // default otherwise. Realistic payloads are tiny; these caps just
    // prevent a misbehaving client from tying up a parse task with a 2 MB
    // JSON body that's destined to fail deserialise anyway.
    /// Max body bytes for `/relay/auth` (enrollment solution + JWK).
    /// Default 16 KB — ~8× a fat JWK.
    pub auth_max_body_bytes: usize,
    /// Max body bytes for `/relay/share/bundle/init` (JSON: kind +
    /// expires_in_secs). Default 4 KB — ~40× the realistic payload.
    pub bundle_init_max_body_bytes: usize,

    // ── Stats ──────────────────────────────────────────────────────────────
    /// HMAC-SHA256 key for hashing device UUIDs before storage (≥32 bytes).
    /// Required — fail-fast at startup if missing.
    pub stats_hmac_key: Vec<u8>,
    /// Path to the stats SQLite database.
    pub stats_db_path: String,
    /// Max ingest batches per device per minute.
    pub stats_ingest_per_min: u32,
    /// Max events per ingest batch (default 200).
    /// The WASM-side ring buffer is intentionally larger (800 = 4× this limit)
    /// so events accumulate across multiple flush windows without head-of-line blocking.
    pub stats_batch_max_events: usize,
    /// Max request body bytes for POST /relay/stats.
    pub stats_max_body_bytes: usize,

    // ── Restricted enrollment (phase 1 scaffold) ────────────────────────────
    /// Gate posture for operational relay surfaces.
    ///
    /// * `Open` (default when `WATTCLOUD_ENROLLMENT_MODE` is unset) — preserves
    ///   every existing install. Anyone can hit `/relay/auth/challenge`,
    ///   upload shares, etc.
    /// * `Restricted` — requires a `wattcloud_device` cookie minted by an
    ///   owner-issued invite. Fresh installs get `restricted` written into the
    ///   env file by `deploy-vps.sh`; existing installs opt in explicitly.
    ///
    /// Phase 1 only surfaces the flag on `/relay/info` — the middleware that
    /// actually enforces the gate lands in phase 2.
    pub enrollment_mode: EnrollmentMode,
    /// SQLite path for the enrollment store (authorized devices, invite
    /// codes, bootstrap token). Default `/var/lib/byo-relay/enrollment.sqlite3`.
    pub enrollment_db_path: PathBuf,
    /// `/relay/info` requests per IP per minute. Public endpoint, cheap, but
    /// rate-limited so it isn't a free firehose. Default 60.
    pub enrollment_info_per_min: u32,
}

impl Config {
    pub fn from_env() -> Self {
        let relay_signing_key = parse_signing_key();
        let share_signing_key = parse_share_signing_key(&relay_signing_key);
        let bind_addr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
            .parse::<SocketAddr>()
            .expect("BIND_ADDR must be a valid socket address (e.g. 0.0.0.0:8443)");

        let tls_cert = std::env::var("TLS_CERT").ok().map(PathBuf::from);
        let tls_key = std::env::var("TLS_KEY").ok().map(PathBuf::from);

        // Both must be set or neither
        match (&tls_cert, &tls_key) {
            (Some(_), None) | (None, Some(_)) => {
                panic!("TLS_CERT and TLS_KEY must both be set or both be absent");
            }
            _ => {}
        }

        let spa_dir =
            PathBuf::from(std::env::var("SPA_DIR").unwrap_or_else(|_| "./dist".to_string()));

        let domain = std::env::var("BYO_DOMAIN").unwrap_or_else(|_| "localhost".to_string());

        let sftp_host_allowlist = std::env::var("SFTP_HOST_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let sftp_allowed_ports: Vec<u16> = std::env::var("SFTP_ALLOWED_PORTS")
            .ok()
            .map(|v| {
                v.split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .filter(|&p| p > 0)
                    .collect()
            })
            .filter(|v: &Vec<u16>| !v.is_empty())
            .unwrap_or_else(|| vec![22, 2022, 2222]);

        let relay_cookie_ttl_secs = std::env::var("RELAY_COOKIE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600u64);

        let trusted_proxies: Vec<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();

        let pow_difficulty_bits = {
            let bits = std::env::var("POW_DIFFICULTY_BITS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(18u32);
            if bits < 12 {
                panic!("POW_DIFFICULTY_BITS must be at least 12 (got {bits}); lower values make the relay trivially farmable");
            }
            bits
        };

        let auth_challenge_per_min = std::env::var("AUTH_CHALLENGE_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10u32);

        let share_storage_dir = PathBuf::from(
            std::env::var("SHARE_STORAGE_DIR")
                .unwrap_or_else(|_| "/var/lib/byo-relay/shares".to_string()),
        );
        let share_db_path = PathBuf::from(
            std::env::var("SHARE_DB_PATH")
                .unwrap_or_else(|_| "/var/lib/byo-relay/shares.sqlite3".to_string()),
        );
        let share_daily_bytes_per_ip = std::env::var("SHARE_DAILY_BYTES_PER_IP")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50 * 1024 * 1024 * 1024); // 50 GB

        // ── Share abuse protections ─────────────────────────────────────────
        let share_max_blob_bytes = env_u64("SHARE_MAX_BLOB_BYTES", 1_073_741_824); // 1 GB
        let share_create_per_hour_per_ip = env_u32("SHARE_CREATE_PER_HOUR_PER_IP", 10);
        let share_create_per_day_per_ip = env_u32("SHARE_CREATE_PER_DAY_PER_IP", 50);
        let share_total_storage_per_ip_bytes =
            env_u64("SHARE_TOTAL_STORAGE_PER_IP_BYTES", 5 * 1024 * 1024 * 1024); // 5 GB
        let share_download_per_hour_per_share = env_u32("SHARE_DOWNLOAD_PER_HOUR_PER_SHARE", 10);
        let share_download_bytes_per_hour_per_share =
            env_u64("SHARE_DOWNLOAD_BYTES_PER_HOUR_PER_SHARE", 1_073_741_824); // 1 GB
        let share_max_concurrent_downloads = env_u32("SHARE_MAX_CONCURRENT_DOWNLOADS", 1);
        let share_slow_start_secs = env_u64("SHARE_SLOW_START_SECS", 300);
        let share_slow_start_max_bps = env_u64("SHARE_SLOW_START_MAX_BPS", 10 * 1024 * 1024); // 10 MB/s
        let disk_watermark_percent = {
            let v = env_u32("DISK_WATERMARK_PERCENT", 80);
            if v > 100 {
                panic!("DISK_WATERMARK_PERCENT must be 0..=100 (got {v})");
            }
            v as u8
        };
        // Default 8 — covers a multi-provider vault (3+ persistent SFTP
        // connections per open vault) plus a second tab or device-enrollment
        // attempt from the same client IP. The previous default of 3 hit
        // exactly when users tried to enroll a new device while their main
        // vault was unlocked: the 4th attempt got 429'd and surfaced as
        // "SFTP relay WebSocket connection failed" on the receiver side.
        // Operators who want a tighter cap can still set
        // SFTP_MAX_CONCURRENT_PER_IP explicitly.
        let sftp_max_concurrent_per_ip = env_u32("SFTP_MAX_CONCURRENT_PER_IP", 8);
        let sftp_failed_auth_per_5min = env_u32("SFTP_FAILED_AUTH_PER_5MIN", 5);
        let auth_max_body_bytes = env_u64("AUTH_MAX_BODY_BYTES", 16 * 1024) as usize;
        let bundle_init_max_body_bytes = env_u64("BUNDLE_INIT_MAX_BODY_BYTES", 4 * 1024) as usize;

        let stats_hmac_key = parse_stats_hmac_key();
        let stats_db_path = std::env::var("STATS_DB_PATH")
            .unwrap_or_else(|_| "/var/lib/byo-relay/stats.sqlite3".to_string());
        let stats_ingest_per_min = std::env::var("STATS_INGEST_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10u32);
        let stats_batch_max_events = std::env::var("STATS_BATCH_MAX_EVENTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200usize);
        let stats_max_body_bytes = std::env::var("STATS_MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(65536usize);

        let enrollment_mode = EnrollmentMode::from_env();
        let enrollment_db_path = PathBuf::from(
            std::env::var("ENROLLMENT_DB_PATH")
                .unwrap_or_else(|_| "/var/lib/byo-relay/enrollment.sqlite3".to_string()),
        );
        let enrollment_info_per_min = env_u32("ENROLLMENT_INFO_PER_MIN", 60);

        Self {
            relay_signing_key,
            share_signing_key,
            bind_addr,
            tls_cert,
            tls_key,
            spa_dir,
            domain,
            sftp_host_allowlist,
            sftp_allowed_ports,
            relay_cookie_ttl_secs,
            trusted_proxies,
            pow_difficulty_bits,
            auth_challenge_per_min,
            share_storage_dir,
            share_db_path,
            share_daily_bytes_per_ip,
            share_max_blob_bytes,
            share_create_per_hour_per_ip,
            share_create_per_day_per_ip,
            share_total_storage_per_ip_bytes,
            share_download_per_hour_per_share,
            share_download_bytes_per_hour_per_share,
            share_max_concurrent_downloads,
            share_slow_start_secs,
            share_slow_start_max_bps,
            disk_watermark_percent,
            sftp_max_concurrent_per_ip,
            sftp_failed_auth_per_5min,
            auth_max_body_bytes,
            bundle_init_max_body_bytes,
            stats_hmac_key,
            stats_db_path,
            stats_ingest_per_min,
            stats_batch_max_events,
            stats_max_body_bytes,
            enrollment_mode,
            enrollment_db_path,
            enrollment_info_per_min,
        }
    }
}

fn parse_signing_key() -> Vec<u8> {
    use base64::Engine as _;

    let raw = std::env::var("RELAY_SIGNING_KEY")
        .expect("RELAY_SIGNING_KEY environment variable is required");

    // Try base64 decoding first; fall back to raw bytes.
    let key = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
        .unwrap_or_else(|_| raw.into_bytes());

    if key.len() < 32 {
        panic!(
            "RELAY_SIGNING_KEY must be at least 32 bytes (got {})",
            key.len()
        );
    }

    // Reject trivially weak keys: all bytes identical.
    if key.iter().all(|&b| b == key[0]) {
        panic!("RELAY_SIGNING_KEY has no entropy (all bytes identical); use a securely generated random key");
    }

    key
}

/// Parse the share owner-token signing key from `RELAY_SHARE_SIGNING_KEY`.
///
/// D8: SPEC-BYO SC1 mandates `RELAY_SHARE_SIGNING_KEY` be distinct from
/// `RELAY_SIGNING_KEY` — sharing key material between primitives weakens both.
/// We allow a silent fallback only when `RELAY_STRICT=false` is explicitly
/// opted into (dev/tests); production deployments fail to start without the
/// dedicated key. Previously this was a `tracing::warn!` that was trivially
/// missed during rollout.
fn parse_share_signing_key(fallback: &[u8]) -> Vec<u8> {
    use base64::Engine as _;

    let Ok(raw) = std::env::var("RELAY_SHARE_SIGNING_KEY") else {
        let strict = std::env::var("RELAY_STRICT")
            .map(|s| {
                !matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "false" | "0" | "no" | "off"
                )
            })
            .unwrap_or(true);
        if strict {
            panic!(
                "RELAY_SHARE_SIGNING_KEY not set. SPEC-BYO SC1 requires a key \
                 distinct from RELAY_SIGNING_KEY for share owner-token HMACs. \
                 Export RELAY_SHARE_SIGNING_KEY=<32+-byte base64 random key>, \
                 or set RELAY_STRICT=false explicitly for dev/tests to fall \
                 back to the JWT key (NOT for production)."
            );
        }
        tracing::warn!(
            "RELAY_SHARE_SIGNING_KEY not set — RELAY_STRICT=false, falling back \
             to RELAY_SIGNING_KEY. DO NOT USE IN PRODUCTION (SC1 domain \
             separation)."
        );
        return fallback.to_vec();
    };

    let key = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
        .unwrap_or_else(|_| raw.into_bytes());

    if key.len() < 32 {
        panic!(
            "RELAY_SHARE_SIGNING_KEY must be at least 32 bytes (got {})",
            key.len()
        );
    }
    if key.iter().all(|&b| b == key[0]) {
        panic!("RELAY_SHARE_SIGNING_KEY has no entropy (all bytes identical)");
    }
    // Loud failure if the operator copy-pasted the same value for both. The
    // whole point of the split is domain separation; a shared value defeats it.
    if key == fallback {
        panic!(
            "RELAY_SHARE_SIGNING_KEY must differ from RELAY_SIGNING_KEY (SC1 \
             domain separation)"
        );
    }
    key
}

/// Parse an env var as u64 with a default. Invalid / zero-length values fall
/// back to the default rather than panicking — keeps operator typos from
/// grounding the relay, and the default is the conservative policy anyway.
fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn parse_stats_hmac_key() -> Vec<u8> {
    use base64::Engine as _;

    let raw =
        std::env::var("STATS_HMAC_KEY").expect("STATS_HMAC_KEY environment variable is required");

    let key = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
        .unwrap_or_else(|_| raw.into_bytes());

    if key.len() < 32 {
        panic!(
            "STATS_HMAC_KEY must be at least 32 bytes (got {})",
            key.len()
        );
    }
    if key.iter().all(|&b| b == key[0]) {
        panic!("STATS_HMAC_KEY has no entropy (all bytes identical)");
    }
    key
}

// Compile-time guard: the PoW default must exceed the runtime minimum. If a
// future change drops the default below 12, this fails to compile.
const _: () = {
    const POW_DEFAULT: u32 = 18;
    const POW_MINIMUM: u32 = 12;
    assert!(POW_DEFAULT >= POW_MINIMUM);
};
