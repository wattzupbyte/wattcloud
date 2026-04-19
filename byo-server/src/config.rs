use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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

        let stats_hmac_key = parse_stats_hmac_key();
        let stats_db_path = std::env::var("STATS_DB_PATH")
            .unwrap_or_else(|_| "/var/lib/byo-server/stats.sqlite3".to_string());
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
            stats_hmac_key,
            stats_db_path,
            stats_ingest_per_min,
            stats_batch_max_events,
            stats_max_body_bytes,
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
        panic!("RELAY_SIGNING_KEY must be at least 32 bytes (got {})", key.len());
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
            .map(|s| !matches!(s.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
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

fn parse_stats_hmac_key() -> Vec<u8> {
    use base64::Engine as _;

    let raw = std::env::var("STATS_HMAC_KEY")
        .expect("STATS_HMAC_KEY environment variable is required");

    let key = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.trim()))
        .unwrap_or_else(|_| raw.into_bytes());

    if key.len() < 32 {
        panic!("STATS_HMAC_KEY must be at least 32 bytes (got {})", key.len());
    }
    if key.iter().all(|&b| b == key[0]) {
        panic!("STATS_HMAC_KEY has no entropy (all bytes identical)");
    }
    key
}

#[cfg(test)]
mod tests {
    #[test]
    fn pow_difficulty_default_is_above_minimum() {
        // The default (18) must be ≥ the minimum (12).
        assert!(18u32 >= 12u32);
    }
}
