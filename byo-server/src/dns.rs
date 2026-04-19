use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::errors::SsrfError;
use crate::ip_filter::is_ip_blocked;

/// Shared async DNS resolver.
///
/// D9: construct once per process and reuse. The previous per-request
/// `TokioAsyncResolver::tokio(...)` spawned its internal worker tasks on
/// every SFTP connection; more importantly it used `ResolverOpts::default()`
/// which honours the host's `resolv.conf` search list. A bare hostname like
/// `sftp` could then resolve to e.g. `sftp.internal.company.com`, giving an
/// SSRF bypass on hosts whose resolv.conf has a search domain set. Forcing
/// `ndots = 0` + empty `search` disables that expansion.
fn shared_resolver() -> &'static TokioAsyncResolver {
    static RESOLVER: OnceLock<TokioAsyncResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let mut opts = ResolverOpts::default();
        opts.ndots = 0;
        let mut cfg = ResolverConfig::default();
        // Remove any implicit search list; we never want search-domain
        // expansion for SSRF-critical lookups.
        cfg.set_domain(hickory_resolver::proto::rr::Name::root());
        cfg.add_search(hickory_resolver::proto::rr::Name::root());
        TokioAsyncResolver::tokio(cfg, opts)
    })
}

/// Validated, pinned IP addresses for a hostname.
/// All addresses are guaranteed to be non-private/non-reserved.
pub struct PinnedAddrs {
    pub addrs: Vec<IpAddr>,
}

/// Resolve a hostname and validate all returned IPs against SSRF rules (R2, R3).
///
/// - If hostname is already an IP literal, validates it directly.
/// - Otherwise resolves both A and AAAA records via system DNS.
/// - ALL resolved IPs must pass `is_ip_blocked` — if any is blocked, the entire
///   lookup is rejected. This prevents attacks where a hostname resolves to a mix
///   of public and private IPs.
/// - Returns pinned addresses; the caller must connect to one of these IPs directly
///   (not the hostname) to prevent TOCTOU DNS rebinding attacks (R3).
pub async fn resolve_and_validate(hostname: &str) -> Result<PinnedAddrs, SsrfError> {
    // IP literal — validate directly (no DNS needed)
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        if is_ip_blocked(&ip) {
            return Err(SsrfError::BlockedIp(ip));
        }
        return Ok(PinnedAddrs { addrs: vec![ip] });
    }

    // Reject empty or obviously invalid hostnames
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(SsrfError::InvalidHostname);
    }

    // Async DNS resolution: A + AAAA via the shared ndots=0 resolver.
    let lookup = shared_resolver()
        .lookup_ip(hostname)
        .await
        .map_err(|e| SsrfError::DnsError(e.to_string()))?;

    let addrs: Vec<IpAddr> = lookup.iter().collect();

    if addrs.is_empty() {
        return Err(SsrfError::NoRecords(hostname.to_string()));
    }

    // Validate ALL resolved IPs — reject if any is private/reserved (R2, R3)
    for addr in &addrs {
        if is_ip_blocked(addr) {
            return Err(SsrfError::BlockedIp(*addr));
        }
    }

    Ok(PinnedAddrs { addrs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literal_public_accepted() {
        let result = tokio_test::block_on(resolve_and_validate("8.8.8.8"));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().addrs,
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn ip_literal_loopback_blocked() {
        let result = tokio_test::block_on(resolve_and_validate("127.0.0.1"));
        assert!(matches!(result, Err(SsrfError::BlockedIp(_))));
    }

    #[test]
    fn ip_literal_private_blocked() {
        let result = tokio_test::block_on(resolve_and_validate("10.0.0.1"));
        assert!(matches!(result, Err(SsrfError::BlockedIp(_))));
    }

    #[test]
    fn ip_literal_ipv6_loopback_blocked() {
        let result = tokio_test::block_on(resolve_and_validate("::1"));
        assert!(matches!(result, Err(SsrfError::BlockedIp(_))));
    }

    #[test]
    fn ip_literal_link_local_blocked() {
        let result = tokio_test::block_on(resolve_and_validate("169.254.1.1"));
        assert!(matches!(result, Err(SsrfError::BlockedIp(_))));
    }

    #[test]
    fn empty_hostname_rejected() {
        let result = tokio_test::block_on(resolve_and_validate(""));
        assert!(matches!(result, Err(SsrfError::InvalidHostname)));
    }
}
