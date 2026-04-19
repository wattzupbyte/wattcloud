//! Client IP extraction behind a trusted reverse proxy.
//!
//! When the relay runs behind Traefik (or any HTTP proxy), the TCP peer
//! address is the proxy's container IP, not the real client. Rate limits,
//! PoW IP-binding, and auth-failure tracking all key on the client IP, so
//! getting this wrong effectively disables per-client enforcement.
//!
//! This module resolves the true client IP by consulting `X-Forwarded-For`
//! **only** when the TCP peer is itself a trusted proxy. Unsanitized headers
//! from non-trusted peers are ignored.
//!
//! Trusted proxies are configured via `TRUSTED_PROXY_IPS` (comma-separated
//! exact IPs, typically `127.0.0.1` and the Docker bridge gateway). If the
//! list is empty the helper behaves as identity on the TCP peer — matching
//! the previous (direct-bind) behaviour.

use axum::http::HeaderMap;
use std::net::IpAddr;

/// Resolve the true client IP from the TCP peer and HTTP headers.
///
/// If `peer` is listed in `trusted_proxies`, walks `X-Forwarded-For` from the
/// right and returns the first address that is **not** a trusted proxy. Falls
/// back to `peer` if the header is missing, malformed, or contains only
/// trusted proxies.
///
/// If `peer` is **not** a trusted proxy, the header is ignored (an attacker
/// connecting directly cannot spoof their own source IP by sending a
/// forwarded-for header).
pub fn extract_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return peer,
    };
    for entry in xff.rsplit(',').map(str::trim) {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            if !trusted_proxies.contains(&ip) {
                return ip;
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let h = headers_with_xff("198.51.100.1, 127.0.0.1");
        assert_eq!(extract_client_ip(peer, &h, &trusted), peer);
    }

    #[test]
    fn trusted_peer_walks_xff_right_to_left() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let h = headers_with_xff("203.0.113.9, 198.51.100.2, 127.0.0.1");
        let expected: IpAddr = "198.51.100.2".parse().unwrap();
        assert_eq!(extract_client_ip(peer, &h, &trusted), expected);
    }

    #[test]
    fn trusted_peer_without_header_falls_back_to_peer() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let h = HeaderMap::new();
        assert_eq!(extract_client_ip(peer, &h, &trusted), peer);
    }

    #[test]
    fn all_trusted_xff_falls_back_to_peer() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> =
            vec!["127.0.0.1".parse().unwrap(), "172.17.0.1".parse().unwrap()];
        let h = headers_with_xff("127.0.0.1, 172.17.0.1");
        assert_eq!(extract_client_ip(peer, &h, &trusted), peer);
    }

    #[test]
    fn malformed_xff_entry_is_skipped() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let h = headers_with_xff("not-an-ip, 203.0.113.9, 127.0.0.1");
        let expected: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(extract_client_ip(peer, &h, &trusted), expected);
    }
}
