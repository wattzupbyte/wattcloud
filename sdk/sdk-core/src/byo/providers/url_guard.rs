// Provider URL guard (SSRF protection).
//
// Several BYO code paths accept URLs from attacker-controlled sources:
//
//   * The `Location` header of resumable-upload starts (GDrive, tus/WebDAV).
//   * The `uploadUrl` field of OneDrive's createUploadSession response.
//   * The `hosts[]` and `path` fields of pCloud's getfilelink response.
//   * The `<D:href>` values in a WebDAV PROPFIND reply.
//   * User-supplied `s3_endpoint` / `serverUrl` in ProviderConfig.
//
// A hostile provider (or MITM on an OAuth API response) can redirect every
// subsequent ciphertext chunk to an arbitrary host — classically the cloud
// metadata service at 169.254.169.254. V7 ciphertext confidentiality still
// holds (no ZK-5 violation), but the SSRF primitive is real: the relay server
// learns that the VM has connectivity to the target, receives the Authorization
// header attached to the request, and can exfiltrate IAM role credentials.
//
// This module centralises the guard. Every `Location`, `uploadUrl`, CDN-host,
// or PROPFIND-href that the code ingests from a provider response MUST be
// validated through one of these helpers before being used as the target of
// another HTTP call.

use crate::byo::ProviderError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Require `https://` as the scheme. Non-HTTPS urls are rejected because:
///   * Credentials (Bearer, Basic) would travel in clear text.
///   * `http://169.254.169.254` is the canonical AWS metadata URL.
///   * Relay requirements (V7 ciphertext carried only over TLS) must not
///     be silently downgraded by a hostile response.
fn require_https(url: &Url) -> Result<(), ProviderError> {
    if url.scheme() != "https" {
        return Err(ProviderError::Provider(format!(
            "refusing non-HTTPS URL: {}",
            url.scheme()
        )));
    }
    Ok(())
}

/// Reject every host that could redirect traffic inside the cloud/VPC:
///   * RFC 1918 private ranges (10/8, 172.16/12, 192.168/16)
///   * Loopback (127/8 and ::1)
///   * Link-local (169.254.0.0/16 — **AWS metadata**, fe80::/10)
///   * CGNAT (100.64.0.0/10)
///   * Broadcast + unspecified + documentation ranges
///   * Multicast (224.0.0.0/4)
///   * IPv6 ULA (fc00::/7)
///   * Benchmarking range 198.18.0.0/15 (some cloud overlays use it)
fn reject_private_host(url: &Url) -> Result<(), ProviderError> {
    let host = url
        .host()
        .ok_or_else(|| ProviderError::Provider(format!("URL has no host: {url}")))?;
    match host {
        url::Host::Ipv4(ip) => {
            if is_blocked_v4(ip) {
                return Err(ProviderError::Provider(format!(
                    "refusing URL with private/internal IPv4 host: {ip}"
                )));
            }
        }
        url::Host::Ipv6(ip) => {
            if is_blocked_v6(ip) {
                return Err(ProviderError::Provider(format!(
                    "refusing URL with private/internal IPv6 host: {ip}"
                )));
            }
        }
        url::Host::Domain(name) => {
            // Strings are also literal IPs without the `http://[…]` bracket.
            if let Ok(IpAddr::V4(ip)) = name.parse::<IpAddr>() {
                if is_blocked_v4(ip) {
                    return Err(ProviderError::Provider(format!(
                        "refusing URL with private/internal IPv4 host: {ip}"
                    )));
                }
            }
            if let Ok(IpAddr::V6(ip)) = name.parse::<IpAddr>() {
                if is_blocked_v6(ip) {
                    return Err(ProviderError::Provider(format!(
                        "refusing URL with private/internal IPv6 host: {ip}"
                    )));
                }
            }
            // Reject localhost by name.
            if name.eq_ignore_ascii_case("localhost") {
                return Err(ProviderError::Provider(
                    "refusing URL with host 'localhost'".to_string(),
                ));
            }
        }
    }
    // Reject URLs that smuggle credentials inline (`https://user:pw@host/…`)
    // since our HTTP layer uses an explicit Authorization header; inline
    // credentials are a common obfuscation trick.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProviderError::Provider(
            "refusing URL with embedded credentials".into(),
        ));
    }
    Ok(())
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
        // CGNAT 100.64.0.0/10
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64)
        // RFC 2544 benchmarking 198.18.0.0/15
        || (ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19))
        // IETF protocol assignments 192.0.0.0/24
        || (ip.octets()[0..3] == [192, 0, 0])
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // Link-local fe80::/10
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        // ULA fc00::/7
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // IPv4-mapped: delegate to v4 rules.
        || ip
            .to_ipv4_mapped()
            .map(is_blocked_v4)
            .unwrap_or(false)
}

/// Validate a URL that was returned by a provider API response (resumable
/// upload `Location` header, OneDrive `uploadUrl`, pCloud CDN host, etc.).
///
/// Requires HTTPS, no inline credentials, and no host that resolves to a
/// reserved/private/link-local/multicast range.
///
/// If `allowed_suffixes` is non-empty, the URL host must also end with one of
/// the given suffixes (case-insensitive). Use this to scope provider-response
/// URLs to the provider's own API / CDN domains; pass an empty slice to skip
/// the suffix check (still enforces HTTPS + private-IP block).
pub fn validate_response_url(
    url_str: &str,
    allowed_suffixes: &[&str],
) -> Result<Url, ProviderError> {
    let url = Url::parse(url_str)
        .map_err(|e| ProviderError::Provider(format!("invalid URL from provider: {e}")))?;
    require_https(&url)?;
    reject_private_host(&url)?;

    if !allowed_suffixes.is_empty() {
        let host_str = url.host_str().unwrap_or("").to_ascii_lowercase();
        let matches_suffix = allowed_suffixes.iter().any(|suf| {
            host_str == suf.to_ascii_lowercase()
                || host_str.ends_with(&format!(".{}", suf.to_ascii_lowercase()))
        });
        if !matches_suffix {
            return Err(ProviderError::Provider(format!(
                "refusing URL with host {host_str}: not in provider allowlist"
            )));
        }
    }
    Ok(url)
}

/// Validate a URL derived from user-supplied provider configuration
/// (`serverUrl` for WebDAV, `s3_endpoint` for S3). Requires HTTPS: plaintext
/// `http://` would send Basic auth / S3 AccessKey in cleartext on every
/// request, and `reject_private_host` already blocks the loopback case that a
/// relaxed rule would have targeted — so `http://` was only ever reachable for
/// public hosts, which is exactly the footgun we want to close.
///
/// Also blocks private/internal IPs (RFC 1918, link-local AWS metadata, …).
pub fn validate_config_url(url_str: &str) -> Result<Url, ProviderError> {
    let url = Url::parse(url_str)
        .map_err(|e| ProviderError::Provider(format!("invalid URL in config: {e}")))?;
    require_https(&url)?;
    reject_private_host(&url)?;
    Ok(url)
}

/// Like [`validate_response_url`] but also verifies the URL shares the same
/// origin (scheme + host + port) as `base`. Use for `Location` headers from a
/// resumable-upload start whose continuation must remain on the originating
/// API/CDN (tus, WebDAV chunked PUT, GDrive resumable, Box upload session).
///
/// `base` may be either a full URL or the configured server base. The guard
/// parses `base` with the same rules and then requires origin equality.
pub fn validate_same_origin(url_str: &str, base: &Url) -> Result<Url, ProviderError> {
    let url = Url::parse(url_str)
        .map_err(|e| ProviderError::Provider(format!("invalid URL from provider: {e}")))?;
    require_https(&url).or_else(|_| {
        // Permit http only when `base` is also http (configured plaintext endpoint).
        if base.scheme() == "http" && url.scheme() == "http" {
            Ok(())
        } else {
            Err(ProviderError::Provider(format!(
                "refusing non-matching scheme {}",
                url.scheme()
            )))
        }
    })?;
    reject_private_host(&url)?;
    if url.origin() != base.origin() {
        return Err(ProviderError::Provider(format!(
            "refusing URL with mismatched origin: got {}, expected {}",
            url.origin().ascii_serialization(),
            base.origin().ascii_serialization()
        )));
    }
    Ok(url)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_https() {
        let u = validate_response_url("https://www.googleapis.com/upload", &[]).unwrap();
        assert_eq!(u.host_str(), Some("www.googleapis.com"));
    }

    #[test]
    fn rejects_http() {
        assert!(validate_response_url("http://www.googleapis.com/u", &[]).is_err());
    }

    #[test]
    fn rejects_localhost_by_name() {
        assert!(validate_response_url("https://localhost/x", &[]).is_err());
    }

    #[test]
    fn rejects_aws_metadata() {
        assert!(validate_response_url("https://169.254.169.254/latest", &[]).is_err());
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(validate_response_url("https://10.0.0.1/", &[]).is_err());
        assert!(validate_response_url("https://172.16.0.1/", &[]).is_err());
        assert!(validate_response_url("https://192.168.1.1/", &[]).is_err());
    }

    #[test]
    fn rejects_cgnat() {
        assert!(validate_response_url("https://100.64.0.1/", &[]).is_err());
        assert!(validate_response_url("https://100.127.255.254/", &[]).is_err());
    }

    #[test]
    fn rejects_ipv6_link_local() {
        assert!(validate_response_url("https://[fe80::1]/", &[]).is_err());
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(validate_response_url("https://[fc00::1]/", &[]).is_err());
        assert!(validate_response_url("https://[fd00::1]/", &[]).is_err());
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(validate_response_url("https://[::1]/", &[]).is_err());
    }

    #[test]
    fn rejects_embedded_credentials() {
        assert!(validate_response_url("https://attacker:token@www.googleapis.com/", &[]).is_err());
    }

    #[test]
    fn suffix_allowlist_enforced() {
        // Host suffix allowed.
        assert!(validate_response_url(
            "https://x.googleusercontent.com/f",
            &["googleusercontent.com"]
        )
        .is_ok());
        // Exact match also allowed.
        assert!(validate_response_url(
            "https://googleusercontent.com/f",
            &["googleusercontent.com"]
        )
        .is_ok());
        // Sibling domain rejected.
        assert!(
            validate_response_url("https://attacker.com/f", &["googleusercontent.com"]).is_err()
        );
        // Look-alike suffix (foogoogleusercontent.com) is rejected because we
        // require a dot-separator or exact match.
        assert!(validate_response_url(
            "https://foogoogleusercontent.com/f",
            &["googleusercontent.com"]
        )
        .is_err());
    }

    #[test]
    fn config_url_allows_loopback_http_dev() {
        // Developer workflows: MinIO / WebDAV over plaintext loopback.
        // Explicit loopback still blocks because we reject ALL private hosts
        // (loopback is a frequent SSRF bypass). Dev rigs must tunnel through
        // a TLS terminator or bind to a non-reserved address.
        assert!(validate_config_url("http://127.0.0.1:9000").is_err());
    }

    #[test]
    fn config_url_rejects_private() {
        assert!(validate_config_url("https://192.168.1.5").is_err());
        assert!(validate_config_url("http://192.168.1.5").is_err());
    }

    #[test]
    fn config_url_rejects_unknown_scheme() {
        assert!(validate_config_url("file:///etc/passwd").is_err());
        assert!(validate_config_url("ftp://example.com").is_err());
    }

    #[test]
    fn config_url_rejects_http_public_host() {
        // Plaintext to a public host would leak Basic auth / S3 AccessKey —
        // reject at config time so the user notices before the first request.
        assert!(validate_config_url("http://webdav.example.com").is_err());
        assert!(validate_config_url("http://s3.example.com:9000").is_err());
        assert!(validate_config_url("https://webdav.example.com").is_ok());
    }

    #[test]
    fn same_origin_guard() {
        let base = Url::parse("https://dav.example.com/webdav/").unwrap();
        // Same origin, different path — ok.
        assert!(validate_same_origin("https://dav.example.com/uploads/abc", &base).is_ok());
        // Different host — reject.
        assert!(validate_same_origin("https://attacker.example.com/u", &base).is_err());
        // Same host, different scheme — reject.
        assert!(validate_same_origin("http://dav.example.com/u", &base).is_err());
        // Same host, private IP form — reject.
        assert!(validate_same_origin("https://169.254.169.254/u", &base).is_err());
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_of_private() {
        // ::ffff:10.0.0.1 maps to 10.0.0.1, must still be blocked.
        assert!(validate_response_url("https://[::ffff:10.0.0.1]/", &[]).is_err());
        assert!(validate_response_url("https://[::ffff:169.254.169.254]/", &[]).is_err());
    }

    #[test]
    fn rejects_multicast_v4() {
        assert!(validate_response_url("https://224.0.0.1/", &[]).is_err());
    }

    #[test]
    fn rejects_benchmarking_range() {
        assert!(validate_response_url("https://198.18.0.1/", &[]).is_err());
        assert!(validate_response_url("https://198.19.255.254/", &[]).is_err());
    }
}
