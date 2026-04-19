use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine as _;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_cookies::Cookies;

use crate::channel::handle_enrollment_ws;
use crate::client_ip::extract_client_ip;
use crate::dns::resolve_and_validate;
use crate::relay_auth::{derive_enrollment_purpose, derive_sftp_purpose, verify_relay_cookie, AppState};
use crate::sftp_relay::handle_sftp_session;

#[derive(Debug, Deserialize)]
pub struct RelayQuery {
    pub mode: Option<String>,
    pub channel: Option<String>, // base64url-encoded 16-byte channel ID (enrollment)
    pub host: Option<String>,    // SFTP target hostname or IP
    pub port: Option<u16>,       // SFTP target port
}

/// WS /relay/ws — upgrade handler, dispatches enrollment vs SFTP relay.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<RelayQuery>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    cookies: Cookies,
) -> impl IntoResponse {
    // RWS1: defence-in-depth Origin check. Browsers don't enforce same-origin
    // on WebSocket upgrades themselves, so a cross-origin page that
    // `new WebSocket(wss://relay/…)` would otherwise arrive here with a
    // SameSite=Strict cookie in some navigation contexts. Requiring the
    // Origin header to match the configured domain closes that gap. If
    // Origin is absent (older clients, curl, tests on localhost), we only
    // allow it when the server domain is `localhost` — production always
    // has a non-localhost domain and therefore always requires a header.
    if !is_origin_allowed(&headers, &state.config.domain) {
        tracing::warn!(
            domain = %state.config.domain,
            "ws upgrade denied: Origin header missing or mismatched",
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // Verify relay_auth cookie signature and expiry.
    let claims = match verify_relay_cookie(&cookies, &state.config.relay_signing_key) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);

    match query.mode.as_deref().unwrap_or("enrollment") {
        "sftp" => {
            // ── SFTP relay ────────────────────────────────────────────────
            let host = match &query.host {
                Some(h) => h.clone(),
                None => return StatusCode::BAD_REQUEST.into_response(),
            };
            let port = match query.port {
                Some(p) if p > 0 => p,
                _ => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Enforce SFTP destination-port allowlist.
            if !is_port_allowed(port, &state.config.sftp_allowed_ports) {
                tracing::warn!(

                    port,
                    "sftp relay denied: port not in allowlist",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Enforce SFTP host allowlist (empty = default-allow; SSRF protection still enforced).
            if !is_host_allowed(&host, &state.config.sftp_host_allowlist) {
                tracing::warn!(

                    host = %host,
                    "sftp relay denied: host not in allowlist",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Validate cookie purpose matches this SFTP target.
            let expected_purpose = derive_sftp_purpose(&host, port);
            if claims.purpose != expected_purpose {
                tracing::warn!(

                    cookie_purpose = %claims.purpose,
                    expected_purpose = %expected_purpose,
                    "sftp relay denied: cookie purpose mismatch",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Consume the jti — single-use enforcement.
            if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
                tracing::warn!(

                    jti = %claims.jti,
                    "sftp relay denied: jti already consumed (replay)",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Check if IP is blocked by auth-failure or spray tracker.
            if state.sftp_auth_tracker.is_blocked(client_ip) {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }

            // Per-IP concurrent SFTP connection limit.
            let _guard = match state.sftp_tracker.try_acquire(client_ip) {
                Some(g) => g,
                None => return StatusCode::TOO_MANY_REQUESTS.into_response(),
            };

            // DNS resolution + SSRF protection — must happen before upgrade.
            let pinned = match resolve_and_validate(&host).await {
                Ok(p) => p,
                Err(_) => return StatusCode::FORBIDDEN.into_response(),
            };

            let sftp_auth_tracker = Arc::clone(&state.sftp_auth_tracker);
            ws.on_upgrade(move |socket| async move {
                handle_sftp_session(socket, pinned.addrs, port, client_ip, host, sftp_auth_tracker).await;
                drop(_guard);
            })
            .into_response()
        }

        _ => {
            // ── Enrollment relay (default) ────────────────────────────────
            let channel_b64 = match &query.channel {
                Some(c) => c.clone(),
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Decode 16-byte channel ID from base64url
            let channel_id_vec =
                match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&channel_b64) {
                    Ok(bytes) if bytes.len() == 16 => bytes,
                    _ => return StatusCode::BAD_REQUEST.into_response(),
                };
            let mut channel_id = [0u8; 16];
            channel_id.copy_from_slice(&channel_id_vec);

            // Validate cookie purpose matches this enrollment channel.
            let expected_purpose = derive_enrollment_purpose(&channel_b64);
            if claims.purpose != expected_purpose {
                tracing::warn!(

                    cookie_purpose = %claims.purpose,
                    expected_purpose = %expected_purpose,
                    "enrollment relay denied: cookie purpose mismatch",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Consume the jti — single-use enforcement.
            if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
                tracing::warn!(

                    jti = %claims.jti,
                    "enrollment relay denied: jti already consumed (replay)",
                );
                return StatusCode::FORBIDDEN.into_response();
            }

            // Rate limit: 10 channel joins per minute per IP.
            if !state.join_limiter.check_and_record(client_ip) {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }

            let registry = Arc::clone(&state.channel_registry);
            ws.on_upgrade(move |socket| async move {
                handle_enrollment_ws(socket, registry, channel_id, client_ip).await;
            })
            .into_response()
        }
    }
}

/// Check whether `port` is in the SFTP destination-port allowlist.
fn is_port_allowed(port: u16, allowed_ports: &[u16]) -> bool {
    allowed_ports.contains(&port)
}

/// Check whether `host` is permitted by the allowlist.
///
/// Allowlist format (per entry):
///   - Exact hostname match (case-insensitive): `sftp.example.com`
///   - Wildcard subdomain: `*.example.com` (matches any single subdomain label)
///
/// An empty allowlist permits all hosts (default-allow).
/// Operators who know their SFTP hosts can restrict with SFTP_HOST_ALLOWLIST.
/// SSRF protection (DNS + private IP blocking) is enforced regardless.
fn is_host_allowed(host: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true; // default-allow; SSRF guard still runs after this
    }
    let host_lower = host.to_lowercase();
    for pattern in allowlist {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard: host must have exactly one additional label before the suffix.
            if let Some(rest) = host_lower.strip_suffix(suffix) {
                if let Some(label) = rest.strip_suffix('.') {
                    // label must not contain '.', meaning exactly one sub-level.
                    if !label.is_empty() && !label.contains('.') {
                        return true;
                    }
                }
            }
        } else if pattern == &host_lower {
            return true;
        }
    }
    false
}

/// RWS1: verify the WebSocket upgrade Origin header matches the configured
/// BYO domain. Browsers do NOT enforce same-origin on WebSocket handshakes,
/// so this is defense-in-depth against cross-origin malicious pages opening
/// WebSockets that would include a SameSite=Strict cookie. Dev/test
/// environments running against `localhost` may omit Origin.
fn is_origin_allowed(headers: &HeaderMap, configured_domain: &str) -> bool {
    let Some(origin_hv) = headers.get("origin") else {
        // Only allow a missing Origin when explicitly running against
        // localhost (dev/tests). Production domains require the header.
        return configured_domain == "localhost";
    };
    let Ok(origin) = origin_hv.to_str() else { return false };
    // D6: only accept http:// for `localhost` (dev/tests). Production domains
    // require https — a cleartext HTTP page on the same hostname must not be
    // able to open an authenticated WebSocket.
    let acceptable: Vec<String> = if configured_domain == "localhost" {
        vec![
            format!("https://{configured_domain}"),
            format!("http://{configured_domain}"),
        ]
    } else {
        vec![format!("https://{configured_domain}")]
    };
    acceptable.iter().any(|a| a.eq_ignore_ascii_case(origin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hv(s: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_str(s).unwrap());
        h
    }

    #[test]
    fn origin_missing_allowed_on_localhost_only() {
        let empty = HeaderMap::new();
        assert!(is_origin_allowed(&empty, "localhost"));
        assert!(!is_origin_allowed(&empty, "byo.example.com"));
    }

    #[test]
    fn origin_match_accepted() {
        assert!(is_origin_allowed(&hv("https://byo.example.com"), "byo.example.com"));
    }

    #[test]
    fn origin_case_insensitive() {
        assert!(is_origin_allowed(
            &hv("HTTPS://BYO.EXAMPLE.COM"),
            "byo.example.com"
        ));
    }

    #[test]
    fn origin_mismatch_rejected() {
        assert!(!is_origin_allowed(&hv("https://attacker.example.com"), "byo.example.com"));
        assert!(!is_origin_allowed(&hv("https://byo.example.com.attacker.com"), "byo.example.com"));
    }

    #[test]
    fn origin_http_rejected_for_non_localhost() {
        // D6: http:// only valid for localhost; non-localhost production
        // domains require https.
        assert!(!is_origin_allowed(&hv("http://byo.example.com"), "byo.example.com"));
        assert!(is_origin_allowed(&hv("http://localhost"), "localhost"));
    }

    #[test]
    fn allowlist_empty_allows_all() {
        assert!(is_host_allowed("sftp.example.com", &[]));
        assert!(is_host_allowed("anything.internal", &[]));
    }

    #[test]
    fn allowlist_exact_match() {
        let list = vec!["sftp.example.com".to_string()];
        assert!(is_host_allowed("sftp.example.com", &list));
        assert!(is_host_allowed("SFTP.EXAMPLE.COM", &list)); // case-insensitive
        assert!(!is_host_allowed("other.example.com", &list));
    }

    #[test]
    fn allowlist_wildcard_match() {
        let list = vec!["*.example.com".to_string()];
        assert!(is_host_allowed("sftp.example.com", &list));
        assert!(is_host_allowed("files.example.com", &list));
    }

    #[test]
    fn allowlist_wildcard_does_not_match_two_levels() {
        let list = vec!["*.example.com".to_string()];
        assert!(!is_host_allowed("a.b.example.com", &list));
    }

    #[test]
    fn allowlist_wildcard_does_not_match_base() {
        let list = vec!["*.example.com".to_string()];
        assert!(!is_host_allowed("example.com", &list));
    }

    #[test]
    fn port_whitelist_enforced() {
        let allowed = vec![22u16, 2022, 2222];
        assert!(is_port_allowed(22, &allowed));
        assert!(is_port_allowed(2022, &allowed));
        assert!(is_port_allowed(2222, &allowed));
        assert!(!is_port_allowed(80, &allowed));
        assert!(!is_port_allowed(443, &allowed));
        assert!(!is_port_allowed(8022, &allowed));
    }

    #[test]
    fn port_whitelist_empty_denies_all() {
        assert!(!is_port_allowed(22, &[]));
        assert!(!is_port_allowed(2222, &[]));
    }
}
