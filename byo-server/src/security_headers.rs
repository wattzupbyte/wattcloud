use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

/// Middleware adding BYO-specific security headers per BYO_PLAN.md Section 5.6.
///
/// `domain` is the BYO server's domain (e.g. byo.example.com), used in CSP wss:// directive.
/// Apply this middleware after inserting the domain extension (see main.rs).
///
/// `/share/*` paths receive a narrowed CSP: `connect-src 'self' https:` (needed for B1
/// provider URL fetches) but no OAuth-specific origins or WebSocket upgrade needed.
pub async fn byo_security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    // Determine CSP scope before request is consumed by next.run().
    let is_share_path = request.uri().path().starts_with("/share");

    // Extract domain from request extensions (inserted by the router layer in main.rs)
    let domain = request
        .extensions()
        .get::<Domain>()
        .map(|d| d.0.as_str())
        .unwrap_or("localhost");

    let csp = if is_share_path {
        build_share_csp()
    } else {
        build_csp(domain)
    };

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    if let Ok(v) = HeaderValue::from_str(&csp) {
        headers.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // D7: SPEC-BYO §Security Headers requires `camera=(), microphone=(),
    // geolocation=()`. The prior `camera=(self)` unexpectedly granted the BYO
    // origin its own camera access and missed `geolocation=()` entirely.
    if let Ok(v) = HeaderValue::from_str("camera=(), microphone=(), geolocation=()") {
        headers.insert(header::HeaderName::from_static("permissions-policy"), v);
    }
    // Strict-Transport-Security is harmless on HTTP (browsers ignore it) and required on HTTPS.
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );

    response
}

/// Extension type for injecting the BYO domain into requests.
#[derive(Clone)]
pub struct Domain(pub String);

/// Build the Content-Security-Policy for the `/share/*` page.
///
/// Narrower than the main app CSP: no OAuth origins, no WebSocket (share page is
/// a static decrypt-only page). `connect-src 'self' https:` allows variant B1
/// to fetch provider presigned URLs (which may point to any HTTPS origin).
pub(crate) fn build_share_csp() -> String {
    "default-src 'none'; \
     script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     connect-src 'self' https:; \
     img-src 'self' blob:; \
     worker-src 'self'; \
     object-src 'none'; \
     frame-ancestors 'none'; \
     base-uri 'self'; \
     form-action 'self'"
        .to_string()
}

/// Build the Content-Security-Policy value for a given BYO domain.
pub(crate) fn build_csp(domain: &str) -> String {
    // default-src 'none': unlisted directives fall back to blocked, not 'self'.
    // All required source types are enumerated explicitly.
    format!(
        "default-src 'none'; \
         script-src 'self' 'wasm-unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; \
         connect-src 'self' \
           https://oauth2.googleapis.com https://www.googleapis.com \
           https://content.googleapis.com https://*.googleusercontent.com \
           https://api.dropboxapi.com https://content.dropboxapi.com \
           https://login.microsoftonline.com https://graph.microsoft.com \
           https://*.sharepoint.com https://*.1drv.com \
           https://api.box.com https://upload.box.com https://account.box.com \
           https://api.pcloud.com https://eapi.pcloud.com \
           https://*.pcloud.com https://*.pcloud.link \
           wss://{domain}; \
         img-src 'self' blob:; \
         worker-src 'self'; \
         object-src 'none'; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'"
    )
}

#[cfg(test)]
mod tests {
    use super::{build_csp, build_share_csp};

    #[test]
    fn csp_starts_with_none_default() {
        let csp = build_csp("byo.example.com");
        assert!(csp.starts_with("default-src 'none'"), "CSP must open with default-src 'none'");
    }

    #[test]
    fn csp_includes_wasm_script_directive() {
        let csp = build_csp("byo.example.com");
        assert!(csp.contains("'wasm-unsafe-"), "CSP must include wasm-unsafe directive");
    }

    #[test]
    fn csp_includes_wss_connect_src() {
        let csp = build_csp("byo.example.com");
        assert!(csp.contains("wss://byo.example.com"), "CSP must allow WSS to the BYO domain");
    }

    #[test]
    fn csp_blocks_object_src() {
        let csp = build_csp("byo.example.com");
        assert!(csp.contains("object-src 'none'"), "CSP must block object-src");
    }

    #[test]
    fn csp_includes_oauth_connect_srcs() {
        let csp = build_csp("byo.example.com");
        assert!(csp.contains("https://oauth2.googleapis.com"), "CSP must allow Google OAuth endpoint");
        assert!(csp.contains("https://www.googleapis.com"), "CSP must allow Google Drive API");
        assert!(csp.contains("https://api.dropboxapi.com"), "CSP must allow Dropbox API");
        assert!(csp.contains("https://login.microsoftonline.com"), "CSP must allow Microsoft OAuth endpoint");
        assert!(csp.contains("https://graph.microsoft.com"), "CSP must allow OneDrive API");
        // F2: Box + pCloud OAuth endpoints were missing from the allowlist;
        // their token-exchange fetches would have been blocked by the CSP.
        assert!(csp.contains("https://api.box.com"), "CSP must allow Box API");
        assert!(csp.contains("https://account.box.com"), "CSP must allow Box OAuth endpoint");
        assert!(csp.contains("https://api.pcloud.com"), "CSP must allow pCloud US API");
        assert!(csp.contains("https://eapi.pcloud.com"), "CSP must allow pCloud EU API");
    }

    #[test]
    fn csp_blocks_framing() {
        let csp = build_csp("byo.example.com");
        assert!(csp.contains("frame-ancestors 'none'"), "CSP must deny framing");
    }

    #[test]
    fn csp_domain_interpolated_correctly() {
        let csp1 = build_csp("server1.test");
        let csp2 = build_csp("server2.test");
        assert!(csp1.contains("wss://server1.test"));
        assert!(!csp1.contains("wss://server2.test"));
        assert!(csp2.contains("wss://server2.test"));
        assert!(!csp2.contains("wss://server1.test"));
    }

    #[test]
    fn share_csp_allows_https_connect_src() {
        let csp = build_share_csp();
        assert!(csp.contains("connect-src 'self' https:"), "share CSP must allow https: for B1 provider URLs");
        assert!(!csp.contains("oauth2.googleapis.com"), "share CSP must not include OAuth origins");
        assert!(!csp.contains("wss://"), "share CSP must not allow WebSocket (no relay connection needed)");
        assert!(csp.contains("default-src 'none'"), "share CSP must open with default-src 'none'");
        assert!(csp.contains("frame-ancestors 'none'"), "share CSP must deny framing");
    }

    #[test]
    fn share_csp_allows_wasm() {
        let csp = build_share_csp();
        assert!(csp.contains("'wasm-unsafe-eval'"), "share CSP must allow WASM for in-browser decrypt");
    }

    #[test]
    fn hsts_header_value_correct() {
        // Verify the HSTS value constant is well-formed (max-age ≥ 1 year, includeSubDomains).
        let hsts = "max-age=63072000; includeSubDomains";
        assert!(hsts.contains("max-age=63072000"), "HSTS must set max-age to 2 years");
        assert!(hsts.contains("includeSubDomains"), "HSTS must include subdomains");
        // Ensure it's parseable as a header value.
        assert!(axum::http::HeaderValue::from_str(hsts).is_ok());
    }
}
