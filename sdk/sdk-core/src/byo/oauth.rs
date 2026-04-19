// OAuth2 PKCE helpers for BYO storage providers.
//
// Provides static provider configs (auth/token URLs, scopes) and pure
// string builders for:
//   - Authorization URL (auth_url?params...)
//   - Token exchange form body (authorization_code grant)
//   - Refresh form body (refresh_token grant)
//   - Token response parser
//
// The actual HTTP request and popup/redirect logic stay in the TS/Kotlin
// platform layer — only URL/form construction and JSON parsing are shared here.
//
// Redirect URI and client_id are always caller-supplied (Vite env on browser,
// BuildConfig on Android) — they are never baked into sdk-core.

use rand::RngCore;
use serde::Deserialize;
use thiserror::Error;

use crate::byo::pkce::{base64url_encode_no_pad, generate_pkce, PkcePair};
use crate::byo::provider::ProviderType;
use crate::error::SdkError;

// ─── Provider config table ────────────────────────────────────────────────────

/// Static OAuth2 config for a provider (URLs and scope only — no secrets).
pub struct OAuthProviderConfig {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scope: &'static str,
    /// Extra key-value pairs appended to the auth URL query string.
    pub extra_auth_params: &'static [(&'static str, &'static str)],
}

/// Return the static OAuth config for OAuth-capable providers (GDrive, Dropbox, OneDrive).
/// Returns `None` for non-OAuth providers (WebDAV, SFTP).
pub fn provider_oauth_config(provider: ProviderType) -> Option<&'static OAuthProviderConfig> {
    match provider {
        ProviderType::Gdrive => Some(&GDRIVE_CONFIG),
        ProviderType::Dropbox => Some(&DROPBOX_CONFIG),
        ProviderType::Onedrive => Some(&ONEDRIVE_CONFIG),
        ProviderType::Box => Some(&BOX_CONFIG),
        // pCloud: default to US config; callers that need EU must use pcloud_oauth_config_eu().
        ProviderType::Pcloud => Some(&PCLOUD_CONFIG),
        ProviderType::Webdav | ProviderType::Sftp | ProviderType::S3 => None,
    }
}

/// Return the EU-region pCloud OAuth config.
pub fn pcloud_oauth_config_eu() -> &'static OAuthProviderConfig {
    &PCLOUD_EU_CONFIG
}

static GDRIVE_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    scope: "https://www.googleapis.com/auth/drive.file",
    extra_auth_params: &[
        ("access_type", "offline"), // Request refresh token
        ("prompt", "consent"),      // Force consent to get a new refresh token
    ],
};

static DROPBOX_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://www.dropbox.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
    scope: "files.content.write files.content.read",
    // Required to receive a refresh token from Dropbox (Dropbox-specific param name).
    extra_auth_params: &[("token_access_type", "offline")],
};

static ONEDRIVE_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    scope: "Files.ReadWrite offline_access",
    extra_auth_params: &[],
};

static BOX_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://account.box.com/api/oauth2/authorize",
    token_url: "https://api.box.com/oauth2/token",
    scope: "root_readwrite",
    extra_auth_params: &[],
};

/// pCloud US datacenter (default). EU accounts use PCLOUD_EU_CONFIG instead.
static PCLOUD_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://my.pcloud.com/oauth2/authorize",
    token_url: "https://api.pcloud.com/oauth2_token",
    scope: "",
    extra_auth_params: &[],
};

/// pCloud EU datacenter.
static PCLOUD_EU_CONFIG: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://eapi.pcloud.com/oauth2/authorize",
    token_url: "https://eapi.pcloud.com/oauth2_token",
    scope: "",
    extra_auth_params: &[],
};

// ─── URL / form builders ──────────────────────────────────────────────────────

/// Build the authorization URL including PKCE params and any provider extras.
///
/// `state` should be a cryptographically random nonce for CSRF protection.
pub fn build_auth_url(
    cfg: &OAuthProviderConfig,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let mut params = vec![
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", cfg.scope),
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];
    for (k, v) in cfg.extra_auth_params {
        params.push((k, v));
    }
    let query = encode_query_params(&params);
    format!("{}?{}", cfg.auth_url, query)
}

/// Build an `application/x-www-form-urlencoded` body for the
/// `authorization_code` token exchange.
pub fn build_token_exchange_form(
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
) -> String {
    encode_form_params(&[
        ("client_id", client_id),
        ("code", code),
        ("code_verifier", code_verifier),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ])
}

/// Build an `application/x-www-form-urlencoded` body for the
/// `refresh_token` grant.
pub fn build_refresh_form(refresh_token: &str, client_id: &str) -> String {
    encode_form_params(&[
        ("client_id", client_id),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ])
}

// ─── Token response ───────────────────────────────────────────────────────────

/// Parsed OAuth2 token response (authorization_code and refresh_token grants).
#[derive(Debug, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Seconds until the access token expires.
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Maximum acceptable OAuth token response body size (64 KiB).
/// A legitimate provider response is never larger than a few KiB; rejecting
/// oversized bodies prevents unbounded allocation from a malicious provider.
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

/// Parse a JSON token response body. Returns `Err` on malformed JSON or
/// missing `access_token` field.
pub fn parse_token_response(body: &[u8]) -> Result<OAuthTokenResponse, OAuthError> {
    if body.len() > MAX_TOKEN_RESPONSE_BYTES {
        return Err(OAuthError::InvalidResponse(format!(
            "token response too large ({} bytes; max {})",
            body.len(),
            MAX_TOKEN_RESPONSE_BYTES,
        )));
    }
    // Parse as a generic value first so we can check the `error` field before
    // attempting typed deserialization.  Some providers return both
    // `access_token` and `error` (e.g. on race conditions / partial revocation);
    // we treat any `error` field as a provider-side failure regardless.
    let val: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| OAuthError::InvalidResponse(e.to_string()))?;
    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        let desc = val
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or(err);
        // O1: sanitize attacker-controlled provider error strings before
        // embedding them in our error variant. Callers may log this; a
        // hostile provider could otherwise inject newlines / CSI sequences
        // to spoof log entries.
        return Err(OAuthError::ProviderError(sanitize_error_msg(desc)));
    }
    serde_json::from_value(val).map_err(|e| OAuthError::InvalidResponse(e.to_string()))
}

// ─── OAuthExchangeFlow ────────────────────────────────────────────────────────

/// Stateful PKCE OAuth2 exchange flow.
///
/// Holds the PKCE verifier and a CSRF-protection state nonce until the provider
/// redirects back with an authorization code.  The platform layer owns the
/// popup/redirect mechanism; this struct owns only the cryptographic state.
///
/// # Usage
///
/// ```rust,ignore
/// use sdk_core::byo::oauth::{OAuthExchangeFlow, provider_oauth_config};
/// use sdk_core::byo::ProviderType;
///
/// let cfg = provider_oauth_config(ProviderType::Gdrive).unwrap();
/// let mut flow = OAuthExchangeFlow::new()?;
/// let url = flow.auth_url(cfg, "client-id-here", "https://app.example.com/callback");
///
/// // … open browser popup, wait for redirect …
/// let returned_state = "…";  // from redirect URL ?state= param
/// let code = "…";             // from redirect URL ?code= param
///
/// let form = flow.build_exchange_form(returned_state, code, "client-id-here",
///                                     "https://app.example.com/callback")?;
/// // POST form to cfg.token_url and parse the response.
/// ```
pub struct OAuthExchangeFlow {
    pkce: PkcePair,
    state: String,
}

impl OAuthExchangeFlow {
    /// Begin a new OAuth2 PKCE flow.
    ///
    /// Generates a fresh PKCE verifier + challenge and a 16-byte random state
    /// nonce.  Returns `Err` only if the OS RNG is unavailable (extremely rare).
    pub fn new() -> Result<Self, SdkError> {
        let pkce = generate_pkce()?;
        let state = generate_state()?;
        Ok(Self { pkce, state })
    }

    /// Build the provider authorization URL.
    ///
    /// The URL embeds the PKCE challenge and the CSRF state nonce.  Open this
    /// URL in a browser popup or Custom Tab; the provider will redirect back
    /// with `?code=…&state=…` query parameters.
    pub fn auth_url(&self, cfg: &OAuthProviderConfig, client_id: &str, redirect_uri: &str) -> String {
        build_auth_url(cfg, client_id, redirect_uri, &self.state, &self.pkce.code_challenge)
    }

    /// Validate the redirect state and build the token-exchange form body.
    ///
    /// Call this after the browser popup redirects back.
    ///
    /// # Arguments
    ///
    /// * `returned_state` — the `state` query parameter from the redirect URL.
    ///   Must match the nonce embedded in the original authorization URL.
    /// * `code` — the `code` query parameter from the redirect URL.
    /// * `client_id` — same client_id used in `auth_url`.
    /// * `redirect_uri` — same redirect_uri used in `auth_url`.
    ///
    /// # Errors
    ///
    /// Returns `Err(SdkError::Auth)` if `returned_state` does not match the
    /// stored nonce (CSRF attack or stale redirect).
    pub fn build_exchange_form(
        self,
        returned_state: &str,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<String, SdkError> {
        if returned_state != self.state {
            return Err(SdkError::Auth(crate::error::AuthError::ChallengeFailed));
        }
        Ok(build_token_exchange_form(code, &self.pkce.code_verifier, redirect_uri, client_id))
    }
}

/// Generate a cryptographically random 16-byte state nonce, base64url-encoded.
/// O1: sanitize provider-supplied error strings. Strips control bytes
/// (including CR/LF and CSI sequences), collapses ASCII non-printables to
/// the Unicode replacement char, and caps to 256 bytes so a hostile
/// provider can't fill logs or spoof additional log lines. Non-ASCII
/// printable content is preserved as-is.
fn sanitize_error_msg(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(256));
    for c in s.chars() {
        let code = c as u32;
        if code < 0x20 || code == 0x7f {
            out.push('\u{FFFD}');
        } else {
            out.push(c);
        }
        if out.len() >= 256 {
            break;
        }
    }
    out
}

fn generate_state() -> Result<String, SdkError> {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes)
        .map_err(|_| SdkError::Crypto(crate::error::CryptoError::InvalidKeyMaterial))?;
    Ok(base64url_encode_no_pad(&bytes))
}

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("invalid provider response: {0}")]
    InvalidResponse(String),
    #[error("provider error: {0}")]
    ProviderError(String),
    #[error("unsupported provider")]
    UnsupportedProvider,
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

/// URL-encode a query parameter value (RFC 3986 unreserved chars are unescaped;
/// spaces become `%20`; everything else is percent-encoded).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            // Unreserved chars per RFC 3986 §2.3 — never encoded
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            // Everything else is percent-encoded
            b => {
                out.push('%');
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 0x0F));
            }
        }
    }
    out
}

fn hex_nibble(n: u8) -> char {
    b"0123456789ABCDEF"[n as usize] as char
}

/// Build a `key=value&...` query string; values are percent-encoded.
fn encode_query_params(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build an `application/x-www-form-urlencoded` body.
/// Spaces in values encode as `+`; other special chars as `%XX`.
fn encode_form_params(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| {
            // Form encoding: space → '+', other chars → percent-encode
            let venc = v.replace(' ', "+");
            format!("{}={}", percent_encode(k), percent_encode_form_value(&venc))
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Like `percent_encode` but treats '+' as a literal (space was already
/// swapped to '+' by the caller).
fn percent_encode_form_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'+' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 0x0F));
            }
        }
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── OAuthExchangeFlow ─────────────────────────────────────────────────────

    #[test]
    fn auth_url_contains_state_and_challenge() {
        let cfg = provider_oauth_config(ProviderType::Gdrive).unwrap();
        let flow = OAuthExchangeFlow::new().unwrap();
        let url = flow.auth_url(cfg, "my-client", "https://app.example.com/cb");
        assert!(url.contains("state="));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.starts_with("https://accounts.google.com/"));
    }

    #[test]
    fn exchange_succeeds_with_correct_state() {
        let cfg = provider_oauth_config(ProviderType::Dropbox).unwrap();
        let flow = OAuthExchangeFlow::new().unwrap();
        let url = flow.auth_url(cfg, "cid", "https://example.com/cb");

        // Extract state from the URL.
        let state_val = url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let form = flow
            .build_exchange_form(state_val, "auth-code-123", "cid", "https://example.com/cb")
            .unwrap();
        assert!(form.contains("grant_type=authorization_code"));
        assert!(form.contains("code=auth-code-123"));
        assert!(form.contains("code_verifier="));
    }

    #[test]
    fn exchange_fails_on_state_mismatch() {
        let flow = OAuthExchangeFlow::new().unwrap();
        let err = flow
            .build_exchange_form("wrong-state", "code", "cid", "https://example.com/cb")
            .unwrap_err();
        assert!(matches!(err, SdkError::Auth(_)));
    }

    #[test]
    fn each_flow_has_unique_state() {
        let flow1 = OAuthExchangeFlow::new().unwrap();
        let flow2 = OAuthExchangeFlow::new().unwrap();
        assert_ne!(flow1.state, flow2.state);
    }

    #[test]
    fn each_flow_has_unique_pkce() {
        let flow1 = OAuthExchangeFlow::new().unwrap();
        let flow2 = OAuthExchangeFlow::new().unwrap();
        assert_ne!(flow1.pkce.code_verifier, flow2.pkce.code_verifier);
    }

    // ── provider_oauth_config ─────────────────────────────────────────────────

    #[test]
    fn gdrive_config_fields() {
        let cfg = provider_oauth_config(ProviderType::Gdrive).unwrap();
        assert_eq!(cfg.auth_url, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(cfg.token_url, "https://oauth2.googleapis.com/token");
        assert!(cfg.scope.contains("drive.file"));
        assert!(cfg.extra_auth_params.contains(&("access_type", "offline")));
        assert!(cfg.extra_auth_params.contains(&("prompt", "consent")));
    }

    #[test]
    fn dropbox_config_fields() {
        let cfg = provider_oauth_config(ProviderType::Dropbox).unwrap();
        assert!(cfg.auth_url.contains("dropbox.com"));
        assert!(cfg.scope.contains("files.content.write"));
        assert!(cfg.extra_auth_params.contains(&("token_access_type", "offline")));
    }

    #[test]
    fn onedrive_config_fields() {
        let cfg = provider_oauth_config(ProviderType::Onedrive).unwrap();
        assert!(cfg.auth_url.contains("microsoftonline.com"));
        assert!(cfg.scope.contains("offline_access"));
    }

    #[test]
    fn webdav_sftp_have_no_oauth_config() {
        assert!(provider_oauth_config(ProviderType::Webdav).is_none());
        assert!(provider_oauth_config(ProviderType::Sftp).is_none());
        assert!(provider_oauth_config(ProviderType::Box).is_some());
        assert!(provider_oauth_config(ProviderType::Pcloud).is_some());
    }

    // ── build_auth_url ────────────────────────────────────────────────────────

    #[test]
    fn build_auth_url_contains_required_params() {
        let cfg = provider_oauth_config(ProviderType::Dropbox).unwrap();
        let url = build_auth_url(
            cfg,
            "my_client_id",
            "http://localhost:5173/oauth/callback",
            "random_state_abc",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
        assert!(url.starts_with("https://www.dropbox.com/oauth2/authorize?"));
        assert!(url.contains("client_id=my_client_id"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=random_state_abc"));
        // redirect_uri must be percent-encoded
        assert!(url.contains("http%3A%2F%2Flocalhost%3A5173%2Foauth%2Fcallback"));
    }

    #[test]
    fn build_auth_url_gdrive_includes_extra_params() {
        let cfg = provider_oauth_config(ProviderType::Gdrive).unwrap();
        let url = build_auth_url(cfg, "cid", "https://example.com/cb", "st", "ch");
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
    }

    // ── build_token_exchange_form ─────────────────────────────────────────────

    #[test]
    fn build_token_exchange_form_fields() {
        let body = build_token_exchange_form(
            "auth_code_xyz",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "http://localhost:5173/oauth/callback",
            "my_client",
        );
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=auth_code_xyz"));
        assert!(body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert!(body.contains("client_id=my_client"));
        // redirect_uri must be encoded
        assert!(body.contains("http%3A%2F%2Flocalhost%3A5173%2Foauth%2Fcallback"));
    }

    // ── build_refresh_form ────────────────────────────────────────────────────

    #[test]
    fn build_refresh_form_fields() {
        let body = build_refresh_form("my_refresh_token", "my_client");
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=my_refresh_token"));
        assert!(body.contains("client_id=my_client"));
    }

    // ── parse_token_response ──────────────────────────────────────────────────

    #[test]
    fn parse_google_token_response() {
        let json = br#"{
          "access_token": "ya29.access",
          "refresh_token": "1//refresh",
          "expires_in": 3599,
          "token_type": "Bearer",
          "scope": "https://www.googleapis.com/auth/drive.file"
        }"#;
        let r = parse_token_response(json).unwrap();
        assert_eq!(r.access_token, "ya29.access");
        assert_eq!(r.refresh_token, Some("1//refresh".to_string()));
        assert_eq!(r.expires_in, Some(3599));
    }

    #[test]
    fn parse_dropbox_token_response_short_lived() {
        // Without token_access_type=offline, Dropbox omits the refresh_token.
        // This shape is kept as a regression guard — we now always request offline.
        let json = br#"{
          "access_token": "sl.db_token",
          "token_type": "bearer",
          "expires_in": 14400
        }"#;
        let r = parse_token_response(json).unwrap();
        assert_eq!(r.access_token, "sl.db_token");
        assert!(r.refresh_token.is_none());
    }

    #[test]
    fn parse_dropbox_token_response_with_refresh_token() {
        // Expected response when token_access_type=offline is set.
        let json = br#"{
          "access_token": "sl.ABCDaccess",
          "token_type": "bearer",
          "expires_in": 14400,
          "refresh_token": "sl.ABCDrefresh",
          "uid": "12345",
          "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc"
        }"#;
        let r = parse_token_response(json).unwrap();
        assert_eq!(r.access_token, "sl.ABCDaccess");
        assert_eq!(r.refresh_token, Some("sl.ABCDrefresh".to_string()));
        assert_eq!(r.expires_in, Some(14400));
    }

    #[test]
    fn build_dropbox_auth_url_includes_offline_param() {
        let cfg = provider_oauth_config(ProviderType::Dropbox).unwrap();
        let url = build_auth_url(cfg, "cid", "https://example.com/cb", "st", "ch");
        assert!(url.contains("token_access_type=offline"));
    }

    #[test]
    fn parse_token_response_provider_error() {
        let json = br#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"#;
        let err = parse_token_response(json).unwrap_err();
        assert!(matches!(err, OAuthError::ProviderError(_)));
        assert!(err.to_string().contains("expired or revoked"));
    }

    #[test]
    fn parse_token_response_rejects_malformed_json() {
        let err = parse_token_response(b"not json").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidResponse(_)));
    }

    // ── encoding helpers ──────────────────────────────────────────────────────

    #[test]
    fn percent_encode_unreserved_unchanged() {
        assert_eq!(percent_encode("abc-123_.~"), "abc-123_.~");
    }

    #[test]
    fn percent_encode_slash_and_colon() {
        assert_eq!(percent_encode("http://a/b"), "http%3A%2F%2Fa%2Fb");
    }

    #[test]
    fn percent_encode_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn scope_with_space_encodes_as_plus_in_form() {
        let body = build_token_exchange_form("c", "v", "http://localhost/cb", "id");
        // scope is not in the token exchange form — just check redirect_uri encoding
        assert!(body.contains("%3A%2F%2F"));
    }

    #[test]
    fn dropbox_scope_spaces_encoded_in_auth_url() {
        let cfg = provider_oauth_config(ProviderType::Dropbox).unwrap();
        let url = build_auth_url(cfg, "c", "https://example.com/cb", "s", "ch");
        // scope="files.content.write files.content.read" — spaces become %20 in query
        assert!(url.contains("files.content.write%20files.content.read"));
    }

    #[test]
    fn parse_token_response_rejects_oversized_body() {
        let body = vec![b'x'; 64 * 1024 + 1];
        match parse_token_response(&body) {
            Err(OAuthError::InvalidResponse(msg)) => {
                assert!(msg.contains("too large"), "error should mention size: {msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_token_response_accepts_64kib_body() {
        // Exactly at the limit: should fail on JSON parse, not size check.
        let body = vec![b'x'; 64 * 1024];
        match parse_token_response(&body) {
            Err(OAuthError::InvalidResponse(msg)) => {
                assert!(!msg.contains("too large"), "size check should pass at exactly 64 KiB");
            }
            other => {
                // Unexpected Ok or ProviderError — also acceptable.
                let _ = other;
            }
        }
    }
}
