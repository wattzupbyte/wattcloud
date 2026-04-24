// BYO share-relay client: typed wrappers for B1 (presigned-URL pointer) and
// B2 (ciphertext blob) endpoints on `byo-relay/src/share_relay.rs`.
//
// The relay stores only: share_id, opaque provider URL or V7 ciphertext,
// expiry, and a revoked flag. Content keys are NEVER transmitted to the relay.
//
// # Auth model
//
// Create/upload endpoints require a relay auth cookie (obtained via PoW
// challenge). Pass the full Cookie header value (e.g. `"relay_auth=<jwt>"`).
//
// Revoke endpoints use the `X-Owner-Token` header with the HMAC bearer token
// returned at creation time (no relay cookie needed for revocation).
//
// # Usage
//
// ```rust,ignore
// let client = ShareRelayClient::new(http_client, "https://byo.example.com");
//
// // B1 — presigned URL pointer
// let resp = client.create_b1("share-id-uuid", "https://gdrive.../file", 86400, &relay_cookie).await?;
// let b1 = client.get_b1("share-id-uuid").await?;
// client.revoke_b1("share-id-uuid", &resp.owner_token).await?;
//
// // B2 — V7 ciphertext blob (max 200 MiB)
// let resp = client.upload_b2("share-id-uuid", ciphertext_bytes, 86400, &relay_cookie).await?;
// let blob = client.get_b2("share-id-uuid").await?;
// client.revoke_b2("share-id-uuid", &resp.owner_token).await?;
// ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::api::provider_http::{ProviderHttpClient, ProviderHttpRequest};
use crate::error::{SdkError, ShareRelayError};

// ─── Input validation ─────────────────────────────────────────────────────────

/// Validate a `share_id` or `owner_token` that will be interpolated into a URL
/// path segment or `X-*` header value.
///
/// Allowed charset: `[A-Za-z0-9_-]`.  This matches the server-issued UUID /
/// base64url-without-padding format and prevents path traversal (`..`, `/`,
/// `?`) and header injection (CR, LF).
fn validate_share_id(value: &str, field: &str) -> Result<(), SdkError> {
    if value.is_empty() {
        return Err(SdkError::ShareRelay(ShareRelayError::Unexpected(400)));
    }
    let ok = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err(SdkError::ShareRelay(ShareRelayError::Unexpected(400)));
    }
    let _ = field; // used only for documentation clarity at call sites
    Ok(())
}

/// Reject any header value that contains CR (`\r`) or LF (`\n`) to prevent
/// HTTP header-splitting attacks.
fn validate_header_value(value: &str, field: &str) -> Result<(), SdkError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        let _ = field;
        return Err(SdkError::ShareRelay(ShareRelayError::Unexpected(400)));
    }
    Ok(())
}

// ─── Response types ───────────────────────────────────────────────────────────

/// Returned by `create_b1` and `upload_b2`.
#[derive(Debug)]
pub struct ShareCreateResponse {
    pub share_id: String,
    /// Unix timestamp (seconds) when the share expires.
    pub expires_at: i64,
    /// HMAC-SHA256 ownership token.  Store in vault SQLite `share_tokens.owner_token`
    /// and present to `revoke_b1` / `revoke_b2` to revoke the share.
    pub owner_token: String,
}

/// Returned by `get_b1`.
#[derive(Debug)]
pub struct B1GetResponse {
    /// The opaque provider URL that was registered at creation time.
    pub provider_url: String,
    /// Unix timestamp (seconds) when the share expires.
    pub expires_at: i64,
}

// ─── Client ───────────────────────────────────────────────────────────────────

/// Typed client for the BYO share-relay API.
///
/// Generic over `C: ProviderHttpClient` so the same code compiles for
/// `reqwest` (native/Android), `reqwest` wasm feature (browser), and mocks.
pub struct ShareRelayClient<C: ProviderHttpClient> {
    client: C,
    /// Base URL of the relay server, without a trailing slash.
    /// Example: `"https://byo.example.com"`
    base_url: String,
    /// Cumulative ciphertext bytes uploaded via B2 (upload bandwidth).
    pub bytes_sent: Arc<AtomicU64>,
    /// Cumulative ciphertext bytes downloaded via B1/B2 get (download bandwidth).
    pub bytes_recv: Arc<AtomicU64>,
}

impl<C: ProviderHttpClient> ShareRelayClient<C> {
    /// Create a new client.
    ///
    /// `base_url` is the relay server root, e.g. `"https://byo.example.com"`.
    pub fn new(client: C, base_url: impl Into<String>) -> Self {
        let mut base = base_url.into();
        if base.ends_with('/') {
            base.pop();
        }
        Self {
            client,
            base_url: base,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Read and atomically reset the share-relay bandwidth counters.
    ///
    /// Returns `(bytes_sent, bytes_recv)`.  Both counters are reset to 0 after
    /// the read.  Called by the WASM layer at vault-lock time to emit
    /// `relay_bandwidth_share`.
    pub fn relay_bandwidth_and_reset(&self) -> (u64, u64) {
        let sent = self.bytes_sent.swap(0, Ordering::AcqRel);
        let recv = self.bytes_recv.swap(0, Ordering::AcqRel);
        (sent, recv)
    }

    // ── B1 endpoints ──────────────────────────────────────────────────────────

    /// Create a B1 share (presigned-URL pointer).
    ///
    /// Requires a relay auth cookie (`"relay_auth=<jwt>"`) with purpose
    /// `"share:b1"`.  `expires_in_secs` is capped server-side at 30 days.
    pub async fn create_b1(
        &self,
        share_id: &str,
        provider_url: &str,
        expires_in_secs: u32,
        relay_cookie: &str,
    ) -> Result<ShareCreateResponse, SdkError> {
        validate_share_id(share_id, "share_id")?;
        validate_header_value(relay_cookie, "relay_cookie")?;
        let body = serde_json::json!({
            "share_id": share_id,
            "provider_url": provider_url,
            "expires_in_secs": expires_in_secs,
        });
        let req = ProviderHttpRequest::post(format!("{}/relay/share/b1", self.base_url))
            .header(("Cookie".into(), relay_cookie.into()))
            .header(("Content-Type".into(), "application/json".into()))
            .body(serde_json::to_vec(&body).map_err(|e| SdkError::Api(e.to_string()))?);

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            200 | 201 => {
                let v: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| SdkError::Api(format!("B1 create response parse: {e}")))?;
                Ok(ShareCreateResponse {
                    share_id: json_str(&v, "share_id")?,
                    expires_at: json_i64(&v, "expires_at")?,
                    owner_token: json_str(&v, "owner_token")?,
                })
            }
            401 | 403 => Err(SdkError::ShareRelay(ShareRelayError::Unauthorized)),
            409 => Err(SdkError::ShareRelay(ShareRelayError::Conflict)),
            429 => Err(SdkError::ShareRelay(ShareRelayError::RateLimited)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }

    /// Retrieve a B1 share by ID (unauthenticated).
    ///
    /// Returns `Err(NotFound)` for missing or expired shares.
    /// Returns `Err(Revoked)` for revoked shares.
    pub async fn get_b1(&self, share_id: &str) -> Result<B1GetResponse, SdkError> {
        validate_share_id(share_id, "share_id")?;
        let req =
            ProviderHttpRequest::get(format!("{}/relay/share/b1/{}", self.base_url, share_id));
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            200 => {
                let v: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| SdkError::Api(format!("B1 get response parse: {e}")))?;
                Ok(B1GetResponse {
                    provider_url: json_str(&v, "provider_url")?,
                    expires_at: json_i64(&v, "expires_at")?,
                })
            }
            404 => Err(SdkError::ShareRelay(ShareRelayError::NotFound)),
            410 => Err(SdkError::ShareRelay(ShareRelayError::Revoked)),
            429 => Err(SdkError::ShareRelay(ShareRelayError::RateLimited)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }

    /// Revoke a B1 share.
    ///
    /// `owner_token` is the HMAC bearer token returned by `create_b1`.
    /// No relay auth cookie is required.
    pub async fn revoke_b1(&self, share_id: &str, owner_token: &str) -> Result<(), SdkError> {
        validate_share_id(share_id, "share_id")?;
        validate_header_value(owner_token, "owner_token")?;
        let req =
            ProviderHttpRequest::delete(format!("{}/relay/share/b1/{}", self.base_url, share_id))
                .header(("X-Owner-Token".into(), owner_token.into()));
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            204 => Ok(()),
            401 | 403 => Err(SdkError::ShareRelay(ShareRelayError::Unauthorized)),
            404 => Err(SdkError::ShareRelay(ShareRelayError::NotFound)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }

    // ── B2 endpoints ──────────────────────────────────────────────────────────

    /// Upload a V7 ciphertext blob as a B2 share.
    ///
    /// Requires a relay auth cookie with purpose `"share:b2"`.
    /// `ciphertext` must be a valid V7 blob (first byte = 0x07, ≥ 1741 bytes,
    /// ≤ 200 MiB).  The server validates the V7 header marker independently.
    pub async fn upload_b2(
        &self,
        share_id: &str,
        ciphertext: Vec<u8>,
        expires_in_secs: u32,
        relay_cookie: &str,
    ) -> Result<ShareCreateResponse, SdkError> {
        validate_share_id(share_id, "share_id")?;
        validate_header_value(relay_cookie, "relay_cookie")?;
        let ciphertext_len = ciphertext.len() as u64;
        let req = ProviderHttpRequest::post(format!("{}/relay/share/b2", self.base_url))
            .header(("Cookie".into(), relay_cookie.into()))
            .header(("Content-Type".into(), "application/octet-stream".into()))
            .header(("X-Share-Id".into(), share_id.into()))
            .header(("X-Expires-In".into(), expires_in_secs.to_string()))
            .body(ciphertext);

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            200 | 201 => {
                // Count bytes only on success.
                self.bytes_sent.fetch_add(ciphertext_len, Ordering::Relaxed);
                let v: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| SdkError::Api(format!("B2 upload response parse: {e}")))?;
                Ok(ShareCreateResponse {
                    share_id: json_str(&v, "share_id")?,
                    expires_at: json_i64(&v, "expires_at")?,
                    owner_token: json_str(&v, "owner_token")?,
                })
            }
            401 | 403 => Err(SdkError::ShareRelay(ShareRelayError::Unauthorized)),
            409 => Err(SdkError::ShareRelay(ShareRelayError::Conflict)),
            413 => Err(SdkError::ShareRelay(ShareRelayError::TooLarge)),
            429 => Err(SdkError::ShareRelay(ShareRelayError::RateLimited)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }

    /// Retrieve a B2 ciphertext blob by ID (unauthenticated).
    ///
    /// Returns raw V7 ciphertext bytes.
    pub async fn get_b2(&self, share_id: &str) -> Result<Vec<u8>, SdkError> {
        validate_share_id(share_id, "share_id")?;
        let req =
            ProviderHttpRequest::get(format!("{}/relay/share/b2/{}", self.base_url, share_id));
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            200 => {
                // Count bytes only on successful download.
                self.bytes_recv
                    .fetch_add(resp.body.len() as u64, Ordering::Relaxed);
                Ok(resp.body)
            }
            404 => Err(SdkError::ShareRelay(ShareRelayError::NotFound)),
            410 => Err(SdkError::ShareRelay(ShareRelayError::Revoked)),
            429 => Err(SdkError::ShareRelay(ShareRelayError::RateLimited)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }

    /// Revoke a B2 share.
    ///
    /// `owner_token` is the HMAC bearer token returned by `upload_b2`.
    /// No relay auth cookie is required.
    pub async fn revoke_b2(&self, share_id: &str, owner_token: &str) -> Result<(), SdkError> {
        validate_share_id(share_id, "share_id")?;
        validate_header_value(owner_token, "owner_token")?;
        let req =
            ProviderHttpRequest::delete(format!("{}/relay/share/b2/{}", self.base_url, share_id))
                .header(("X-Owner-Token".into(), owner_token.into()));
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| SdkError::Api(e.to_string()))?;
        match resp.status {
            204 => Ok(()),
            401 | 403 => Err(SdkError::ShareRelay(ShareRelayError::Unauthorized)),
            404 => Err(SdkError::ShareRelay(ShareRelayError::NotFound)),
            status => Err(SdkError::ShareRelay(ShareRelayError::Unexpected(status))),
        }
    }
}

// ─── JSON extraction helpers ──────────────────────────────────────────────────

fn json_str(v: &serde_json::Value, key: &str) -> Result<String, SdkError> {
    v.get(key)
        .and_then(|f| f.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| SdkError::Api(format!("missing '{key}' field in relay response")))
}

fn json_i64(v: &serde_json::Value, key: &str) -> Result<i64, SdkError> {
    v.get(key).and_then(|f| f.as_i64()).ok_or_else(|| {
        SdkError::Api(format!(
            "missing or invalid '{key}' field in relay response"
        ))
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::api::provider_http::{ProviderHttpRequest, ProviderHttpResponse};
    use crate::byo::ProviderError;
    use std::future::Future;

    // Minimal mock client for testing status code mapping.
    struct MockClient {
        status: u16,
        body: Vec<u8>,
    }

    impl ProviderHttpClient for MockClient {
        fn request(
            &self,
            _req: ProviderHttpRequest,
        ) -> impl Future<Output = Result<ProviderHttpResponse, ProviderError>> {
            let resp = ProviderHttpResponse {
                status: self.status,
                headers: vec![],
                body: self.body.clone(),
            };
            async move { Ok(resp) }
        }
    }

    fn ok_body(share_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "share_id": share_id,
            "expires_at": 9999999999i64,
            "owner_token": "deadbeef",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn create_b1_ok() {
        let c = MockClient {
            status: 201,
            body: ok_body("test-id"),
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let resp = relay
            .create_b1(
                "test-id",
                "https://gdrive.com/file",
                86400,
                "relay_auth=jwt",
            )
            .await
            .unwrap();
        assert_eq!(resp.share_id, "test-id");
        assert_eq!(resp.owner_token, "deadbeef");
    }

    #[tokio::test]
    async fn create_b1_conflict() {
        let c = MockClient {
            status: 409,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .create_b1("x", "https://gdrive.com/file", 86400, "relay_auth=jwt")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Conflict)
        ));
    }

    #[tokio::test]
    async fn create_b1_unauthorized() {
        let c = MockClient {
            status: 401,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .create_b1("x", "url", 3600, "bad_cookie")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn get_b1_not_found() {
        let c = MockClient {
            status: 404,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay.get_b1("missing").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::NotFound)
        ));
    }

    #[tokio::test]
    async fn get_b1_revoked() {
        let c = MockClient {
            status: 410,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay.get_b1("revoked-id").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Revoked)
        ));
    }

    #[tokio::test]
    async fn get_b1_ok() {
        let body = serde_json::to_vec(&serde_json::json!({
            "provider_url": "https://gdrive.com/file",
            "expires_at": 9999999999i64,
        }))
        .unwrap();
        let c = MockClient { status: 200, body };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let b1 = relay.get_b1("test-id").await.unwrap();
        assert_eq!(b1.provider_url, "https://gdrive.com/file");
    }

    #[tokio::test]
    async fn revoke_b1_ok() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        relay.revoke_b1("test-id", "deadbeef").await.unwrap();
    }

    #[tokio::test]
    async fn upload_b2_too_large() {
        let c = MockClient {
            status: 413,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .upload_b2("x", vec![0x07u8; 200], 3600, "relay_auth=jwt")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn upload_b2_rate_limited() {
        let c = MockClient {
            status: 429,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .upload_b2("x", vec![0x07u8], 3600, "relay_auth=jwt")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn get_b2_ok() {
        let fake_v7 = vec![0x07u8; 2048];
        let c = MockClient {
            status: 200,
            body: fake_v7.clone(),
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let bytes = relay.get_b2("test-id").await.unwrap();
        assert_eq!(bytes, fake_v7);
    }

    #[tokio::test]
    async fn revoke_b2_ok() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        relay.revoke_b2("test-id", "deadbeef").await.unwrap();
    }

    #[tokio::test]
    async fn base_url_trailing_slash_stripped() {
        let c = MockClient {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "provider_url": "https://gdrive.com/file",
                "expires_at": 9999999999i64,
            }))
            .unwrap(),
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com/");
        // Should not double-slash the path.
        let b1 = relay.get_b1("test-id").await.unwrap();
        assert!(!b1.provider_url.is_empty());
    }

    // ── H3 regression: input validation ──────────────────────────────────────

    #[tokio::test]
    async fn share_id_with_path_traversal_is_rejected() {
        // H3 regression: share_id interpolated raw into URL path.
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay.get_b1("../../admin/drop").await.unwrap_err();
        assert!(
            matches!(err, SdkError::ShareRelay(ShareRelayError::Unexpected(400))),
            "path traversal share_id must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn share_id_with_crlf_is_rejected() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay.get_b1("abc\r\nX-Injected: evil").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Unexpected(400))
        ));
    }

    #[tokio::test]
    async fn owner_token_with_crlf_is_rejected() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .revoke_b1("valid-id", "tok\r\nX-Injected: evil")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Unexpected(400))
        ));
    }

    #[tokio::test]
    async fn relay_cookie_with_crlf_is_rejected() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay
            .create_b1(
                "valid-id",
                "https://example.com/file",
                3600,
                "relay_auth=x\r\nevil: hdr",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Unexpected(400))
        ));
    }

    #[tokio::test]
    async fn empty_share_id_is_rejected() {
        let c = MockClient {
            status: 204,
            body: vec![],
        };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        let err = relay.get_b1("").await.unwrap_err();
        assert!(matches!(
            err,
            SdkError::ShareRelay(ShareRelayError::Unexpected(400))
        ));
    }

    #[tokio::test]
    async fn valid_uuid_share_id_passes_validation() {
        let body = serde_json::to_vec(&serde_json::json!({
            "provider_url": "https://example.com/file",
            "expires_at": 9999999999i64,
        }))
        .unwrap();
        let c = MockClient { status: 200, body };
        let relay = ShareRelayClient::new(c, "https://relay.example.com");
        // UUID format with hyphens — must pass
        let result = relay.get_b1("550e8400-e29b-41d4-a716-446655440000").await;
        assert!(result.is_ok(), "UUID share_id must be accepted: {result:?}");
    }
}
