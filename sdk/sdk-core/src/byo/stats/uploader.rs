// StatsUploader — POSTs a batch of StatsEvents to POST /relay/stats.
//
// Gated on the `providers` feature because it requires ProviderHttpClient
// (which in turn gates its own module).  The recorder + events + error types
// are always compiled so Android-future can use them without HTTP.

use crate::api::provider_http::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::stats::error::StatsError;
use crate::byo::stats::events::StatsEvent;

// ─── Input validation ─────────────────────────────────────────────────────────

/// Validate that `device_id` matches the lowercase UUIDv4 format.
/// Pattern: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (36 chars, hex + hyphens).
fn validate_device_id(id: &str) -> Result<(), StatsError> {
    if id.len() != 36 {
        return Err(StatsError::InvalidDeviceId);
    }
    let bytes = id.as_bytes();
    let hyphen_positions = [8usize, 13, 18, 23];
    for (i, &b) in bytes.iter().enumerate() {
        if hyphen_positions.contains(&i) {
            if b != b'-' {
                return Err(StatsError::InvalidDeviceId);
            }
        } else if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            // Lowercase only — UUIDv4 canonical form. Reject uppercase.
            return Err(StatsError::InvalidDeviceId);
        }
    }
    Ok(())
}

/// Reject CR/LF in a header value to prevent HTTP header-injection.
fn validate_header_value(value: &str) -> Result<(), StatsError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(StatsError::Encoding);
    }
    Ok(())
}

// ─── StatsUploader ────────────────────────────────────────────────────────────

/// Async client that POSTs a batch of events to `POST /relay/stats`.
///
/// Generic over `C: ProviderHttpClient` — the same concrete type used by all
/// BYO storage providers.  The WASM layer supplies `ReqwestProviderHttpClient`;
/// Android will supply its own `reqwest` implementation.
///
/// The relay auth cookie (`relay_auth=<jwt>`) must be acquired by the host
/// (via `acquireRelayCookie("stats")`) before calling `flush_batch`.  For
/// same-origin browser requests the browser attaches HttpOnly cookies
/// automatically; pass `""` for `relay_cookie` in that case.
pub struct StatsUploader<C: ProviderHttpClient> {
    client: C,
    /// Base URL of the relay server without trailing slash.
    base_url: String,
}

impl<C: ProviderHttpClient> StatsUploader<C> {
    /// Create a new uploader.
    ///
    /// `base_url` is the relay root, e.g. `"https://byo.example.com"`.
    pub fn new(client: C, base_url: impl Into<String>) -> Self {
        let mut base = base_url.into();
        if base.ends_with('/') {
            base.pop();
        }
        Self {
            client,
            base_url: base,
        }
    }

    /// POST a batch of events.
    ///
    /// - `device_id`: lowercase UUIDv4 (36 chars), never rotated.
    /// - `events`: batch to POST (caller must respect ≤200 limit).
    /// - `relay_cookie`: full `Cookie` header value (e.g. `"relay_auth=<jwt>"`).
    ///   Pass `""` for same-origin browser requests where the browser attaches
    ///   the HttpOnly cookie automatically.
    ///
    /// Returns `Ok(())` on 204.  Stats failures are intentionally NOT propagated
    /// into `SdkError` — the caller should log and discard any error.
    pub fn flush_batch(
        &self,
        device_id: &str,
        events: Vec<StatsEvent>,
        relay_cookie: &str,
    ) -> impl std::future::Future<Output = Result<(), StatsError>> + '_ {
        let device_id = device_id.to_owned();
        let relay_cookie = relay_cookie.to_owned();
        async move {
            validate_device_id(&device_id)?;
            if !relay_cookie.is_empty() {
                validate_header_value(&relay_cookie)?;
            }
            if events.is_empty() {
                return Ok(());
            }
            let payload = serde_json::json!({
                "device_id": device_id,
                "events": events,
            });
            let body = serde_json::to_vec(&payload).map_err(|_| StatsError::Encoding)?;
            let mut req = ProviderHttpRequest::post(format!("{}/relay/stats", self.base_url))
                .header(("Content-Type".into(), "application/json".into()))
                .body(body);
            if !relay_cookie.is_empty() {
                req = req.header(("Cookie".into(), relay_cookie));
            }
            let resp = self
                .client
                .request(req)
                .await
                .map_err(|_| StatsError::Network)?;
            match resp.status {
                204 => Ok(()),
                401 | 403 => Err(StatsError::Unauthorized),
                413 => Err(StatsError::TooLarge),
                429 => Err(StatsError::RateLimited),
                s => Err(StatsError::Unexpected(s)),
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::api::provider_http::{ProviderHttpRequest, ProviderHttpResponse};
    use crate::byo::provider::ProviderError;
    use std::future::Future;

    struct MockClient(u16);
    impl ProviderHttpClient for MockClient {
        fn request(
            &self,
            _req: ProviderHttpRequest,
        ) -> impl Future<Output = Result<ProviderHttpResponse, ProviderError>> {
            let status = self.0;
            async move {
                Ok(ProviderHttpResponse {
                    status,
                    headers: vec![],
                    body: vec![],
                })
            }
        }
    }

    fn one_event() -> Vec<StatsEvent> {
        vec![StatsEvent::VaultUnlock { ts: 1 }]
    }

    #[tokio::test]
    async fn flush_204_ok() {
        let up = StatsUploader::new(MockClient(204), "https://relay.example.com");
        up.flush_batch("5f3b1234-1234-1234-1234-1234567890ab", one_event(), "")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn flush_401_unauthorized() {
        let up = StatsUploader::new(MockClient(401), "https://relay.example.com");
        let err = up
            .flush_batch(
                "5f3b1234-1234-1234-1234-1234567890ab",
                one_event(),
                "relay_auth=x",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StatsError::Unauthorized));
    }

    #[tokio::test]
    async fn flush_413_too_large() {
        let up = StatsUploader::new(MockClient(413), "https://relay.example.com");
        let err = up
            .flush_batch("5f3b1234-1234-1234-1234-1234567890ab", one_event(), "")
            .await
            .unwrap_err();
        assert!(matches!(err, StatsError::TooLarge));
    }

    #[tokio::test]
    async fn flush_429_rate_limited() {
        let up = StatsUploader::new(MockClient(429), "https://relay.example.com");
        let err = up
            .flush_batch("5f3b1234-1234-1234-1234-1234567890ab", one_event(), "")
            .await
            .unwrap_err();
        assert!(matches!(err, StatsError::RateLimited));
    }

    #[tokio::test]
    async fn flush_500_unexpected() {
        let up = StatsUploader::new(MockClient(500), "https://relay.example.com");
        let err = up
            .flush_batch("5f3b1234-1234-1234-1234-1234567890ab", one_event(), "")
            .await
            .unwrap_err();
        assert!(matches!(err, StatsError::Unexpected(500)));
    }

    #[tokio::test]
    async fn empty_events_skip_request() {
        // MockClient with 500 — would fail if a request were actually made.
        let up = StatsUploader::new(MockClient(500), "https://relay.example.com");
        // Should return Ok without hitting the network.
        up.flush_batch("5f3b1234-1234-1234-1234-1234567890ab", vec![], "")
            .await
            .unwrap();
    }

    #[test]
    fn validate_device_id_good() {
        assert!(validate_device_id("5f3b1234-1234-4321-a123-1234567890ab").is_ok());
        assert!(validate_device_id("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn validate_device_id_bad() {
        assert!(validate_device_id("").is_err());
        assert!(validate_device_id("not-a-uuid").is_err());
        // Wrong length
        assert!(validate_device_id("5f3b1234-1234-1234-1234-1234567890abc").is_err());
        // Uppercase not allowed (lowercase UUIDv4 only)
        assert!(validate_device_id("5F3B1234-1234-1234-1234-1234567890AB").is_err());
    }

    #[test]
    fn validate_header_crlf_rejected() {
        assert!(validate_header_value("relay_auth=x\r\nevil: hdr").is_err());
        assert!(validate_header_value("relay_auth=x\nevil").is_err());
        assert!(validate_header_value("relay_auth=valid_jwt").is_ok());
    }
}
