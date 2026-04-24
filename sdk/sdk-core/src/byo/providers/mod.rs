// BYO storage provider implementations.
//
// Each provider is generic over `H: ProviderHttpClient` so the same struct
// compiles for both WASM (reqwest wasm feature) and native/Android (reqwest).
//
// Design constraints from CLAUDE.md:
//   - No panics: use map_err/ok_or instead of unwrap/expect
//   - No base64 in sdk-core logic: base64 is only used at the WebDAV boundary
//     for Basic auth header construction (not for V7 data)
//   - std::sync::Mutex is safe as long as the lock is NOT held across await points
//   - Tokens are NOT auto-refreshed: all methods return ProviderError::Unauthorized
//     when a token is expired. Callers use byo_gdrive_refresh_token / etc.

#[cfg(feature = "providers")]
pub mod box_storage;
#[cfg(feature = "providers")]
pub mod dropbox;
#[cfg(feature = "providers")]
pub mod gdrive;
#[cfg(feature = "providers")]
pub mod onedrive;
#[cfg(feature = "providers")]
pub mod pcloud;
#[cfg(feature = "providers")]
pub mod s3;
#[cfg(feature = "providers")]
pub mod url_guard;
#[cfg(feature = "providers")]
pub mod webdav;

#[cfg(feature = "providers")]
pub use box_storage::BoxProvider;
#[cfg(feature = "providers")]
pub use dropbox::DropboxProvider;
#[cfg(feature = "providers")]
pub use gdrive::GdriveProvider;
#[cfg(feature = "providers")]
pub use onedrive::OneDriveProvider;
#[cfg(feature = "providers")]
pub use pcloud::PCloudProvider;
#[cfg(feature = "providers")]
pub use s3::S3Provider;
#[cfg(feature = "providers")]
pub use webdav::WebDAVProvider;

// ─── Shared helpers ───────────────────────────────────────────────────────────

use crate::api::provider_http::{ProviderHttpClient, ProviderHttpRequest, ProviderHttpResponse};
use crate::byo::ProviderError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Return the current Unix timestamp in milliseconds.
pub(crate) fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Generate a unique stream ID for the current process session.
pub(crate) fn new_stream_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!("s{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Map an HTTP status code to a `ProviderError`. Returns `None` for 2xx.
/// `body` is included in error messages for diagnostics (never contains key material).
///
/// The generic 409/412 conflict parser only looks for top-level `etag`/`eTag` and is
/// therefore only correct for GDrive / OneDrive / WebDAV. Dropbox (409 on update-mode
/// conflicts) and Box (409 with nested `context_info.conflicts.etag`) must extract
/// the current version with their own per-provider logic and return
/// `ProviderError::Conflict { current_version }` directly, before delegating to this
/// helper. See `map_http_status_with_conflict` for an explicit-version variant.
pub(crate) fn map_http_status(status: u16, body: &[u8]) -> Option<ProviderError> {
    match status {
        200..=299 => None,
        // 3xx redirects are never followed automatically: we sign every request
        // with provider-specific auth + payload hash, and the new target would
        // need re-signing (AWS 301/307 point at a different region; WebDAV
        // proxies may redirect to an HTTP URL that would downgrade Basic auth).
        // Surface a clear hint so the user can correct `s3_region` / `server_url`.
        301 | 302 | 307 | 308 => Some(ProviderError::Provider(format!(
            "HTTP {status} redirect — bucket may be in a different region, or the \
             configured endpoint/server URL is wrong (check s3_region / s3_endpoint / server_url)"
        ))),
        401 => Some(ProviderError::Unauthorized),
        403 => Some(ProviderError::Forbidden),
        404 | 410 => Some(ProviderError::NotFound),
        408 | 429 => Some(ProviderError::RateLimited),
        409 | 412 => {
            let version = extract_etag_like(body).unwrap_or_default();
            Some(ProviderError::Conflict {
                current_version: version,
            })
        }
        _ => {
            let msg = String::from_utf8_lossy(body)
                .chars()
                .take(200)
                .collect::<String>();
            Some(ProviderError::Provider(format!("HTTP {status}: {msg}")))
        }
    }
}

/// Same as `map_http_status`, but the caller supplies the `current_version` to use on
/// 409/412 responses. Used by providers (Dropbox, Box) whose conflict bodies put the
/// version somewhere `extract_etag_like` can't find it.
pub(crate) fn map_http_status_with_conflict_version(
    status: u16,
    body: &[u8],
    current_version: String,
) -> Option<ProviderError> {
    match status {
        200..=299 => None,
        301 | 302 | 307 | 308 => Some(ProviderError::Provider(format!(
            "HTTP {status} redirect — bucket may be in a different region, or the \
             configured endpoint/server URL is wrong (check s3_region / s3_endpoint / server_url)"
        ))),
        401 => Some(ProviderError::Unauthorized),
        403 => Some(ProviderError::Forbidden),
        404 | 410 => Some(ProviderError::NotFound),
        408 | 429 => Some(ProviderError::RateLimited),
        409 | 412 => Some(ProviderError::Conflict { current_version }),
        _ => {
            let msg = String::from_utf8_lossy(body)
                .chars()
                .take(200)
                .collect::<String>();
            Some(ProviderError::Provider(format!("HTTP {status}: {msg}")))
        }
    }
}

/// Best-effort extraction of a top-level `etag`/`eTag` string — useful for GDrive /
/// OneDrive / WebDAV conflict responses. Returns `None` if the body is not JSON or
/// the field isn't present.
pub(crate) fn extract_etag_like(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("etag")
                .or_else(|| v.get("eTag"))
                .and_then(|e| e.as_str())
                .map(|s| s.to_string())
        })
}

/// Dropbox-specific conflict parser: Dropbox 409 bodies look like
/// `{"error_summary": "...", "error": {".tag": "path", "path": {".tag": "conflict",
/// "conflict": {".tag": "file"}}}}` — there is no `etag` at any level, but the
/// `path/write-conflict` style errors carry enough to build a path/rev reference.
/// We return the `error_summary` as the "current version" identifier so the caller
/// can at least surface a meaningful message; an empty string falls back on plain
/// `HTTP 409` semantics.
pub(crate) fn extract_dropbox_conflict_rev(body: &[u8]) -> Option<String> {
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    // Dropbox returns the latest server `rev` in upload_session/finish conflicts
    // as `error.conflict.rev` when update mode is `{".tag": "update", "update":
    // "<rev>"}` and the target moved underneath the client.
    if let Some(rev) = v
        .get("error")
        .and_then(|e| e.get("conflict"))
        .and_then(|c| c.get("rev"))
        .and_then(|r| r.as_str())
    {
        return Some(rev.to_string());
    }
    // Fall back to error_summary (human-readable; better than empty).
    v.get("error_summary")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/// Box-specific conflict parser: Box 409 responses nest the conflict etag at
/// `context_info.conflicts[0].etag` (for uploads against an existing file name
/// in the same folder) or `context_info.conflicts.etag`. (Not yet wired up —
/// `box_storage` inlines equivalent logic; kept here for uniformity and so the
/// streaming commit path can switch over later.)
#[allow(dead_code)]
pub(crate) fn extract_box_conflict_etag(body: &[u8]) -> Option<String> {
    let v = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let ci = v.get("context_info")?;
    let conflicts = ci.get("conflicts")?;
    // Sometimes an array, sometimes an object — probe both shapes.
    if let Some(arr) = conflicts.as_array() {
        return arr
            .first()
            .and_then(|c| c.get("etag"))
            .and_then(|e| e.as_str())
            .map(|s| s.to_string());
    }
    conflicts
        .get("etag")
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
}

/// Parse response body as a JSON value. Returns `ProviderError::InvalidResponse` on failure.
pub(crate) fn parse_json(body: &[u8]) -> Result<serde_json::Value, ProviderError> {
    serde_json::from_slice(body).map_err(|_| ProviderError::InvalidResponse)
}

/// Extract a string field from a JSON value.
pub(crate) fn json_str<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, ProviderError> {
    v.get(key)
        .and_then(|f| f.as_str())
        .ok_or(ProviderError::InvalidResponse)
}

/// Construct a Bearer authorization header tuple.
pub(crate) fn bearer(token: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {token}"))
}

/// Strip RFC 7232 weak prefix `W/` and surrounding quotes from a server-supplied ETag.
/// Returns the opaque token, suitable for storing as `UploadResult::version`.
///
/// Nextcloud and other DAV servers return weak ETags like `W/"abc123"`. A naive
/// `trim_matches('"')` leaves `W/"abc123` (only the trailing quote is removed),
/// and any `If-Match` built from that string is rejected by every server.
pub(crate) fn normalize_etag(raw: &str) -> String {
    let t = raw.trim();
    let t = t.strip_prefix("W/").or_else(|| t.strip_prefix("w/")).unwrap_or(t);
    t.trim_matches('"').to_string()
}

/// Format a stored opaque ETag token as a strongly-quoted `If-Match` value
/// per RFC 7232. Idempotent: also accepts values that still carry `W/` / quotes.
pub(crate) fn fmt_if_match(token: &str) -> String {
    format!("\"{}\"", normalize_etag(token))
}

/// Chunk size for Range-based streaming downloads (8 MiB).
pub(crate) const RANGE_CHUNK_SIZE: u64 = 8 * 1024 * 1024;

/// Closure type for computing per-chunk request headers.
///
/// Called with `(offset_inclusive, end_inclusive)`. Returns all headers
/// for the request: auth + `Range: bytes=offset-end`.
pub(crate) type MakeHeaders = Arc<dyn Fn(u64, u64) -> Vec<(String, String)> + Send + Sync>;

/// Boxed async HTTP call. The closure itself is `Send + Sync` because it only
/// captures `Arc<H>`. The inner future's `Send`-ness is target-dependent and
/// mirrors `ProviderHttpClient::request`: native needs `Send` to satisfy the
/// UniFFI tokio runtime; wasm cannot offer `Send` because `reqwest`'s wasm
/// futures wrap JS promises.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type HttpCallFn = Arc<
    dyn Fn(
            ProviderHttpRequest,
        )
            -> Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send>>
        + Send
        + Sync,
>;

#[cfg(target_arch = "wasm32")]
pub(crate) type HttpCallFn = Arc<
    dyn Fn(
            ProviderHttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, ProviderError>>>>
        + Send
        + Sync,
>;

/// Wrap a concrete `ProviderHttpClient` in an `HttpCallFn` for `RangedDownloadBuffer`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn make_http_call_fn<H: ProviderHttpClient + 'static>(http: Arc<H>) -> HttpCallFn {
    Arc::new(move |req: ProviderHttpRequest| {
        let http = Arc::clone(&http);
        Box::pin(async move { http.request(req).await })
            as Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send>>
    })
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn make_http_call_fn<H: ProviderHttpClient + 'static>(http: Arc<H>) -> HttpCallFn {
    Arc::new(move |req: ProviderHttpRequest| {
        let http = Arc::clone(&http);
        Box::pin(async move { http.request(req).await })
            as Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, ProviderError>>>>
    })
}

/// Range-based streaming download buffer.
///
/// Issues one HTTP `Range` request per chunk rather than buffering the
/// full file. All 7 HTTP providers support RFC 7233 range requests.
///
/// # Lock discipline
///
/// `download_stream_read` MUST NOT hold the state `Mutex` across the HTTP
/// `.await`. The canonical pattern:
/// 1. Lock → extract `(request, http_call)` → drop lock.
/// 2. `http_call(request).await` — no lock held.
/// 3. Lock → `apply_response(...)` → drop lock.
pub(crate) struct RangedDownloadBuffer {
    pub url: String,
    /// `"GET"` for all providers except Dropbox (`"POST"`).
    pub method: &'static str,
    /// Fixed request body for POST-based providers (Dropbox).
    pub fixed_body: Option<Vec<u8>>,
    pub make_headers: MakeHeaders,
    pub http_call: HttpCallFn,
    /// Next byte to fetch.
    pub offset: u64,
    /// Total file size. `0` = unknown (discovered from `Content-Range`).
    pub total_size: u64,
    pub chunk_size: u64,
    /// Explicit EOF flag. Set by `apply_response` on 200, 416, 206 short-read,
    /// or 206 empty-body — any of which means there is no more data to fetch.
    /// Needed in addition to `offset >= total_size` because a server may
    /// signal EOF via an empty 206 before `total_size` is ever populated
    /// (RFC 7233 allows omitting Content-Range when total size is unknown).
    done: bool,
}

impl RangedDownloadBuffer {
    pub fn new(
        url: String,
        method: &'static str,
        fixed_body: Option<Vec<u8>>,
        make_headers: MakeHeaders,
        http_call: HttpCallFn,
    ) -> Self {
        Self {
            url,
            method,
            fixed_body,
            make_headers,
            http_call,
            offset: 0,
            total_size: 0,
            chunk_size: RANGE_CHUNK_SIZE,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done || (self.total_size > 0 && self.offset >= self.total_size)
    }

    /// Build the next Range request. Returns `None` when exhausted.
    ///
    /// Returns `(request, requested_size)` where `requested_size` is the number
    /// of bytes the Range header asks for. Callers pass this to
    /// `apply_response` so it can detect implicit EOF (see that method's docs).
    pub fn next_request(&self) -> Option<(ProviderHttpRequest, u64)> {
        if self.is_done() {
            return None;
        }
        let end = if self.total_size > 0 {
            (self.offset + self.chunk_size - 1).min(self.total_size - 1)
        } else {
            self.offset + self.chunk_size - 1
        };
        let requested_size = end - self.offset + 1;
        let req = ProviderHttpRequest {
            method: self.method.to_string(),
            url: self.url.clone(),
            headers: (self.make_headers)(self.offset, end),
            body: self.fixed_body.clone(),
        };
        Some((req, requested_size))
    }

    /// Apply an HTTP response: advance `offset`, update `total_size`, return data.
    ///
    /// `requested_size` is the byte count the caller asked for in the Range header
    /// (`end - offset + 1`). Used to detect implicit EOF when a 206 response is
    /// shorter than requested and `total_size` was never populated from a
    /// `Content-Range` header (RFC 7233 §4.1 allows omitting Content-Range when
    /// total size is unknown; a short read is the only reliable EOF signal then).
    pub fn apply_response(
        &mut self,
        status: u16,
        body: Vec<u8>,
        content_range: Option<&str>,
        requested_size: u64,
    ) -> Result<Option<Vec<u8>>, ProviderError> {
        match status {
            206 => {
                if self.total_size == 0 {
                    if let Some(cr) = content_range {
                        self.total_size = parse_content_range_total(cr).unwrap_or(0);
                    }
                }
                let received = body.len() as u64;
                self.offset += received;
                // Implicit EOF detection, only when total_size is still unknown:
                // a server that omits Content-Range signals EOF by returning
                // fewer bytes than requested (or an empty body). Prevents an
                // infinite read loop against servers that never include
                // Content-Range. When total_size IS known (either from an
                // earlier Content-Range or a 200 fallback), completion is
                // tracked via `offset >= total_size` and we must not mis-flag
                // mid-file short reads as EOF.
                if self.total_size == 0 && received < requested_size {
                    self.done = true;
                }
                if body.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(body))
                }
            }
            200 => {
                // Server ignored Range — full content returned (single chunk).
                self.total_size = body.len() as u64;
                self.offset = self.total_size;
                self.done = true;
                if body.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(body))
                }
            }
            416 => {
                self.done = true;
                Ok(None)
            }
            _ => Err(map_http_status(status, &body).unwrap_or_else(|| {
                ProviderError::Provider(format!("range request failed: HTTP {status}"))
            })),
        }
    }
}

fn parse_content_range_total(cr: &str) -> Option<u64> {
    // "bytes 0-8388607/93547009" → 93547009
    cr.split('/').nth(1)?.trim().parse().ok()
}

/// Build a `MakeHeaders` closure for Bearer-token providers (GET).
pub(crate) fn bearer_range_headers(token: String) -> MakeHeaders {
    Arc::new(move |offset: u64, end: u64| {
        vec![
            bearer(&token),
            // B11: RFC 7233 canonical form is `Range` (title case). HTTP/2+ lowercases
            // every header, so this is cosmetic on modern transports; some
            // HTTP/1.1 intermediaries still ignore lowercase `range` and return
            // 200 with the full body, defeating streaming.
            ("Range".to_string(), format!("bytes={offset}-{end}")),
        ]
    })
}

// ─── Tests for RangedDownloadBuffer ───────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dummy_http_call() -> HttpCallFn {
        Arc::new(|_req: ProviderHttpRequest| {
            Box::pin(async { Err(ProviderError::Provider("no-op mock http".to_string())) })
        })
    }

    fn dummy_make_headers() -> MakeHeaders {
        Arc::new(|_, _| vec![])
    }

    #[test]
    fn normalize_etag_strips_weak_prefix_and_quotes() {
        // Strong ETag with quotes — classic case.
        assert_eq!(normalize_etag("\"abc123\""), "abc123");
        // Weak ETag as served by Nextcloud.
        assert_eq!(normalize_etag("W/\"abc123\""), "abc123");
        // Lowercase `w/` — not spec, but some servers emit it.
        assert_eq!(normalize_etag("w/\"abc123\""), "abc123");
        // No prefix, no quotes — already bare.
        assert_eq!(normalize_etag("abc123"), "abc123");
        // Whitespace around header value.
        assert_eq!(normalize_etag("  W/\"abc123\"  "), "abc123");
        // Multipart-style hyphenated ETag survives unchanged.
        assert_eq!(
            normalize_etag("\"d41d8cd98f00b204e9800998ecf8427e-3\""),
            "d41d8cd98f00b204e9800998ecf8427e-3"
        );
    }

    #[test]
    fn map_http_status_3xx_surfaces_redirect_hint() {
        for code in [301, 302, 307, 308] {
            let err = map_http_status(code, b"")
                .unwrap_or_else(|| panic!("{code} should not map to Ok"));
            let msg = err.to_string();
            assert!(msg.contains(&code.to_string()), "{code}: {msg}");
            assert!(msg.contains("redirect"), "{code}: {msg}");
        }
    }

    #[test]
    fn fmt_if_match_always_quotes_bare_token() {
        assert_eq!(fmt_if_match("abc"), "\"abc\"");
        // Idempotent: accepts values that still carry W/ or quotes.
        assert_eq!(fmt_if_match("W/\"abc\""), "\"abc\"");
        assert_eq!(fmt_if_match("\"abc\""), "\"abc\"");
    }

    #[test]
    fn parse_content_range_total_standard_form() {
        assert_eq!(
            parse_content_range_total("bytes 0-8388607/93547009"),
            Some(93547009)
        );
    }

    #[test]
    fn parse_content_range_total_small_range() {
        assert_eq!(parse_content_range_total("bytes 0-0/42"), Some(42));
    }

    #[test]
    fn parse_content_range_total_rejects_unknown_size() {
        // "bytes 0-999/*" is a valid form but we can't infer total — returns None
        assert_eq!(parse_content_range_total("bytes 0-999/*"), None);
    }

    #[test]
    fn parse_content_range_total_rejects_malformed() {
        assert_eq!(parse_content_range_total("garbage"), None);
        assert_eq!(parse_content_range_total(""), None);
    }

    #[test]
    fn apply_response_206_updates_total_from_content_range() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        let body = vec![0xAA; 100];
        let result = buf
            .apply_response(206, body.clone(), Some("bytes 0-99/5000"), 100)
            .unwrap();
        assert_eq!(result, Some(body));
        assert_eq!(buf.offset, 100);
        assert_eq!(buf.total_size, 5000);
        assert!(!buf.is_done());
    }

    #[test]
    fn apply_response_206_second_chunk_preserves_total() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        buf.apply_response(206, vec![0; 100], Some("bytes 0-99/300"), 100)
            .unwrap();
        // Second chunk: server may or may not include Content-Range; total_size should stay.
        buf.apply_response(206, vec![1; 100], None, 100).unwrap();
        assert_eq!(buf.offset, 200);
        assert_eq!(buf.total_size, 300);
        assert!(!buf.is_done());
    }

    #[test]
    fn apply_response_final_chunk_marks_done() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        buf.apply_response(206, vec![0; 100], Some("bytes 0-99/300"), 100)
            .unwrap();
        buf.apply_response(206, vec![1; 100], None, 100).unwrap();
        buf.apply_response(206, vec![2; 100], None, 100).unwrap();
        assert_eq!(buf.offset, 300);
        assert_eq!(buf.total_size, 300);
        assert!(buf.is_done());
        assert!(buf.next_request().is_none());
    }

    #[test]
    fn apply_response_200_treats_as_full_body() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        let body = vec![0xAA; 500];
        let result = buf.apply_response(200, body.clone(), None, 500).unwrap();
        assert_eq!(result, Some(body));
        assert_eq!(buf.offset, 500);
        assert_eq!(buf.total_size, 500);
        assert!(buf.is_done());
    }

    #[test]
    fn apply_response_416_returns_none() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        let result = buf.apply_response(416, vec![], None, 100).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn apply_response_error_status_propagates() {
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        let result = buf.apply_response(404, b"not found".to_vec(), None, 100);
        assert!(matches!(result, Err(ProviderError::NotFound)));
    }

    #[test]
    fn apply_response_206_short_read_without_content_range_marks_done() {
        // Regression: when a server returns 206 without Content-Range AND the
        // body is shorter than requested, treat this as implicit EOF.
        // Without this, `is_done()` stays false forever → infinite loop.
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        // Asked for 8 MiB, server returned 4 MiB with no Content-Range.
        buf.apply_response(206, vec![0; 4_000_000], None, 8_000_000)
            .unwrap();
        assert_eq!(buf.offset, 4_000_000);
        assert!(
            buf.is_done(),
            "short-read without Content-Range should mark done"
        );
        assert!(buf.next_request().is_none());
    }

    #[test]
    fn apply_response_206_empty_body_without_content_range_returns_eof() {
        // Server sends an empty 206 with no Content-Range at EOF (e.g. when
        // Range exactly hit the last byte).
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            dummy_make_headers(),
            dummy_http_call(),
        );
        let result = buf.apply_response(206, vec![], None, 8_000_000).unwrap();
        assert!(result.is_none());
        assert!(buf.is_done());
    }

    #[test]
    fn next_request_builds_correct_range_header() {
        let headers: MakeHeaders =
            Arc::new(|offset, end| vec![("range".to_string(), format!("bytes={offset}-{end}"))]);
        let buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            headers,
            dummy_http_call(),
        );
        let (req, requested) = buf.next_request().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://x");
        assert_eq!(
            req.headers[0],
            (
                "range".to_string(),
                format!("bytes=0-{}", RANGE_CHUNK_SIZE - 1)
            )
        );
        assert_eq!(requested, RANGE_CHUNK_SIZE);
    }

    #[test]
    fn next_request_caps_end_at_total_size_minus_one() {
        let headers: MakeHeaders =
            Arc::new(|offset, end| vec![("range".to_string(), format!("bytes={offset}-{end}"))]);
        let mut buf = RangedDownloadBuffer::new(
            "http://x".to_string(),
            "GET",
            None,
            headers,
            dummy_http_call(),
        );
        // First chunk reveals total_size = 300
        buf.apply_response(206, vec![0; 100], Some("bytes 0-99/300"), 100)
            .unwrap();
        // Second chunk request: offset=100, expected end=299 (capped at total-1)
        let (req, requested) = buf.next_request().unwrap();
        assert_eq!(
            req.headers[0],
            ("range".to_string(), "bytes=100-299".to_string())
        );
        assert_eq!(requested, 200);
    }

    #[test]
    fn bearer_range_headers_includes_auth_and_range() {
        let h = bearer_range_headers("tok123".to_string());
        let headers = h(0, 99);
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer tok123"));
        assert!(headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("range") && v == "bytes=0-99"));
    }
}
