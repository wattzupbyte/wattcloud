// OneDriveProvider — BYO storage backend for Microsoft OneDrive (Graph API).
//
// Design notes:
//   - Resumable upload: POST /createUploadSession → uploadUrl →
//     PUT chunks with Content-Range → 202 (continue) or 200/201 (done).
//   - download_stream_* buffers the full response.
//   - Tokens are NOT auto-refreshed: return ProviderError::Unauthorized.
//   - Mutex is never held across .await points.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::oauth::{build_refresh_form, parse_token_response};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    bearer, bearer_range_headers, current_time_ms, make_http_call_fn, map_http_status,
    new_stream_id, parse_json, RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0/me/drive";
const TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

// ─── State ────────────────────────────────────────────────────────────────────

/// OneDrive resumable-upload chunk size: 10 MiB.
///
/// Microsoft Graph requires each non-final byte range to be a multiple of
/// 320 KiB. 10 MiB = 32 × 320 KiB and is MS's recommended default — large
/// enough to amortize HTTP overhead, small enough to keep peak WASM heap
/// bounded to one chunk (not the full file).
const OD_CHUNK_SIZE: usize = 10 * 1024 * 1024;

/// Alignment unit required by Graph for non-final chunk ranges (320 KiB).
const OD_CHUNK_ALIGNMENT: usize = 320 * 1024;

struct UploadSession {
    upload_url: String,
    total_size: u64,
    /// Ciphertext bytes not yet flushed to the upload URL. Held below
    /// `OD_CHUNK_SIZE`, so peak heap per upload is ≤ one chunk.
    buffer: Vec<u8>,
    /// Bytes already acknowledged by the server (next range start).
    offset: u64,
    /// Response metadata captured once the server returns 200/201 on the
    /// final chunk. Consumed by `upload_stream_close`.
    completed: Option<UploadResult>,
}

struct OneDriveState {
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_expiry: Option<i64>,
    client_id: Option<String>,
    root_folder_id: Option<String>,
    upload_sessions: HashMap<String, UploadSession>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

// ─── Provider ─────────────────────────────────────────────────────────────────

pub struct OneDriveProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<OneDriveState>>,
}

impl<H: ProviderHttpClient> OneDriveProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(OneDriveState {
                access_token: None,
                refresh_token: None,
                token_expiry: None,
                client_id: None,
                root_folder_id: None,
                upload_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build the Graph API path for a file under SecureCloud/.
fn od_file_path(name: &str, parent_ref: Option<&str>) -> String {
    match parent_ref {
        Some(p) if !p.is_empty() => format!("{}/{}", p.trim_end_matches('/'), name),
        _ => format!("/SecureCloud/{}", name),
    }
}

/// Percent-encode a Graph path segment so spaces and other reserved characters
/// don't break the `/root:{path}:/action` URL format. Slashes are preserved so
/// the path structure is kept intact. (B10)
fn encode_od_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            // Unreserved per RFC 3986 §2.3 + path separator.
            '/' | 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => out.push(ch),
            _ => {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

/// Compile-time guarantee: the chunk size is aligned to Graph's 320 KiB
/// requirement. `const _` forces the assertion to fire at compile time.
const _: () = assert!(OD_CHUNK_SIZE.is_multiple_of(OD_CHUNK_ALIGNMENT));

/// PUT one byte range to a OneDrive resumable-upload URL.
///
/// `range_start` is the byte offset of `payload[0]` inside the full file;
/// `total` is the declared file size. Returns the raw response body so the
/// final chunk's JSON metadata can be parsed by the caller.
async fn od_put_range<H: ProviderHttpClient>(
    http: &H,
    upload_url: &str,
    range_start: u64,
    total: u64,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ProviderError> {
    let payload_len = payload.len() as u64;
    if payload_len == 0 {
        return Err(ProviderError::Provider(
            "od_put_range: empty payload".into(),
        ));
    }
    let range_end = range_start + payload_len - 1;
    let content_range = format!("bytes {range_start}-{range_end}/{total}");
    let req = ProviderHttpRequest::put(upload_url.to_string())
        .header(("Content-Range".to_string(), content_range))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(payload);
    let resp = http.request(req).await?;
    // 202 = more expected; 200/201 = completed with metadata body.
    if resp.status == 202 || resp.status == 200 || resp.status == 201 {
        return Ok(resp.body);
    }
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    Err(ProviderError::InvalidResponse)
}

/// GET the Graph API item by path.
async fn od_get_item<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    item_path: &str,
) -> Result<serde_json::Value, ProviderError> {
    let url = format!("{}/root:{}", GRAPH_BASE, encode_od_path(item_path));
    let req = ProviderHttpRequest::get(url).header(bearer(token));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    parse_json(&resp.body)
}

/// GET the Graph API by item ID.
async fn od_get_item_by_id<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    item_id: &str,
) -> Result<serde_json::Value, ProviderError> {
    let url = format!("{}/items/{}", GRAPH_BASE, item_id);
    let req = ProviderHttpRequest::get(url).header(bearer(token));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    parse_json(&resp.body)
}

/// Ensure the /SecureCloud folder exists. Returns its item ID.
#[allow(dead_code)]
async fn od_ensure_root<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    state: &Arc<Mutex<OneDriveState>>,
) -> Result<String, ProviderError> {
    // Check state cache first (no lock across await)
    {
        let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
        if let Some(id) = &s.root_folder_id {
            return Ok(id.clone());
        }
    }
    // Try to GET; if not found, PATCH to create
    let result = od_get_item(http, token, "/SecureCloud").await;
    let folder_id = match result {
        Ok(meta) => meta
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(ProviderError::InvalidResponse)?
            .to_string(),
        Err(ProviderError::NotFound) => {
            // Create folder
            let body = serde_json::json!({
                "name": "SecureCloud",
                "folder": {},
                "@microsoft.graph.conflictBehavior": "rename"
            });
            let body_bytes =
                serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
            let url = format!("{}/root/children", GRAPH_BASE);
            let req = ProviderHttpRequest::post(url)
                .header(bearer(token))
                .header(("Content-Type".to_string(), "application/json".to_string()))
                .body(body_bytes);
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            meta.get("id")
                .and_then(|v| v.as_str())
                .ok_or(ProviderError::InvalidResponse)?
                .to_string()
        }
        Err(e) => return Err(e),
    };
    {
        let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
        s.root_folder_id = Some(folder_id.clone());
    }
    Ok(folder_id)
}

/// Extract the eTag from a Graph API response.
fn parse_etag(meta: &serde_json::Value) -> String {
    meta.get("eTag")
        .or_else(|| meta.get("etag"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract the item ID from a Graph API response.
fn parse_id(meta: &serde_json::Value) -> String {
    meta.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parse a modified timestamp from a Graph API response (ISO 8601).
fn parse_modified_at(meta: &serde_json::Value) -> Option<i64> {
    let s = meta
        .get("lastModifiedDateTime")
        .and_then(|v| v.as_str())?;
    crate::byo::providers::gdrive::parse_rfc3339_ms(s)
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for OneDriveProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Onedrive
    }

    fn display_name(&self) -> String {
        "OneDrive".to_string()
    }

    fn is_ready(&self) -> bool {
        self.state
            .lock()
            .ok()
            .map(|s| s.access_token.is_some())
            .unwrap_or(false)
    }

    fn get_config(&self) -> ProviderConfig {
        let s = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return ProviderConfig::default(),
        };
        ProviderConfig {
            type_: ProviderType::Onedrive,
            access_token: s.access_token.clone(),
            refresh_token: s.refresh_token.clone(),
            token_expiry: s.token_expiry,
            client_id: s.client_id.clone(),
            ..Default::default()
        }
    }

    fn init(
        &self,
        config: ProviderConfig,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = config.access_token;
            s.refresh_token = config.refresh_token;
            s.token_expiry = config.token_expiry;
            s.client_id = config.client_id;
            s.root_folder_id = None; // reset so it's re-fetched
            Ok(())
        }
    }

    fn disconnect(
        &self,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = None;
            s.refresh_token = None;
            s.token_expiry = None;
            s.root_folder_id = None;
            s.upload_sessions.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    fn refresh_auth(
        &self,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (refresh_token, client_id) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.refresh_token.clone(), s.client_id.clone())
            };
            let refresh_token = refresh_token.ok_or(ProviderError::Unauthorized)?;
            let client_id = client_id
                .ok_or_else(|| ProviderError::Provider("client_id required for refresh".into()))?;
            let form = build_refresh_form(&refresh_token, &client_id);
            let req = ProviderHttpRequest::post(TOKEN_URL.to_string())
                .header((
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ))
                .body(form.into_bytes());
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let tok = parse_token_response(&resp.body)
                .map_err(|e| ProviderError::Provider(e.to_string()))?;
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = Some(tok.access_token);
            if let Some(new_refresh) = tok.refresh_token {
                s.refresh_token = Some(new_refresh);
            }
            if let Some(expires_in) = tok.expires_in {
                s.token_expiry = Some(current_time_ms() + (expires_in as i64) * 1000);
            }
            Ok(())
        }
    }

    fn upload(
        &self,
        ref_: Option<String>,
        name: String,
        data: Vec<u8>,
        options: UploadOptions,
    ) -> impl std::future::Future<Output = Result<UploadResult, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };

            let item_path = match &ref_ {
                Some(r) if !r.is_empty() => {
                    // ref_ is a Graph API item ID — use /items/{id}/content
                    // For consistency, treat it as a path
                    r.clone()
                }
                _ => od_file_path(&name, options.parent_ref.as_deref()),
            };

            // If item_path looks like an ID (no slash), use the ID-based endpoint
            let url = if item_path.contains('/') {
                format!("{}/root:{}/content", GRAPH_BASE, encode_od_path(&item_path))
            } else {
                format!("{}/items/{}/content", GRAPH_BASE, item_path)
            };

            let mut req = ProviderHttpRequest::put(url)
                .header(bearer(&token))
                .header(("Content-Type".to_string(), "application/octet-stream".to_string()))
                .body(data);

            if let Some(etag) = &options.expected_version {
                req = req.header(("If-Match".to_string(), etag.clone()));
            }

            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            Ok(UploadResult {
                ref_: parse_id(&meta),
                version: parse_etag(&meta),
            })
        }
    }

    fn download(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = if ref_.contains('/') {
                format!("{}/root:{}/content", GRAPH_BASE, encode_od_path(&ref_))
            } else {
                format!("{}/items/{}/content", GRAPH_BASE, ref_)
            };
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            Ok(resp.body)
        }
    }

    fn delete(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = if ref_.contains('/') {
                format!("{}/root:{}", GRAPH_BASE, encode_od_path(&ref_))
            } else {
                format!("{}/items/{}", GRAPH_BASE, ref_)
            };
            let req = ProviderHttpRequest::delete(url).header(bearer(&token));
            let resp = http.request(req).await?;
            // 204 = success for DELETE; map_http_status returns None for 204
            if resp.status != 204 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            Ok(())
        }
    }

    fn get_version(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let meta = if ref_.contains('/') {
                od_get_item(&*http, &token, &ref_).await?
            } else {
                od_get_item_by_id(&*http, &token, &ref_).await?
            };
            Ok(parse_etag(&meta))
        }
    }

    // ── Resumable upload ─────────────────────────────────────────────────────

    fn upload_stream_open(
        &self,
        ref_: Option<String>,
        name: String,
        total_size: u64,
        options: UploadOptions,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };

            let item_path = match &ref_ {
                Some(r) if !r.is_empty() => r.clone(),
                _ => od_file_path(&name, options.parent_ref.as_deref()),
            };

            // Create upload session
            let session_url = if item_path.contains('/') {
                format!("{}/root:{}/createUploadSession", GRAPH_BASE, encode_od_path(&item_path))
            } else {
                format!("{}/items/{}/createUploadSession", GRAPH_BASE, item_path)
            };

            let body = serde_json::json!({
                "item": {
                    "@microsoft.graph.conflictBehavior": "replace",
                    "name": name,
                }
            });
            let body_bytes =
                serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
            let req = ProviderHttpRequest::post(session_url)
                .header(bearer(&token))
                .header(("Content-Type".to_string(), "application/json".to_string()))
                .body(body_bytes);
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            let upload_url = meta
                .get("uploadUrl")
                .and_then(|v| v.as_str())
                .ok_or(ProviderError::InvalidResponse)?
                .to_string();
            // P1/SSRF: Graph returns an attacker-controlled `uploadUrl` pointed
            // at a scoped CDN. Validate scheme+host before storing it as the
            // PATCH target for every chunk — otherwise a hostile or
            // intercepted response can redirect ciphertext + SAS token to
            // 169.254.169.254 (cloud metadata) or an internal service.
            // Upload URLs live under *.sharepoint.com / *.1drv.com /
            // api.onedrive.com / *.microsoft.com depending on the tenant.
            super::url_guard::validate_response_url(
                &upload_url,
                &[
                    "sharepoint.com",
                    "1drv.com",
                    "1drv.ms",
                    "onedrive.com",
                    "microsoft.com",
                    "live.com",
                ],
            )?;

            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.upload_sessions.insert(
                    stream_id.clone(),
                    UploadSession {
                        upload_url,
                        total_size,
                        buffer: Vec::with_capacity(OD_CHUNK_SIZE),
                        offset: 0,
                        completed: None,
                    },
                );
            }
            Ok(stream_id)
        }
    }

    fn upload_stream_write(
        &self,
        stream_id: String,
        chunk: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            // Append the caller's data to the per-session buffer, then flush
            // every full `OD_CHUNK_SIZE`-aligned range to the upload URL. The
            // mutex is released between flushes to keep async HTTP calls
            // off-lock.
            {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let session = s.upload_sessions.get_mut(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                session.buffer.extend_from_slice(&chunk);
            }
            drop(chunk);

            // Flush all aligned chunks currently in the buffer.
            loop {
                let (upload_url, range_start, total_size, payload, is_final) = {
                    let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                    let session = s.upload_sessions.get_mut(&stream_id).ok_or_else(|| {
                        ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                    })?;
                    if session.buffer.len() < OD_CHUNK_SIZE {
                        break;
                    }
                    let remaining_after_chunk = session.total_size
                        .saturating_sub(session.offset.saturating_add(OD_CHUNK_SIZE as u64));
                    let is_final = remaining_after_chunk == 0 && session.buffer.len() == OD_CHUNK_SIZE;
                    let payload: Vec<u8> = session.buffer.drain(..OD_CHUNK_SIZE).collect();
                    (
                        session.upload_url.clone(),
                        session.offset,
                        session.total_size,
                        payload,
                        is_final,
                    )
                };

                let resp = od_put_range(&*http, &upload_url, range_start, total_size, payload).await?;
                let range_end = range_start + OD_CHUNK_SIZE as u64; // next offset
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let session = s.upload_sessions.get_mut(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                session.offset = range_end;
                if is_final {
                    // 200/201 with metadata is expected on the final chunk.
                    let meta = parse_json(&resp).unwrap_or(serde_json::Value::Null);
                    session.completed = Some(UploadResult {
                        ref_: parse_id(&meta),
                        version: parse_etag(&meta),
                    });
                }
            }
            Ok(())
        }
    }

    fn upload_stream_close(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<UploadResult, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            // If all bytes already landed (file size was an exact multiple of
            // the chunk size), we have a cached `completed` result — just
            // return it. Otherwise flush whatever remains as the final range.
            let (upload_url, range_start, total_size, payload, already_done) = {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let session = s.upload_sessions.remove(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                if let Some(done) = session.completed {
                    if session.buffer.is_empty() {
                        return Ok(done);
                    }
                    // Both completed AND non-empty buffer would mean callers
                    // wrote past `total_size` — reject rather than corrupt.
                    return Err(ProviderError::Provider(
                        "upload_stream_close: bytes written exceed declared total_size".into(),
                    ));
                }
                (
                    session.upload_url,
                    session.offset,
                    session.total_size,
                    session.buffer,
                    false,
                )
            };
            let _ = already_done;

            let payload_len = payload.len() as u64;
            let total = if total_size > 0 {
                total_size
            } else {
                range_start.saturating_add(payload_len)
            };
            if range_start.saturating_add(payload_len) != total {
                return Err(ProviderError::Provider(format!(
                    "upload_stream_close: short upload — offset {} + {} remaining != total {}",
                    range_start, payload_len, total
                )));
            }

            let resp = od_put_range(&*http, &upload_url, range_start, total, payload).await?;
            let meta = parse_json(&resp)?;
            Ok(UploadResult {
                ref_: parse_id(&meta),
                version: parse_etag(&meta),
            })
        }
    }

    fn upload_stream_abort(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let upload_url = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.upload_sessions
                    .remove(&stream_id)
                    .map(|session| session.upload_url)
            };
            if let Some(url) = upload_url {
                // DELETE the upload session on OneDrive's side
                let req = ProviderHttpRequest::delete(url);
                let _ = http.request(req).await; // best-effort; ignore errors
            }
            Ok(())
        }
    }

    // ── Streaming download ───────────────────────────────────────────────────

    fn download_stream_open(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = if ref_.contains('/') {
                format!("{}/root:{}/content", GRAPH_BASE, encode_od_path(&ref_))
            } else {
                format!("{}/items/{}/content", GRAPH_BASE, ref_)
            };
            // OneDrive follows a 302 redirect to a CDN; Range header is preserved.
            let make_headers = bearer_range_headers(token);
            let http_call = make_http_call_fn(http);
            let buf = RangedDownloadBuffer::new(url, "GET", None, make_headers, http_call);
            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.download_buffers.insert(stream_id.clone(), buf);
            }
            Ok(stream_id)
        }
    }

    fn download_stream_read(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let (req, requested, http_call) = {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let buf = s
                    .download_buffers
                    .get_mut(&stream_id)
                    .ok_or_else(|| ProviderError::Provider(format!("unknown stream_id: {stream_id}")))?;
                match buf.next_request() {
                    None => return Ok(None),
                    Some((req, size)) => (req, size, Arc::clone(&buf.http_call)),
                }
            };
            let resp = http_call(req).await?;
            let content_range = resp.header("content-range").map(str::to_owned);
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            match s.download_buffers.get_mut(&stream_id) {
                None => Ok(None),
                Some(buf) => buf.apply_response(resp.status, resp.body, content_range.as_deref(), requested),
            }
        }
    }

    fn download_stream_close(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.download_buffers.remove(&stream_id);
            Ok(())
        }
    }

    // ── Directory operations ─────────────────────────────────────────────────

    fn list(
        &self,
        parent_ref: Option<String>,
    ) -> impl std::future::Future<Output = Result<Vec<StorageEntry>, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = match parent_ref {
                Some(ref p) if !p.is_empty() && !p.contains('/') => {
                    format!("{}/items/{}/children", GRAPH_BASE, p)
                }
                Some(p) => format!("{}/root:{}/children", GRAPH_BASE, encode_od_path(&p)),
                None => format!("{}/root:/SecureCloud:/children", GRAPH_BASE),
            };
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            let items = data
                .get("value")
                .and_then(|v| v.as_array())
                .ok_or(ProviderError::InvalidResponse)?;
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                let is_folder = item.get("folder").is_some();
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ref_ = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = item
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let mime_type = item
                    .get("file")
                    .and_then(|f| f.get("mimeType"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let modified_at = parse_modified_at(item);
                result.push(StorageEntry {
                    ref_,
                    name,
                    size,
                    is_folder,
                    mime_type,
                    modified_at,
                });
            }
            Ok(result)
        }
    }

    fn create_folder(
        &self,
        name: String,
        parent_ref: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = match parent_ref {
                Some(ref p) if !p.is_empty() && !p.contains('/') => {
                    format!("{}/items/{}/children", GRAPH_BASE, p)
                }
                Some(p) => format!("{}/root:{}/children", GRAPH_BASE, encode_od_path(&p)),
                None => format!("{}/root:/SecureCloud:/children", GRAPH_BASE),
            };
            let body = serde_json::json!({
                "name": name,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "rename"
            });
            let body_bytes =
                serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
            let req = ProviderHttpRequest::post(url)
                .header(bearer(&token))
                .header(("Content-Type".to_string(), "application/json".to_string()))
                .body(body_bytes);
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            Ok(parse_id(&meta))
        }
    }

    fn delete_folder(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = if ref_.contains('/') {
                format!("{}/root:{}", GRAPH_BASE, encode_od_path(&ref_))
            } else {
                format!("{}/items/{}", GRAPH_BASE, ref_)
            };
            let req = ProviderHttpRequest::delete(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if resp.status != 204 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            Ok(())
        }
    }

    // ── Share link (P10) — stub ───────────────────────────────────────────────

    async fn create_public_link(
        &self,
        _ref_: String,
    ) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for onedrive".into(),
        ))
    }

    async fn revoke_public_link(
        &self,
        _ref_: String,
    ) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn create_presigned_url(
        &self,
        _ref_: String,
        _ttl_seconds: u32,
    ) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Presigned URLs not yet implemented for onedrive".into(),
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::api::{ProviderHttpRequest, ProviderHttpResponse};
    use std::sync::Mutex;

    struct MockHttp {
        responses: Mutex<Vec<(u16, Vec<u8>)>>,
    }

    impl MockHttp {
        fn new(r: Vec<(u16, Vec<u8>)>) -> Self {
            Self { responses: Mutex::new(r) }
        }
    }

    impl ProviderHttpClient for MockHttp {
        fn request(
            &self,
            _req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            let response = self
                .responses
                .lock()
                .unwrap()
                .drain(0..1)
                .next()
                .unwrap_or((500, b"no response".to_vec()));
            async move {
                Ok(ProviderHttpResponse {
                    status: response.0,
                    headers: Vec::new(),
                    body: response.1,
                })
            }
        }
    }

    fn make_provider(responses: Vec<(u16, Vec<u8>)>) -> OneDriveProvider<MockHttp> {
        let p = OneDriveProvider::new(MockHttp::new(responses));
        p.state.lock().unwrap().access_token = Some("tok".to_string());
        p
    }

    fn item_json(id: &str, etag: &str, name: &str) -> Vec<u8> {
        serde_json::json!({
            "id": id,
            "eTag": etag,
            "name": name,
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn upload_simple() {
        let p = make_provider(vec![(201, item_json("item1", "etag1", "file.bin"))]);
        let result = p
            .upload(None, "file.bin".into(), b"data".to_vec(), UploadOptions::default())
            .await
            .unwrap();
        assert_eq!(result.ref_, "item1");
        assert_eq!(result.version, "etag1");
    }

    #[tokio::test]
    async fn upload_401_unauthorized() {
        let p = make_provider(vec![(401, b"Unauthorized".to_vec())]);
        let err = p
            .upload(None, "f.bin".into(), vec![], UploadOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Unauthorized));
    }

    #[tokio::test]
    async fn upload_412_conflict() {
        let p = make_provider(vec![(412, b"{}".to_vec())]);
        let err = p
            .upload(
                Some("item1".into()),
                "f.bin".into(),
                vec![],
                UploadOptions {
                    expected_version: Some("old-etag".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Conflict { .. }));
    }

    /// Recording mock: like MockHttp but captures (method, url) on every call.
    struct RecordingHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl RecordingHttp {
        fn new(responses: Vec<(u16, Vec<u8>, Vec<(&'static str, &'static str)>)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b, h)| {
                            (
                                s,
                                b,
                                h.into_iter()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderHttpClient for RecordingHttp {
        fn request(
            &self,
            req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            self.calls
                .lock()
                .unwrap()
                .push((req.method.clone(), req.url.clone()));
            let mut responses = self.responses.lock().unwrap();
            let r = if responses.is_empty() {
                (500, b"no response".to_vec(), Vec::new())
            } else {
                responses.remove(0)
            };
            async move {
                Ok(ProviderHttpResponse {
                    status: r.0,
                    headers: r.2,
                    body: r.1,
                })
            }
        }
    }

    /// S7: aborting a OneDrive resumable upload must DELETE the createUploadSession
    /// URL so the SharePoint/OneDrive backend releases the upload buffer.
    #[tokio::test]
    async fn upload_stream_abort_issues_delete_to_upload_url() {
        let session_resp = serde_json::json!({
            "uploadUrl": "https://example.sharepoint.com/_api/uploads/abc"
        })
        .to_string()
        .into_bytes();
        let http = RecordingHttp::new(vec![
            (200, session_resp, vec![]),
            (204, vec![], vec![]),
        ]);
        let p = OneDriveProvider::new(http);
        p.state.lock().unwrap().access_token = Some("tok".to_string());

        let sid = p
            .upload_stream_open(None, "x.bin".into(), 9, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_abort(sid).await.unwrap();

        let calls = p.http.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2, "expected POST + DELETE, got {calls:?}");
        assert_eq!(calls[0].0, "POST");
        assert_eq!(calls[1].0, "DELETE");
        assert!(
            calls[1].1.contains("example.sharepoint.com"),
            "DELETE target must be the session uploadUrl, got {}",
            calls[1].1
        );
    }

    #[tokio::test]
    async fn resumable_upload_roundtrip() {
        // 1st response: createUploadSession
        // 2nd response: final PUT → 201 complete
        // Use a hostname under the real OneDrive allowlist so the URL guard
        // accepts it (real uploads live under *.sharepoint.com / *.1drv.com).
        let session_resp = serde_json::json!({ "uploadUrl": "https://example.sharepoint.com/session1" })
            .to_string()
            .into_bytes();
        let done_resp = item_json("item2", "etag2", "big.bin");
        let p = make_provider(vec![(200, session_resp), (201, done_resp)]);
        let sid = p
            .upload_stream_open(None, "big.bin".into(), 9, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec()).await.unwrap();
        p.upload_stream_write(sid.clone(), b" yoo".to_vec()).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.ref_, "item2");
        assert_eq!(result.version, "etag2");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![(200, b"content bytes".to_vec())]);
        let sid = p.download_stream_open("item1".into()).await.unwrap();
        let chunk = p.download_stream_read(sid.clone()).await.unwrap();
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk, Some(b"content bytes".to_vec()));
        assert_eq!(eof, None);
        p.download_stream_close(sid).await.unwrap();
    }
}
