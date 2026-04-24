// Google Drive storage provider implementation.
//
// API: Google Drive v3 REST
// Auth: OAuth2 Bearer token (no auto-refresh — callers use byo_gdrive_refresh_token)
// Ref: file ID (opaque GDrive string)
// Version: etag field from file metadata
// Conflict: If-Match header → 412 → ProviderError::Conflict
// Upload: multipart for blobs, resumable for streams (chunk PUT with Content-Range)
// Download: GET with Range; chunked via RangedDownloadBuffer (8 MiB chunks)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    bearer, bearer_range_headers, current_time_ms, json_str, make_http_call_fn, map_http_status,
    new_stream_id, parse_json, RangedDownloadBuffer,
};

const DRIVE_API: &str = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD: &str = "https://www.googleapis.com/upload/drive/v3/files";
const VAULT_ROOT_FOLDER: &str = "WattcloudVault";
const GDRIVE_FOLDER_MIME: &str = "application/vnd.google-apps.folder";

// ─── State ────────────────────────────────────────────────────────────────────

struct UploadSession {
    session_uri: String,
    total_size: u64,
    bytes_written: u64,
    // B1: if the final chunk returned a terminal (200/201) response, cache the
    // file metadata so `upload_stream_close` can return it without issuing a
    // stray "query-status" request. Empty means the session is still open or
    // finished on a non-terminal status.
    final_response: Option<UploadResult>,
}

struct GdriveState {
    access_token: Option<String>,
    root_folder_id: Option<String>,
    upload_sessions: HashMap<String, UploadSession>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

fn lock_err() -> ProviderError {
    ProviderError::Provider("state lock poisoned".to_string())
}

// ─── Provider struct ──────────────────────────────────────────────────────────

pub struct GdriveProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<GdriveState>>,
}

impl<H: ProviderHttpClient> GdriveProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(GdriveState {
                access_token: None,
                root_folder_id: None,
                upload_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for GdriveProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Gdrive
    }
    fn display_name(&self) -> String {
        "Google Drive".to_string()
    }
    fn is_ready(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.access_token.is_some())
            .unwrap_or(false)
    }
    fn get_config(&self) -> ProviderConfig {
        let token = self.state.lock().ok().and_then(|s| s.access_token.clone());
        ProviderConfig {
            type_: ProviderType::Gdrive,
            access_token: token,
            ..Default::default()
        }
    }

    fn init(
        &self,
        config: ProviderConfig,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = config
                .access_token
                .clone()
                .ok_or(ProviderError::Unauthorized)?;
            {
                let mut s = state.lock().map_err(|_| lock_err())?;
                s.access_token = config.access_token;
                s.root_folder_id = None;
            }
            let folder_id = gdrive_ensure_root_folder(&*http, &token).await?;
            state.lock().map_err(|_| lock_err())?.root_folder_id = Some(folder_id);
            Ok(())
        }
    }

    fn disconnect(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state.lock().map_err(|_| lock_err())?;
            s.access_token = None;
            s.root_folder_id = None;
            s.upload_sessions.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    async fn refresh_auth(&self) -> Result<(), ProviderError> {
        // Explicit refresh design: callers use byo_gdrive_refresh_token externally.
        Ok(())
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
            let (token, root_folder_id) = {
                let s = state.lock().map_err(|_| lock_err())?;
                (
                    s.access_token.clone().ok_or(ProviderError::Unauthorized)?,
                    s.root_folder_id.clone(),
                )
            };
            gdrive_upload(
                &*http,
                &token,
                ref_,
                &name,
                &data,
                &options,
                root_folder_id.as_deref(),
            )
            .await
        }
    }

    fn download(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = state
                .lock()
                .map_err(|_| lock_err())?
                .access_token
                .clone()
                .ok_or(ProviderError::Unauthorized)?;
            let resp = http
                .request(
                    ProviderHttpRequest::get(format!("{DRIVE_API}/{ref_}?alt=media"))
                        .header(bearer(&token)),
                )
                .await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            Ok(resp.body)
        }
    }

    fn delete(&self, ref_: String) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = state
                .lock()
                .map_err(|_| lock_err())?
                .access_token
                .clone()
                .ok_or(ProviderError::Unauthorized)?;
            let resp = http
                .request(
                    ProviderHttpRequest::delete(format!("{DRIVE_API}/{ref_}"))
                        .header(bearer(&token)),
                )
                .await?;
            if resp.status == 404 {
                return Ok(());
            }
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
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
            let token = state
                .lock()
                .map_err(|_| lock_err())?
                .access_token
                .clone()
                .ok_or(ProviderError::Unauthorized)?;
            let resp = http
                .request(
                    ProviderHttpRequest::get(format!("{DRIVE_API}/{ref_}?fields=etag"))
                        .header(bearer(&token)),
                )
                .await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let json = parse_json(&resp.body)?;
            Ok(json
                .get("etag")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string())
        }
    }

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
            let (token, root_folder_id) = {
                let s = state.lock().map_err(|_| lock_err())?;
                (
                    s.access_token.clone().ok_or(ProviderError::Unauthorized)?,
                    s.root_folder_id.clone(),
                )
            };
            let session_uri = gdrive_start_resumable_upload(
                &*http,
                &token,
                ref_.as_deref(),
                &name,
                total_size,
                &options,
                root_folder_id.as_deref(),
            )
            .await?;
            let stream_id = new_stream_id();
            state
                .lock()
                .map_err(|_| lock_err())?
                .upload_sessions
                .insert(
                    stream_id.clone(),
                    UploadSession {
                        session_uri,
                        total_size,
                        bytes_written: 0,
                        final_response: None,
                    },
                );
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
            let (session_uri, total_size, start) = {
                let s = state.lock().map_err(|_| lock_err())?;
                let sess = s
                    .upload_sessions
                    .get(&stream_id)
                    .ok_or_else(|| ProviderError::Provider("unknown stream_id".to_string()))?;
                (
                    sess.session_uri.clone(),
                    sess.total_size,
                    sess.bytes_written,
                )
            };
            let end = start + chunk.len() as u64 - 1;
            let resp = http
                .request(ProviderHttpRequest::put(session_uri).body(chunk).header((
                    "Content-Range".to_string(),
                    format!("bytes {start}-{end}/{total_size}"),
                )))
                .await?;
            // 308 = Resume Incomplete (chunk accepted), 200/201 = upload complete.
            // B1: on a terminal response, capture the file metadata here rather
            // than relying on close() to issue a second (status-query) request.
            // The status-query variant (`bytes */total`) does NOT flush any
            // remaining bytes — a close that ran without capturing the terminal
            // response would silently drop tail bytes on misaligned chunking.
            let terminal_result = if resp.status == 200 || resp.status == 201 {
                let json = parse_json(&resp.body)?;
                let file_id = json_str(&json, "id")?.to_string();
                let etag = json
                    .get("etag")
                    .and_then(|e| e.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(UploadResult {
                    ref_: file_id,
                    version: etag,
                })
            } else if resp.status == 308 {
                None
            } else if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            } else {
                None
            };
            if let Some(sess) = state
                .lock()
                .map_err(|_| lock_err())?
                .upload_sessions
                .get_mut(&stream_id)
            {
                sess.bytes_written = end + 1;
                if let Some(r) = terminal_result {
                    sess.final_response = Some(r);
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
            let (session_uri, total_size, bytes_written, cached) = {
                let mut s = state.lock().map_err(|_| lock_err())?;
                let sess = s
                    .upload_sessions
                    .remove(&stream_id)
                    .ok_or_else(|| ProviderError::Provider("unknown stream_id".to_string()))?;
                (
                    sess.session_uri,
                    sess.total_size,
                    sess.bytes_written,
                    sess.final_response,
                )
            };
            // B1: the final chunk write already returned the file metadata —
            // reuse it, skip the extra status-query round-trip.
            if let Some(r) = cached {
                return Ok(r);
            }
            // If the final chunk didn't close the session (server replied 308
            // to the last write, or caller closed without covering total_size),
            // refuse to silently drop data. A `bytes */total` status query does
            // NOT flush remaining bytes — historically this is exactly how tail
            // bytes were lost on misaligned chunking.
            if bytes_written < total_size {
                return Err(ProviderError::Provider(format!(
                    "gdrive upload_stream_close: {bytes_written} of {total_size} bytes written; \
                     refusing to finalize an incomplete session"
                )));
            }
            // All bytes on the wire and the last write got a non-terminal
            // response (rare edge-case; GDrive should have emitted 200/201 on
            // the final chunk). Fall back to a status query to pick up the
            // file metadata.
            let resp = http
                .request(
                    ProviderHttpRequest::put(session_uri)
                        .header(("Content-Range".to_string(), format!("bytes */{total_size}"))),
                )
                .await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let json = parse_json(&resp.body)?;
            let file_id = json_str(&json, "id")?.to_string();
            let etag = json
                .get("etag")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string();
            Ok(UploadResult {
                ref_: file_id,
                version: etag,
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
            let session_uri = state
                .lock()
                .map_err(|_| lock_err())?
                .upload_sessions
                .remove(&stream_id)
                .map(|s| s.session_uri);
            if let Some(uri) = session_uri {
                // Best-effort DELETE; ignore errors
                let _ = http.request(ProviderHttpRequest::delete(uri)).await;
            }
            Ok(())
        }
    }

    fn download_stream_open(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = state
                .lock()
                .map_err(|_| lock_err())?
                .access_token
                .clone()
                .ok_or(ProviderError::Unauthorized)?;
            let url = format!("{DRIVE_API}/{ref_}?alt=media");
            let make_headers = bearer_range_headers(token);
            let http_call = make_http_call_fn(http);
            let buf = RangedDownloadBuffer::new(url, "GET", None, make_headers, http_call);
            let stream_id = new_stream_id();
            state
                .lock()
                .map_err(|_| lock_err())?
                .download_buffers
                .insert(stream_id.clone(), buf);
            Ok(stream_id)
        }
    }

    fn download_stream_read(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            // Extract request params (brief lock).
            let (req, requested, http_call) = {
                let mut s = state.lock().map_err(|_| lock_err())?;
                let buf = s
                    .download_buffers
                    .get_mut(&stream_id)
                    .ok_or_else(|| ProviderError::Provider("unknown stream_id".to_string()))?;
                match buf.next_request() {
                    None => return Ok(None),
                    Some((req, size)) => (req, size, Arc::clone(&buf.http_call)),
                }
            };
            // HTTP call without holding the lock.
            let resp = http_call(req).await?;
            let content_range = resp.header("content-range").map(str::to_owned);
            // Apply response (brief lock).
            let mut s = state.lock().map_err(|_| lock_err())?;
            match s.download_buffers.get_mut(&stream_id) {
                None => Ok(None),
                Some(buf) => {
                    buf.apply_response(resp.status, resp.body, content_range.as_deref(), requested)
                }
            }
        }
    }

    fn download_stream_close(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            state
                .lock()
                .map_err(|_| lock_err())?
                .download_buffers
                .remove(&stream_id);
            Ok(())
        }
    }

    fn list(
        &self,
        parent_ref: Option<String>,
    ) -> impl std::future::Future<Output = Result<Vec<StorageEntry>, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (token, root_folder_id) = {
                let s = state.lock().map_err(|_| lock_err())?;
                (
                    s.access_token.clone().ok_or(ProviderError::Unauthorized)?,
                    s.root_folder_id.clone(),
                )
            };
            let folder_id = parent_ref
                .or(root_folder_id)
                .ok_or_else(|| ProviderError::Provider("no root folder id".to_string()))?;
            let safe_id = folder_id.replace('\'', "\\'");
            let query = format!("'{safe_id}' in parents and trashed=false");
            let url = format!(
                "{DRIVE_API}?q={}&fields=files(id,name,size,mimeType,modifiedTime)&pageSize=1000",
                percent_encode(&query)
            );
            let resp = http
                .request(ProviderHttpRequest::get(url).header(bearer(&token)))
                .await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let json = parse_json(&resp.body)?;
            let files = json
                .get("files")
                .and_then(|f| f.as_array())
                .ok_or(ProviderError::InvalidResponse)?;
            let mut entries = Vec::with_capacity(files.len());
            for f in files {
                let ref_ = json_str(f, "id")?.to_string();
                let name = json_str(f, "name")?.to_string();
                let size = f
                    .get("size")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let mime = f
                    .get("mimeType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                let is_folder = mime == GDRIVE_FOLDER_MIME;
                let modified_at = f
                    .get("modifiedTime")
                    .and_then(|t| t.as_str())
                    .and_then(parse_rfc3339_ms);
                entries.push(StorageEntry {
                    ref_,
                    name,
                    size,
                    is_folder,
                    mime_type: if is_folder { None } else { Some(mime) },
                    modified_at,
                });
            }
            Ok(entries)
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
            let (token, root_folder_id) = {
                let s = state.lock().map_err(|_| lock_err())?;
                (
                    s.access_token.clone().ok_or(ProviderError::Unauthorized)?,
                    s.root_folder_id.clone(),
                )
            };
            let parent = parent_ref.or(root_folder_id);
            let mut meta = serde_json::json!({
                "name": name,
                "mimeType": GDRIVE_FOLDER_MIME,
            });
            if let Some(p) = parent {
                meta["parents"] = serde_json::json!([p]);
            }
            let body = serde_json::to_vec(&meta)
                .map_err(|_| ProviderError::Provider("json serialize error".to_string()))?;
            let resp = http
                .request(
                    ProviderHttpRequest::post(DRIVE_API)
                        .body(body)
                        .header(bearer(&token))
                        .header(("Content-Type".to_string(), "application/json".to_string())),
                )
                .await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            Ok(json_str(&parse_json(&resp.body)?, "id")?.to_string())
        }
    }

    fn delete_folder(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        self.delete(ref_)
    }

    // ── Share link (P10) — stub ───────────────────────────────────────────────

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for gdrive".into(),
        ))
    }

    async fn revoke_public_link(&self, _ref_: String) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn create_presigned_url(
        &self,
        _ref_: String,
        _ttl_seconds: u32,
    ) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Presigned URLs not yet implemented for gdrive".into(),
        ))
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Simple percent-encoding for URL query parameter values.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Parse an RFC 3339 / ISO 8601 UTC timestamp string to Unix milliseconds.
/// Returns `None` on parse failure.
pub(crate) fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let s = s.trim_end_matches('Z');
    let (date_part, time_part) = s.split_once('T')?;
    let mut dp = date_part.splitn(3, '-');
    let year: i64 = dp.next()?.parse().ok()?;
    let month: i64 = dp.next()?.parse().ok()?;
    let day: i64 = dp.next()?.parse().ok()?;
    let time_no_frac = time_part.split('.').next().unwrap_or(time_part);
    let mut tp = time_no_frac.splitn(3, ':');
    let hour: i64 = tp.next()?.parse().ok()?;
    let min: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next()?.parse().ok()?;

    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let months = [
        31i64,
        28 + i64::from(is_leap(year)),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    for m in 1..month {
        days += months.get(m as usize - 1).copied().unwrap_or(30);
    }
    days += day - 1;
    Some((days * 86400 + hour * 3600 + min * 60 + sec) * 1000)
}

pub(crate) fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ─── GDrive-specific API helpers ──────────────────────────────────────────────

async fn gdrive_ensure_root_folder<H: ProviderHttpClient>(
    http: &H,
    token: &str,
) -> Result<String, ProviderError> {
    let query = format!(
        "name='{VAULT_ROOT_FOLDER}' and mimeType='{GDRIVE_FOLDER_MIME}' and trashed=false and 'root' in parents"
    );
    let resp = http
        .request(
            ProviderHttpRequest::get(format!(
                "{DRIVE_API}?q={}&fields=files(id)",
                percent_encode(&query)
            ))
            .header(bearer(token)),
        )
        .await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let json = parse_json(&resp.body)?;
    if let Some(files) = json.get("files").and_then(|f| f.as_array()) {
        if let Some(first) = files.first() {
            if let Some(id) = first.get("id").and_then(|i| i.as_str()) {
                return Ok(id.to_string());
            }
        }
    }
    // Not found — create it
    let body = serde_json::to_vec(&serde_json::json!({
        "name": VAULT_ROOT_FOLDER,
        "mimeType": GDRIVE_FOLDER_MIME,
    }))
    .map_err(|_| ProviderError::Provider("json error".to_string()))?;
    let resp = http
        .request(
            ProviderHttpRequest::post(DRIVE_API)
                .body(body)
                .header(bearer(token))
                .header(("Content-Type".to_string(), "application/json".to_string())),
        )
        .await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    Ok(json_str(&parse_json(&resp.body)?, "id")?.to_string())
}

async fn gdrive_upload<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    ref_: Option<String>,
    name: &str,
    data: &[u8],
    options: &UploadOptions,
    root_folder_id: Option<&str>,
) -> Result<UploadResult, ProviderError> {
    if let Some(id) = &ref_ {
        // Update existing file via PATCH
        let mut req = ProviderHttpRequest::patch(format!("{DRIVE_UPLOAD}/{id}?uploadType=media"))
            .body(data.to_vec())
            .header(bearer(token))
            .header((
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ));
        if let Some(ver) = &options.expected_version {
            req = req.header(("If-Match".to_string(), ver.clone()));
        }
        let resp = http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let json = parse_json(&resp.body)?;
        return Ok(UploadResult {
            ref_: json_str(&json, "id")?.to_string(),
            version: json
                .get("etag")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }

    // New file — multipart POST
    let boundary = format!("scb_{}", current_time_ms());
    let parent = options
        .parent_ref
        .clone()
        .or_else(|| root_folder_id.map(|s| s.to_string()));
    let mut meta = serde_json::json!({ "name": name });
    if let Some(p) = &parent {
        meta["parents"] = serde_json::json!([p]);
    }
    let meta_bytes =
        serde_json::to_vec(&meta).map_err(|_| ProviderError::Provider("json error".to_string()))?;
    let content_type = options
        .mime_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut body: Vec<u8> = Vec::with_capacity(data.len() + 512);
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&meta_bytes);
    body.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: {content_type}\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--").as_bytes());

    let resp = http
        .request(
            ProviderHttpRequest::post(format!("{DRIVE_UPLOAD}?uploadType=multipart"))
                .body(body)
                .header(bearer(token))
                .header((
                    "Content-Type".to_string(),
                    format!("multipart/related; boundary={boundary}"),
                )),
        )
        .await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let json = parse_json(&resp.body)?;
    Ok(UploadResult {
        ref_: json_str(&json, "id")?.to_string(),
        version: json
            .get("etag")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

async fn gdrive_start_resumable_upload<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    ref_: Option<&str>,
    name: &str,
    total_size: u64,
    options: &UploadOptions,
    root_folder_id: Option<&str>,
) -> Result<String, ProviderError> {
    // B9: updates to an existing file use PATCH for resumable session init;
    // POST on an existing file ID can be interpreted as create-not-update by
    // some API versions, which bypasses the `If-Match` precondition below.
    let (url, body_bytes, has_json_body, is_update) = if let Some(id) = ref_ {
        (
            format!("{DRIVE_UPLOAD}/{id}?uploadType=resumable"),
            vec![],
            false,
            true,
        )
    } else {
        let parent = options
            .parent_ref
            .clone()
            .or_else(|| root_folder_id.map(|s| s.to_string()));
        let mut meta = serde_json::json!({ "name": name });
        if let Some(p) = parent {
            meta["parents"] = serde_json::json!([p]);
        }
        let bytes = serde_json::to_vec(&meta)
            .map_err(|_| ProviderError::Provider("json error".to_string()))?;
        (
            format!("{DRIVE_UPLOAD}?uploadType=resumable"),
            bytes,
            true,
            false,
        )
    };

    let mut req = if is_update {
        ProviderHttpRequest::patch(url)
    } else {
        ProviderHttpRequest::post(url)
    }
    .body(body_bytes)
    .header(bearer(token))
    .header((
        "X-Upload-Content-Type".to_string(),
        "application/octet-stream".to_string(),
    ))
    .header((
        "X-Upload-Content-Length".to_string(),
        total_size.to_string(),
    ));
    if has_json_body {
        req = req.header((
            "Content-Type".to_string(),
            "application/json; charset=UTF-8".to_string(),
        ));
    }
    if let Some(ver) = &options.expected_version {
        req = req.header(("If-Match".to_string(), ver.clone()));
    }

    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    // P1/SSRF: the Location header is attacker-controlled (hostile Google-API
    // response, or MITM). Validate scheme+host before we use it as the target
    // of the next chunk PUT — a naive forward would let a hostile provider
    // redirect ciphertext PUTs to 169.254.169.254 with the Bearer token
    // attached. GDrive resumable URIs live under googleapis.com and its
    // documented upload CDNs.
    let loc = resp.header("Location").ok_or_else(|| {
        ProviderError::Provider("no Location header in resumable upload response".to_string())
    })?;
    super::url_guard::validate_response_url(loc, &["googleapis.com", "googleusercontent.com"])?;
    Ok(loc.to_string())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::type_complexity)]
mod tests {
    use super::*;
    use crate::api::ProviderHttpResponse;
    use std::sync::Mutex;

    struct MockHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
    }

    impl MockHttp {
        fn new(responses: Vec<(u16, &str)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b)| (s, b.as_bytes().to_vec(), vec![]))
                        .collect(),
                ),
            }
        }

        fn with_headers(responses: Vec<(u16, &str, Vec<(&str, &str)>)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b, h)| {
                            (
                                s,
                                b.as_bytes().to_vec(),
                                h.into_iter()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
            }
        }
    }

    impl ProviderHttpClient for MockHttp {
        fn request(
            &self,
            _req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            let mut responses = self.responses.lock().unwrap();
            let result = if responses.is_empty() {
                Err(ProviderError::Provider(
                    "no more mock responses".to_string(),
                ))
            } else {
                let (status, body, headers) = responses.remove(0);
                Ok(ProviderHttpResponse {
                    status,
                    headers,
                    body,
                })
            };
            std::future::ready(result)
        }
    }

    fn cfg(token: &str) -> ProviderConfig {
        ProviderConfig {
            type_: ProviderType::Gdrive,
            access_token: Some(token.to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn init_creates_root_folder_if_absent() {
        let http = MockHttp::new(vec![
            (200, r#"{"files":[]}"#),
            (200, r#"{"id":"root-folder-id"}"#),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        assert_eq!(
            p.state.lock().unwrap().root_folder_id,
            Some("root-folder-id".to_string())
        );
    }

    #[tokio::test]
    async fn init_reuses_existing_root_folder() {
        let http = MockHttp::new(vec![(200, r#"{"files":[{"id":"existing"}]}"#)]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        assert_eq!(
            p.state.lock().unwrap().root_folder_id,
            Some("existing".to_string())
        );
    }

    #[tokio::test]
    async fn init_unauthorized_returns_error() {
        let http = MockHttp::new(vec![(401, r#"{}"#)]);
        let p = GdriveProvider::new(http);
        assert!(matches!(
            p.init(cfg("expired")).await,
            Err(ProviderError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn upload_new_file_multipart() {
        let http = MockHttp::new(vec![
            (200, r#"{"files":[{"id":"root"}]}"#),
            (200, r#"{"id":"file-id","etag":"etag-1"}"#),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        let r = p
            .upload(
                None,
                "test.v7".to_string(),
                b"hello".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(r.ref_, "file-id");
        assert_eq!(r.version, "etag-1");
    }

    #[tokio::test]
    async fn upload_conflict_on_412() {
        let http = MockHttp::new(vec![
            (200, r#"{"files":[{"id":"root"}]}"#),
            (412, r#"{"etag":"v2"}"#),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        let err = p
            .upload(
                Some("f".to_string()),
                "f.v7".to_string(),
                b"d".to_vec(),
                UploadOptions {
                    expected_version: Some("v1".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::Conflict { current_version } if current_version == "v2")
        );
    }

    #[tokio::test]
    async fn upload_stream_roundtrip() {
        let http = MockHttp::with_headers(vec![
            (200, r#"{"files":[{"id":"root"}]}"#, vec![]),
            (
                200,
                r#"{}"#,
                vec![("Location", "https://up.googleapis.com/sess")],
            ),
            (308, "", vec![]),
            (200, r#"{"id":"file-123","etag":"etag-abc"}"#, vec![]),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        let sid = p
            .upload_stream_open(None, "big.v7".to_string(), 512, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), vec![0u8; 512])
            .await
            .unwrap();
        let r = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(r.ref_, "file-123");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        // Server returns 200 (ignoring Range) — `apply_response` falls back
        // to treating the full body as a single chunk.
        let http = MockHttp::new(vec![
            (200, r#"{"files":[{"id":"root"}]}"#),
            (200, "ciphertext"),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        let sid = p.download_stream_open("f".to_string()).await.unwrap();
        let chunk1 = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk1, Some(b"ciphertext".to_vec()));
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert!(eof.is_none());
        p.download_stream_close(sid).await.unwrap();
    }

    /// Stateful mock that actually parses Range headers and serves the
    /// requested byte range from a stored body. Used to exercise the real
    /// Range-based download path end to end.
    struct RangeServingHttp {
        init_responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        body: Vec<u8>,
    }

    impl RangeServingHttp {
        fn new(init_responses: Vec<(u16, &str, Vec<(&str, &str)>)>, body: Vec<u8>) -> Self {
            Self {
                init_responses: Mutex::new(
                    init_responses
                        .into_iter()
                        .map(|(s, b, h)| {
                            (
                                s,
                                b.as_bytes().to_vec(),
                                h.into_iter()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                body,
            }
        }
    }

    impl ProviderHttpClient for RangeServingHttp {
        fn request(
            &self,
            req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            // Consume init-phase responses first (e.g. root folder lookup).
            let mut init = self.init_responses.lock().unwrap();
            if !init.is_empty() {
                let (status, body, headers) = init.remove(0);
                return std::future::ready(Ok(ProviderHttpResponse {
                    status,
                    headers,
                    body,
                }));
            }
            drop(init);

            // After init, serve Range requests from the stored body.
            let range_hdr = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("range"))
                .map(|(_, v)| v.clone());

            let total = self.body.len() as u64;
            let result = match range_hdr.as_deref() {
                Some(r) => {
                    // Parse "bytes=START-END"
                    let spec = r.trim_start_matches("bytes=");
                    let (start_s, end_s) = spec.split_once('-').unwrap_or(("0", ""));
                    let start: u64 = start_s.parse().unwrap_or(0);
                    let end: u64 = if end_s.is_empty() {
                        total.saturating_sub(1)
                    } else {
                        end_s.parse().unwrap_or(total.saturating_sub(1))
                    };
                    if start >= total {
                        ProviderHttpResponse {
                            status: 416,
                            headers: vec![],
                            body: vec![],
                        }
                    } else {
                        let end = end.min(total - 1);
                        let slice = self.body[start as usize..=end as usize].to_vec();
                        let cr = format!("bytes {start}-{end}/{total}");
                        ProviderHttpResponse {
                            status: 206,
                            headers: vec![
                                ("Content-Range".to_string(), cr),
                                ("Content-Length".to_string(), slice.len().to_string()),
                            ],
                            body: slice,
                        }
                    }
                }
                None => ProviderHttpResponse {
                    status: 200,
                    headers: vec![("Content-Length".to_string(), total.to_string())],
                    body: self.body.clone(),
                },
            };
            std::future::ready(Ok(result))
        }
    }

    #[tokio::test]
    async fn gdrive_download_stream_e2e_v7_roundtrip_via_range() {
        // Full end-to-end test: encrypt plaintext into V7 ciphertext, serve it
        // via a stateful Range-honoring mock provider, download via the
        // RangedDownloadBuffer chunked path, and decrypt back to plaintext.
        //
        // Exercises: V7 wire format, chunked Range requests, 206 + Content-Range,
        // the full provider I/O stack. Failure to correctly handle any piece
        // (chunk boundaries, offset advancement, decryptor state) breaks this test.
        use crate::crypto::pqc::generate_hybrid_keypair;
        use crate::crypto::wire_format::{decrypt_file_v7, encrypt_file_v7};

        // Generate a fresh hybrid keypair and encrypt a ~3 MiB plaintext.
        // V7 chunks plaintext into 512 KiB segments (V7_ENCRYPT_CHUNK_SIZE).
        let kp = generate_hybrid_keypair().unwrap();
        let plaintext = {
            let mut buf = Vec::with_capacity(3 * 1024 * 1024);
            for i in 0..(3 * 1024 * 1024u32) {
                buf.push((i % 256) as u8);
            }
            buf
        };
        const CHUNK: usize = 512 * 1024;
        let chunks: Vec<&[u8]> = plaintext.chunks(CHUNK).collect();
        let v7_bytes =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &chunks).unwrap();

        // Mock init response (GDrive root folder lookup) + stateful Range server.
        let http = RangeServingHttp::new(
            vec![(200, r#"{"files":[{"id":"root"}]}"#, vec![])],
            v7_bytes.clone(),
        );
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();

        // Stream-download via chunked Range requests.
        let sid = p.download_stream_open("f".to_string()).await.unwrap();
        let mut downloaded = Vec::new();
        while let Some(chunk) = p.download_stream_read(sid.clone()).await.unwrap() {
            downloaded.extend_from_slice(&chunk);
        }
        p.download_stream_close(sid).await.unwrap();

        assert_eq!(
            downloaded, v7_bytes,
            "V7 ciphertext must round-trip byte-for-byte via chunked Range download"
        );

        // Decrypt and verify the original plaintext is recovered.
        let recovered =
            decrypt_file_v7(&downloaded, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(
            recovered, plaintext,
            "plaintext must match after V7 encrypt → Range-download → V7 decrypt round-trip"
        );
    }

    #[tokio::test]
    async fn download_stream_multi_chunk_via_range() {
        // Server returns 206 with Content-Range for each chunk.
        // Verifies the Range-based multi-chunk streaming path.
        let http = MockHttp::with_headers(vec![
            (200, r#"{"files":[{"id":"root"}]}"#, vec![]),
            (206, "chunk1_data", vec![("Content-Range", "bytes 0-10/33")]),
            (
                206,
                "chunk2_data",
                vec![("Content-Range", "bytes 11-21/33")],
            ),
            (
                206,
                "chunk3_final",
                vec![("Content-Range", "bytes 22-32/33")],
            ),
        ]);
        let p = GdriveProvider::new(http);
        p.init(cfg("tok")).await.unwrap();
        let sid = p.download_stream_open("f".to_string()).await.unwrap();

        let c1 = p.download_stream_read(sid.clone()).await.unwrap().unwrap();
        assert_eq!(c1, b"chunk1_data");
        let c2 = p.download_stream_read(sid.clone()).await.unwrap().unwrap();
        assert_eq!(c2, b"chunk2_data");
        let c3 = p.download_stream_read(sid.clone()).await.unwrap().unwrap();
        assert_eq!(c3, b"chunk3_final");

        // Fourth read: buffer.is_done() so next_request() returns None immediately.
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert!(eof.is_none());
        p.download_stream_close(sid).await.unwrap();
    }

    /// Recording mock that captures every request (method + url) and replays
    /// a canned queue of responses. Used by the resumable-upload abort tests
    /// to assert that abort() actually emits a DELETE against the session_uri.
    struct RecordingHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        calls: Mutex<Vec<(String, String)>>, // (method, url)
    }

    impl RecordingHttp {
        fn new(responses: Vec<(u16, &str, Vec<(&str, &str)>)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b, h)| {
                            (
                                s,
                                b.as_bytes().to_vec(),
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
            let result = if responses.is_empty() {
                Err(ProviderError::Provider(
                    "no more mock responses".to_string(),
                ))
            } else {
                let (status, body, headers) = responses.remove(0);
                Ok(ProviderHttpResponse {
                    status,
                    headers,
                    body,
                })
            };
            std::future::ready(result)
        }
    }

    /// S7: aborting a resumable upload must DELETE the session URI so the
    /// server-side buffer is released and no orphan partial ciphertext
    /// lingers (GDrive keeps resumable sessions for up to a week).
    #[tokio::test]
    async fn upload_stream_abort_issues_delete_to_session_uri() {
        let http = RecordingHttp::new(vec![
            // upload_stream_open → POST start returns 200 + Location header
            (
                200,
                r#"{}"#,
                vec![("Location", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc123")],
            ),
            // abort → DELETE; provider ignores status but we return 204 for realism
            (204, r#""#, vec![]),
        ]);
        let p = GdriveProvider::new(http);
        // Pre-populate state as if init had run.
        p.state.lock().unwrap().access_token = Some("tok".to_string());
        p.state.lock().unwrap().root_folder_id = Some("root".to_string());

        let sid = p
            .upload_stream_open(None, "x.bin".into(), 1024, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_abort(sid).await.unwrap();

        let calls = p.http.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2, "expected POST + DELETE, got {calls:?}");
        assert_eq!(calls[0].0, "POST", "first call should be the session start");
        assert_eq!(calls[1].0, "DELETE", "abort must DELETE the session URI");
        assert!(
            calls[1].1.contains("upload_id=abc123"),
            "DELETE target must be the session URI, got {}",
            calls[1].1
        );
    }

    #[test]
    fn rfc3339_epoch() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rfc3339_with_fractional_seconds() {
        assert_eq!(
            parse_rfc3339_ms("1970-01-01T00:00:01.500Z"),
            Some(1000) // fractional part is ignored; only integer seconds
        );
    }
}
