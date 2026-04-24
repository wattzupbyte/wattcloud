// DropboxProvider — BYO storage backend for Dropbox.
//
// Design notes:
//   - Streaming uploads use the Dropbox Upload Session API
//     (upload_session/start → append_v2 × N → finish).
//     Chunks are buffered internally; an append_v2 is sent whenever the
//     buffer reaches DROPBOX_CHUNK_FLUSH_SIZE (8 MiB). The finish call
//     sends the remaining bytes (any size, including 0).
//   - download_stream_* uses Range requests (POST with Range header) via
//     RangedDownloadBuffer — 8 MiB chunks, no full-file buffering.
//   - Tokens are NOT auto-refreshed: methods return ProviderError::Unauthorized.
//     Callers use the explicit refresh API.
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
    bearer, extract_dropbox_conflict_rev, make_http_call_fn, map_http_status,
    map_http_status_with_conflict_version, new_stream_id, parse_json, MakeHeaders,
    RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const API_BASE: &str = "https://api.dropboxapi.com/2";
const CONTENT_BASE: &str = "https://content.dropboxapi.com/2";
const TOKEN_URL: &str = "https://api.dropbox.com/oauth2/token";

/// Flush threshold for upload session append calls (128 MiB).
/// Bytes accumulate until this threshold is reached, then sent as one append_v2.
/// The final chunk sent via `finish` may be any size (including 0).
///
/// B2: per SPEC-BYO §Storage Providers / §BYO Streaming, Dropbox uploads should
/// use 128 MiB chunks. The previous 8 MiB constant generated 16× as many API
/// round-trips for large files, hitting Dropbox rate limits far sooner.
const DROPBOX_CHUNK_FLUSH_SIZE: usize = 128 * 1024 * 1024;

// ─── State ────────────────────────────────────────────────────────────────────

/// State for an in-progress Dropbox upload session.
struct UploadSession {
    /// Dropbox upload session identifier.
    session_id: String,
    /// Bytes confirmed delivered to Dropbox so far (i.e., the offset for the next append).
    confirmed_offset: u64,
    /// Buffered bytes not yet sent. Flushed at DROPBOX_CHUNK_FLUSH_SIZE.
    buffer: Vec<u8>,
    /// Destination path (Dropbox absolute path).
    path: String,
    /// Conflict detection rev (if overwriting an existing file).
    expected_version: Option<String>,
}

struct DropboxState {
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_expiry: Option<i64>,
    client_id: Option<String>,
    upload_sessions: HashMap<String, UploadSession>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

// ─── Provider ─────────────────────────────────────────────────────────────────

pub struct DropboxProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<DropboxState>>,
}

impl<H: ProviderHttpClient> DropboxProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(DropboxState {
                access_token: None,
                refresh_token: None,
                token_expiry: None,
                client_id: None,
                upload_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build the full path for a Dropbox file (always starts with "/WattcloudVault/").
fn dbx_path(name: &str, parent_ref: Option<&str>) -> String {
    match parent_ref {
        Some(p) if !p.is_empty() => format!("{}/{}", p.trim_end_matches('/'), name),
        _ => format!("/WattcloudVault/{}", name),
    }
}

/// POST to the Dropbox API endpoint with a JSON body.
async fn dbx_api_call<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    endpoint: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, ProviderError> {
    let body_bytes = serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{}/{}", API_BASE, endpoint))
        .header(bearer(token))
        .header(("Content-Type".to_string(), "application/json".to_string()))
        .body(body_bytes);
    let resp = http.request(req).await?;
    // B4: Dropbox 409 bodies carry the conflict rev nested under
    // error.conflict.rev — the generic etag extractor can't see it.
    if let Some(e) = map_dropbox_status(resp.status, &resp.body) {
        return Err(e);
    }
    parse_json(&resp.body)
}

/// POST to the Dropbox content endpoint (upload).
async fn dbx_upload_call<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    endpoint: &str,
    api_arg: serde_json::Value,
    data: Vec<u8>,
) -> Result<serde_json::Value, ProviderError> {
    let arg_str = serde_json::to_string(&api_arg).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{}/{}", CONTENT_BASE, endpoint))
        .header(bearer(token))
        .header(("Dropbox-API-Arg".to_string(), arg_str))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(data);
    let resp = http.request(req).await?;
    if let Some(e) = map_dropbox_status(resp.status, &resp.body) {
        return Err(e);
    }
    parse_json(&resp.body)
}

/// Dropbox wrapper around `map_http_status` that extracts the conflict rev from the
/// Dropbox error body (see B4). On non-conflict statuses this is equivalent to the
/// generic mapper.
fn map_dropbox_status(status: u16, body: &[u8]) -> Option<ProviderError> {
    if status == 409 || status == 412 {
        let current_version = extract_dropbox_conflict_rev(body).unwrap_or_default();
        return map_http_status_with_conflict_version(status, body, current_version);
    }
    map_http_status(status, body)
}

/// POST to the Dropbox content endpoint (download).
async fn dbx_download_call<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    endpoint: &str,
    api_arg: serde_json::Value,
) -> Result<Vec<u8>, ProviderError> {
    let arg_str = serde_json::to_string(&api_arg).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{}/{}", CONTENT_BASE, endpoint))
        .header(bearer(token))
        .header(("Dropbox-API-Arg".to_string(), arg_str));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    Ok(resp.body)
}

/// Parse the `.rev` or `.id` field from a Dropbox file metadata object.
fn parse_version(meta: &serde_json::Value) -> String {
    meta.get("rev")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parse the `id` field from a Dropbox metadata object.
fn parse_ref(meta: &serde_json::Value) -> String {
    meta.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Start a Dropbox upload session. Returns the `session_id`.
async fn dbx_upload_session_start<H: ProviderHttpClient>(
    http: &H,
    token: &str,
) -> Result<String, ProviderError> {
    let req = ProviderHttpRequest::post(format!("{CONTENT_BASE}/files/upload_session/start"))
        .header(bearer(token))
        .header((
            "Dropbox-API-Arg".to_string(),
            r#"{"close":false}"#.to_string(),
        ))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(vec![]);
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let val = parse_json(&resp.body)?;
    val.get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or(ProviderError::InvalidResponse)
}

/// Send one append_v2 chunk to an open Dropbox upload session.
async fn dbx_upload_session_append<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    session_id: &str,
    offset: u64,
    data: Vec<u8>,
) -> Result<(), ProviderError> {
    let arg = serde_json::json!({
        "cursor": { "session_id": session_id, "offset": offset },
        "close": false,
    });
    let arg_str = serde_json::to_string(&arg).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{CONTENT_BASE}/files/upload_session/append_v2"))
        .header(bearer(token))
        .header(("Dropbox-API-Arg".to_string(), arg_str))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(data);
    let resp = http.request(req).await?;
    // B4: append_v2 can return 409 with the conflict rev on mid-stream concurrent writes.
    if let Some(e) = map_dropbox_status(resp.status, &resp.body) {
        return Err(e);
    }
    Ok(())
}

/// Finish an upload session with a commit. `final_chunk` is the remaining data
/// (may be empty). Returns the committed file metadata.
async fn dbx_upload_session_finish<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    session_id: &str,
    offset: u64,
    final_chunk: Vec<u8>,
    path: &str,
    expected_version: Option<&str>,
) -> Result<serde_json::Value, ProviderError> {
    let mode = match expected_version {
        Some(rev) => serde_json::json!({ ".tag": "update", "update": rev }),
        None => serde_json::json!({ ".tag": "overwrite" }),
    };
    let arg = serde_json::json!({
        "cursor": { "session_id": session_id, "offset": offset },
        "commit": {
            "path": path,
            "mode": mode,
            "autorename": false,
            "mute": false,
        },
    });
    let arg_str = serde_json::to_string(&arg).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{CONTENT_BASE}/files/upload_session/finish"))
        .header(bearer(token))
        .header(("Dropbox-API-Arg".to_string(), arg_str))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(final_chunk);
    let resp = http.request(req).await?;
    if let Some(e) = map_dropbox_status(resp.status, &resp.body) {
        return Err(e);
    }
    parse_json(&resp.body)
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for DropboxProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Dropbox
    }

    fn display_name(&self) -> String {
        "Dropbox".to_string()
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
            type_: ProviderType::Dropbox,
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
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = config.access_token;
            s.refresh_token = config.refresh_token;
            s.token_expiry = config.token_expiry;
            s.client_id = config.client_id;
            Ok(())
        }
    }

    fn disconnect(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = None;
            s.refresh_token = None;
            s.token_expiry = None;
            s.upload_sessions.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    fn refresh_auth(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (refresh_token, client_id) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.refresh_token.clone(), s.client_id.clone())
            };
            let refresh_token = refresh_token.ok_or(ProviderError::Unauthorized)?;
            let client_id = client_id.ok_or(ProviderError::Provider(
                "client_id required for refresh".into(),
            ))?;
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
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.access_token = Some(tok.access_token);
            if let Some(new_refresh) = tok.refresh_token {
                s.refresh_token = Some(new_refresh);
            }
            if let Some(expires_in) = tok.expires_in {
                use crate::byo::providers::current_time_ms;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };

            // Use the ref_ (path) if provided, otherwise build path under WattcloudVault/
            let path = match &ref_ {
                Some(r) if !r.is_empty() => r.clone(),
                _ => dbx_path(&name, options.parent_ref.as_deref()),
            };

            let mut api_arg = serde_json::json!({
                "path": path,
                "mode": if ref_.is_some() { "overwrite" } else { "add" },
                "autorename": false,
                "mute": false,
            });

            // Optimistic concurrency: if expected_version given, use "update" mode
            if let Some(rev) = &options.expected_version {
                api_arg = serde_json::json!({
                    "path": path,
                    "mode": { ".tag": "update", "update": rev },
                    "autorename": false,
                    "mute": false,
                });
            }

            let meta = dbx_upload_call(&*http, &token, "files/upload", api_arg, data).await?;
            Ok(UploadResult {
                ref_: parse_ref(&meta),
                version: parse_version(&meta),
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            dbx_download_call(
                &*http,
                &token,
                "files/download",
                serde_json::json!({ "path": ref_ }),
            )
            .await
        }
    }

    fn delete(&self, ref_: String) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let token = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            dbx_api_call(
                &*http,
                &token,
                "files/delete_v2",
                serde_json::json!({ "path": ref_ }),
            )
            .await?;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let meta = dbx_api_call(
                &*http,
                &token,
                "files/get_metadata",
                serde_json::json!({ "path": ref_ }),
            )
            .await?;
            Ok(parse_version(&meta))
        }
    }

    // ── Streaming upload (Dropbox Upload Session API) ────────────────────────
    //
    // Flow: open → start session → write (buffer + append_v2 at flush threshold)
    //       → close (finish with remaining bytes + commit)
    //       → abort (discard session; Dropbox expires stale sessions in 48 h)
    //
    // The Mutex is never held across .await: data is extracted under the lock,
    // the lock is released, then the async HTTP call is made.

    fn upload_stream_open(
        &self,
        ref_: Option<String>,
        name: String,
        _total_size: u64,
        options: UploadOptions,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            // Extract token without holding the lock across await.
            let token = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };

            // Start the Dropbox upload session (async, no lock held).
            let session_id = dbx_upload_session_start(&*http, &token).await?;

            // Compute the final destination path.
            let path = match &ref_ {
                Some(r) if !r.is_empty() => r.clone(),
                _ => dbx_path(&name, options.parent_ref.as_deref()),
            };
            let expected_version = options.expected_version.clone();

            // Store session state.
            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.upload_sessions.insert(
                    stream_id.clone(),
                    UploadSession {
                        session_id,
                        confirmed_offset: 0,
                        buffer: Vec::new(),
                        path,
                        expected_version,
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
            // Append chunk to buffer; if the buffer reaches the flush threshold,
            // extract the data to send and release the lock before awaiting.
            let flush = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let token = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let session = s.upload_sessions.get_mut(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                session.buffer.extend_from_slice(&chunk);
                if session.buffer.len() >= DROPBOX_CHUNK_FLUSH_SIZE {
                    let data = std::mem::take(&mut session.buffer);
                    let sid = session.session_id.clone();
                    let offset = session.confirmed_offset;
                    Some((token, sid, offset, data))
                } else {
                    None
                }
            }; // lock released

            if let Some((token, sid, offset, data)) = flush {
                let sent = data.len() as u64;
                dbx_upload_session_append(&*http, &token, &sid, offset, data).await?;
                // Update confirmed offset after successful append.
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                if let Some(session) = s.upload_sessions.get_mut(&stream_id) {
                    session.confirmed_offset += sent;
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
            // Extract and remove the session state before awaiting.
            let (token, session) = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let token = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let session = s.upload_sessions.remove(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                (token, session)
            }; // lock released

            // Finish the session: body = remaining buffer bytes (may be empty).
            let final_offset = session.confirmed_offset;
            let final_chunk = session.buffer;
            let meta = dbx_upload_session_finish(
                &*http,
                &token,
                &session.session_id,
                final_offset,
                final_chunk,
                &session.path,
                session.expected_version.as_deref(),
            )
            .await?;

            Ok(UploadResult {
                ref_: parse_ref(&meta),
                version: parse_version(&meta),
            })
        }
    }

    fn upload_stream_abort(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        // Dropbox automatically expires stale upload sessions after 48 hours,
        // so no explicit cancel API call is needed. Just discard local state.
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.upload_sessions.remove(&stream_id);
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            // Dropbox downloads are POST with Dropbox-API-Arg + optional Range header.
            let api_arg = serde_json::to_string(&serde_json::json!({ "path": ref_ }))
                .map_err(|_| ProviderError::InvalidResponse)?;
            let url = format!("{CONTENT_BASE}/files/download");
            let make_headers: MakeHeaders = {
                let token = token.clone();
                let api_arg = api_arg.clone();
                Arc::new(move |offset: u64, end: u64| {
                    vec![
                        bearer(&token),
                        ("Dropbox-API-Arg".to_string(), api_arg.clone()),
                        ("Range".to_string(), format!("bytes={offset}-{end}")),
                    ]
                })
            };
            let http_call = make_http_call_fn(http);
            let buf = RangedDownloadBuffer::new(url, "POST", None, make_headers, http_call);
            let stream_id = new_stream_id();
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.download_buffers.insert(stream_id.clone(), buf);
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
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let buf = s.download_buffers.get_mut(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                match buf.next_request() {
                    None => return Ok(None),
                    Some((req, size)) => (req, size, Arc::clone(&buf.http_call)),
                }
            };
            let resp = http_call(req).await?;
            let content_range = resp.header("content-range").map(str::to_owned);
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let path = parent_ref.unwrap_or_else(|| "/WattcloudVault".to_string());
            let resp = dbx_api_call(
                &*http,
                &token,
                "files/list_folder",
                serde_json::json!({ "path": path, "recursive": false }),
            )
            .await?;
            let entries = resp
                .get("entries")
                .and_then(|e| e.as_array())
                .ok_or(ProviderError::InvalidResponse)?;
            let mut result = Vec::with_capacity(entries.len());
            for entry in entries {
                let tag = entry.get(".tag").and_then(|v| v.as_str()).unwrap_or("file");
                let is_folder = tag == "folder";
                let name = entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ref_ = entry
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let modified_at = entry
                    .get("server_modified")
                    .and_then(|v| v.as_str())
                    .and_then(crate::byo::providers::gdrive::parse_rfc3339_ms);
                result.push(StorageEntry {
                    ref_,
                    name,
                    size,
                    is_folder,
                    mime_type: None,
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let path = match parent_ref {
                Some(p) if !p.is_empty() => format!("{}/{}", p.trim_end_matches('/'), name),
                _ => format!("/WattcloudVault/{}", name),
            };
            let meta = dbx_api_call(
                &*http,
                &token,
                "files/create_folder_v2",
                serde_json::json!({ "path": path }),
            )
            .await?;
            Ok(meta
                .get("metadata")
                .and_then(|m| m.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string())
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            dbx_api_call(
                &*http,
                &token,
                "files/delete_v2",
                serde_json::json!({ "path": ref_ }),
            )
            .await?;
            Ok(())
        }
    }

    // ── Share link (P10) — stub ───────────────────────────────────────────────

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for dropbox".into(),
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
            "Presigned URLs not yet implemented for dropbox".into(),
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]
mod tests {
    use super::*;
    use crate::api::{ProviderHttpRequest, ProviderHttpResponse};
    use std::sync::Mutex;

    struct MockHttp {
        responses: Mutex<Vec<(u16, Vec<u8>)>>,
    }

    impl MockHttp {
        fn new(responses: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
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

    fn meta_json(id: &str, rev: &str, name: &str) -> Vec<u8> {
        serde_json::json!({
            "id": id,
            "rev": rev,
            "name": name,
            ".tag": "file",
            "size": 1024_u64,
        })
        .to_string()
        .into_bytes()
    }

    fn make_provider(responses: Vec<(u16, Vec<u8>)>) -> DropboxProvider<MockHttp> {
        let p = DropboxProvider::new(MockHttp::new(responses));
        // Pre-seed the state with a token
        p.state.lock().unwrap().access_token = Some("tok".to_string());
        p
    }

    #[tokio::test]
    async fn upload_returns_ref_and_version() {
        let meta = meta_json("id:abc", "rev123", "test.bin");
        let p = make_provider(vec![(200, meta)]);
        let result = p
            .upload(
                None,
                "test.bin".into(),
                b"hello".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.ref_, "id:abc");
        assert_eq!(result.version, "rev123");
    }

    #[tokio::test]
    async fn upload_401_returns_unauthorized() {
        let p = make_provider(vec![(401, b"Unauthorized".to_vec())]);
        let err = p
            .upload(None, "f.bin".into(), vec![], UploadOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Unauthorized));
    }

    #[tokio::test]
    async fn download_returns_body() {
        let p = make_provider(vec![(200, b"file content".to_vec())]);
        let data = p.download("id:abc".to_string()).await.unwrap();
        assert_eq!(data, b"file content");
    }

    // ── Upload session helpers ────────────────────────────────────────────────

    fn session_start_resp() -> Vec<u8> {
        serde_json::json!({ "session_id": "sess_abc123" })
            .to_string()
            .into_bytes()
    }

    fn session_finish_resp(id: &str, rev: &str, name: &str) -> Vec<u8> {
        meta_json(id, rev, name)
    }

    #[tokio::test]
    async fn stream_small_file_no_append() {
        // File smaller than DROPBOX_CHUNK_FLUSH_SIZE: open → write → close.
        // Expected HTTP calls: start (200), finish (200).
        let meta = session_finish_resp("id:xyz", "rev789", "large.bin");
        let p = make_provider(vec![
            (200, session_start_resp()), // start session
            (200, meta),                 // finish
        ]);
        let sid = p
            .upload_stream_open(None, "large.bin".into(), 6, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hel".to_vec())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"lo!".to_vec())
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.ref_, "id:xyz");
        assert_eq!(result.version, "rev789");
    }

    #[tokio::test]
    async fn stream_large_file_with_append() {
        // File larger than DROPBOX_CHUNK_FLUSH_SIZE triggers at least one append.
        // Expected: start (200) → append (200) → finish (200).
        let meta = session_finish_resp("id:big", "revBig", "huge.bin");
        let p = make_provider(vec![
            (200, session_start_resp()), // start
            (200, b"".to_vec()),         // append_v2 (204/200 both accepted)
            (200, meta),                 // finish
        ]);
        let chunk = vec![0xABu8; DROPBOX_CHUNK_FLUSH_SIZE + 1]; // just over threshold
        let sid = p
            .upload_stream_open(
                None,
                "huge.bin".into(),
                chunk.len() as u64,
                UploadOptions::default(),
            )
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), chunk).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.ref_, "id:big");
        assert_eq!(result.version, "revBig");
    }

    #[tokio::test]
    async fn stream_abort_cleans_state() {
        let p = make_provider(vec![
            (200, session_start_resp()), // start
        ]);
        let sid = p
            .upload_stream_open(None, "f.bin".into(), 0, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_abort(sid.clone()).await.unwrap();
        // Session entry should be gone.
        assert!(!p.state.lock().unwrap().upload_sessions.contains_key(&sid));
    }

    #[tokio::test]
    async fn stream_roundtrip() {
        // Alias kept for backward compatibility with the test name.
        // Delegates to the small-file path.
        let meta = session_finish_resp("id:xyz", "rev789", "large.bin");
        let p = make_provider(vec![(200, session_start_resp()), (200, meta)]);
        let sid = p
            .upload_stream_open(None, "large.bin".into(), 6, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hel".to_vec())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"lo!".to_vec())
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.ref_, "id:xyz");
        assert_eq!(result.version, "rev789");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![(200, b"streamed data".to_vec())]);
        let sid = p.download_stream_open("id:abc".into()).await.unwrap();
        let chunk1 = p.download_stream_read(sid.clone()).await.unwrap();
        let chunk2 = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk1, Some(b"streamed data".to_vec()));
        assert_eq!(chunk2, None);
        p.download_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn no_token_returns_unauthorized() {
        let p = DropboxProvider::new(MockHttp::new(vec![]));
        let err = p.download("id:x".into()).await.unwrap_err();
        assert!(matches!(err, ProviderError::Unauthorized));
    }

    /// Recording mock that captures the exact headers sent on each request.
    /// Used to verify Dropbox's Range-request header construction.
    struct RecordingHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        recorded_requests: Mutex<Vec<ProviderHttpRequest>>,
    }

    impl RecordingHttp {
        fn new(responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> Self {
            Self {
                responses: Mutex::new(responses),
                recorded_requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl ProviderHttpClient for RecordingHttp {
        fn request(
            &self,
            req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            self.recorded_requests.lock().unwrap().push(req);
            let response = self
                .responses
                .lock()
                .unwrap()
                .drain(0..1)
                .next()
                .unwrap_or((500, b"no response".to_vec(), vec![]));
            async move {
                Ok(ProviderHttpResponse {
                    status: response.0,
                    headers: response.2,
                    body: response.1,
                })
            }
        }
    }

    #[tokio::test]
    async fn dropbox_download_range_headers_correctly_formed() {
        // Verifies the critical Dropbox-API-Arg + Range + Bearer headers on a
        // POST /files/download range request. Dropbox accepts Range on this
        // POST endpoint per their official API documentation.
        //
        // Retains an Arc to the RecordingHttp so we can inspect the captured
        // request after the provider has consumed it.
        use std::sync::Arc;
        let http = Arc::new(RecordingHttp::new(vec![(
            206,
            b"chunk".to_vec(),
            vec![("Content-Range".to_string(), "bytes 0-4/5".to_string())],
        )]));
        // Private field access: this test is inside the same module.
        let p: DropboxProvider<RecordingHttp> = DropboxProvider {
            http: Arc::clone(&http),
            state: Arc::new(Mutex::new(DropboxState {
                access_token: Some("tok-abc".to_string()),
                refresh_token: None,
                token_expiry: None,
                client_id: None,
                upload_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        };

        let ref_path = "/folder/file.bin";
        let sid = p.download_stream_open(ref_path.to_string()).await.unwrap();
        let _ = p.download_stream_read(sid.clone()).await.unwrap();
        p.download_stream_close(sid).await.unwrap();

        let requests = http.recorded_requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "exactly one download request was issued");
        let req = &requests[0];

        // Method: POST (Dropbox download uses POST, not GET).
        assert_eq!(req.method, "POST", "Dropbox download must be POST");
        // URL: content.dropboxapi.com/2/files/download.
        assert!(
            req.url.ends_with("/2/files/download"),
            "url was: {}",
            req.url
        );

        let header = |name: &str| -> Option<String> {
            req.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };

        // Bearer token carries auth.
        assert_eq!(header("Authorization"), Some("Bearer tok-abc".to_string()));
        // Dropbox-API-Arg carries the file path (ZK-6 note: path is a blob
        // ref from the vault, not a user-visible plaintext filename).
        let api_arg = header("Dropbox-API-Arg").expect("Dropbox-API-Arg header missing");
        assert!(
            api_arg.contains(ref_path),
            "Dropbox-API-Arg did not contain path: {api_arg}"
        );
        // Range header specifies the chunk.
        let range = header("range").expect("range header missing");
        assert!(
            range.starts_with("bytes=0-"),
            "range should start at byte 0: {range}"
        );
    }
}
