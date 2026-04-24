// BoxProvider — BYO storage backend for Box.
//
// Design notes:
//   - Auth: Bearer token (no auto-refresh; returns Unauthorized on expiry).
//   - Refs: Box item IDs (opaque strings).
//   - Version: `etag` field on Box file objects.
//   - Conflict detection: If-Match header → 409 from Box.
//   - Upload: multipart/form-data built manually (no multipart crate in sdk-core).
//   - Streaming uploads: buffer-then-upload (UploadBuffer pattern).
//   - Streaming downloads: RangedDownloadBuffer (8 MiB Range requests).
//   - WattcloudVault folder: created under Box root (id="0") at init(); ID cached.
//   - Mutex is never held across .await points.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    bearer, bearer_range_headers, make_http_call_fn, map_http_status, new_stream_id, parse_json,
    RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const API_BASE: &str = "https://api.box.com/2.0";
const UPLOAD_BASE: &str = "https://upload.box.com/api/2.0";
const BOX_ROOT_FOLDER_ID: &str = "0";
const MULTIPART_BOUNDARY: &str = "BoxBoundary12345678";

// ─── State ────────────────────────────────────────────────────────────────────

/// In-progress buffer-then-upload session.
struct UploadBuffer {
    /// Box folder ID of the destination parent.
    parent_id: String,
    /// Display filename for the multipart form.
    name: String,
    /// Accumulated bytes.
    data: Vec<u8>,
    /// Upload options (conflict version, etc.).
    options: UploadOptions,
    /// If Some, this is an overwrite of an existing file with this Box ID.
    existing_file_id: Option<String>,
}

struct BoxState {
    access_token: Option<String>,
    /// Cached Box item ID of the "WattcloudVault" folder.
    root_folder_id: Option<String>,
    upload_buffers: HashMap<String, UploadBuffer>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

// ─── Provider ─────────────────────────────────────────────────────────────────

pub struct BoxProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<BoxState>>,
}

impl<H: ProviderHttpClient> BoxProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(BoxState {
                access_token: None,
                root_folder_id: None,
                upload_buffers: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// P9: reject control characters (including CR/LF) in the filename used inside
/// Content-Disposition. Without this, a malicious or fat-fingered filename
/// containing `\r\n` could inject additional MIME headers into the multipart
/// body and smuggle attributes into the Box payload. BYO invariant ZK-6
/// requires filenames here be opaque UUIDs, so any control byte is certainly
/// a bug.
fn validate_multipart_filename(filename: &str) -> Result<(), ProviderError> {
    if filename.is_empty() {
        return Err(ProviderError::Provider("filename must not be empty".into()));
    }
    for c in filename.chars() {
        if (c as u32) < 0x20 || c == '"' || c == '\\' {
            return Err(ProviderError::Provider(
                "filename contains disallowed control or quote character".into(),
            ));
        }
    }
    Ok(())
}

/// Build a raw multipart/form-data body for Box file upload.
///
/// Returns an error if `filename` contains any byte that would break the
/// Content-Disposition header (see `validate_multipart_filename`).
fn build_multipart(
    boundary: &str,
    attributes_json: &str,
    filename: &str,
    data: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    validate_multipart_filename(filename)?;
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"attributes\"\r\nContent-Type: application/json\r\n\r\n{}\r\n",
            boundary, attributes_json
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            boundary, filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    Ok(body)
}

/// Extract `etag` from a Box file/folder JSON object.
fn parse_box_etag(v: &serde_json::Value) -> String {
    v.get("etag")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract `id` from a Box JSON object.
fn parse_box_id(v: &serde_json::Value) -> String {
    v.get("id")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parse a Box RFC 3339 / ISO 8601 timestamp to Unix milliseconds.
fn parse_box_modified(v: &serde_json::Value) -> Option<i64> {
    let s = v.get("modified_at").and_then(|e| e.as_str())?;
    crate::byo::providers::gdrive::parse_rfc3339_ms(s)
}

/// Find or create the "WattcloudVault" folder directly inside Box root (id="0").
/// Returns the Box folder ID string.
async fn box_ensure_root<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    state: &Arc<Mutex<BoxState>>,
) -> Result<String, ProviderError> {
    // Fast-path: already cached.
    {
        let s = state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
        if let Some(id) = &s.root_folder_id {
            return Ok(id.clone());
        }
    }

    // Try to create; 409 means it already exists — find it via list.
    let body = serde_json::json!({
        "name": "WattcloudVault",
        "parent": { "id": BOX_ROOT_FOLDER_ID }
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
    let req = ProviderHttpRequest::post(format!("{}/folders", API_BASE))
        .header(bearer(token))
        .header(("Content-Type".to_string(), "application/json".to_string()))
        .body(body_bytes);
    let resp = http.request(req).await?;

    let folder_id = if resp.status == 409 {
        // Folder already exists — enumerate root children to find it.
        let list_url = format!(
            "{}/folders/{}/items?fields=id,name,type&limit=1000",
            API_BASE, BOX_ROOT_FOLDER_ID
        );
        let list_req = ProviderHttpRequest::get(list_url).header(bearer(token));
        let list_resp = http.request(list_req).await?;
        if let Some(e) = map_http_status(list_resp.status, &list_resp.body) {
            return Err(e);
        }
        let data = parse_json(&list_resp.body)?;
        let entries = data
            .get("entries")
            .and_then(|e| e.as_array())
            .ok_or(ProviderError::InvalidResponse)?;
        entries
            .iter()
            .find(|e| {
                e.get("type").and_then(|t| t.as_str()) == Some("folder")
                    && e.get("name").and_then(|n| n.as_str()) == Some("WattcloudVault")
            })
            .map(parse_box_id)
            .filter(|id| !id.is_empty())
            .ok_or(ProviderError::InvalidResponse)?
    } else {
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let meta = parse_json(&resp.body)?;
        let id = parse_box_id(&meta);
        if id.is_empty() {
            return Err(ProviderError::InvalidResponse);
        }
        id
    };

    {
        let mut s = state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
        s.root_folder_id = Some(folder_id.clone());
    }
    Ok(folder_id)
}

/// Perform a Box file upload (new or overwrite) and return (file_id, etag).
async fn box_upload_file<H: ProviderHttpClient>(
    http: &H,
    token: &str,
    parent_folder_id: &str,
    existing_file_id: Option<&str>,
    filename: &str,
    data: &[u8],
    expected_version: Option<&str>,
) -> Result<UploadResult, ProviderError> {
    let attributes_json = match existing_file_id {
        Some(_) => {
            // Overwrite: attributes only need the name
            serde_json::json!({ "name": filename }).to_string()
        }
        None => serde_json::json!({
            "name": filename,
            "parent": { "id": parent_folder_id }
        })
        .to_string(),
    };

    let body = build_multipart(MULTIPART_BOUNDARY, &attributes_json, filename, data)?;
    let content_type = format!("multipart/form-data; boundary={}", MULTIPART_BOUNDARY);

    let url = match existing_file_id {
        Some(file_id) => format!("{}/files/{}/content", UPLOAD_BASE, file_id),
        None => format!("{}/files/content", UPLOAD_BASE),
    };

    let mut req = ProviderHttpRequest::post(url)
        .header(bearer(token))
        .header(("Content-Type".to_string(), content_type))
        .body(body);

    if let Some(etag) = expected_version {
        req = req.header(("If-Match".to_string(), etag.to_string()));
    }

    let resp = http.request(req).await?;

    if resp.status == 409 {
        // Extract current version from conflict response body if available.
        let version = parse_json(&resp.body)
            .ok()
            .and_then(|v| {
                // Box 409 conflict body: {"context_info":{"conflicts":{"etag":"..."}}}
                v.get("context_info")
                    .and_then(|ci| ci.get("conflicts"))
                    .and_then(|c| c.get("etag"))
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        return Err(ProviderError::Conflict {
            current_version: version,
        });
    }
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }

    let meta = parse_json(&resp.body)?;

    // New file upload: `{"entries":[{"id":"...","etag":"..."}]}`
    // Overwrite upload:  `{"id":"...","etag":"..."}`
    let file_obj = if let Some(entries) = meta.get("entries").and_then(|e| e.as_array()) {
        entries
            .first()
            .ok_or(ProviderError::InvalidResponse)?
            .clone()
    } else {
        meta
    };

    Ok(UploadResult {
        ref_: parse_box_id(&file_obj),
        version: parse_box_etag(&file_obj),
    })
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for BoxProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Box
    }

    fn display_name(&self) -> String {
        "Box".to_string()
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
            type_: ProviderType::Box,
            access_token: s.access_token.clone(),
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
            let token = config.access_token.ok_or(ProviderError::Unauthorized)?;
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token = Some(token.clone());
                s.root_folder_id = None;
            }
            // Eagerly ensure the WattcloudVault folder exists.
            box_ensure_root(&*http, &token, &state).await?;
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
            s.root_folder_id = None;
            s.upload_buffers.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    async fn refresh_auth(&self) -> Result<(), ProviderError> {
        // Box tokens are refreshed externally via the Box OAuth flow.
        Ok(())
    }

    // ── File operations ──────────────────────────────────────────────────────

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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let fid = s.root_folder_id.clone();
                (tok, fid)
            };

            // Resolve or re-fetch WattcloudVault folder ID.
            let parent_folder_id = match root_folder_id {
                Some(id) => id,
                None => box_ensure_root(&*http, &token, &state).await?,
            };

            // `ref_` is a Box file ID for overwrites; None means new upload.
            let existing_file_id = ref_.as_deref().filter(|r| !r.is_empty());
            let parent_id = options
                .parent_ref
                .as_deref()
                .filter(|r| !r.is_empty())
                .unwrap_or(&parent_folder_id);

            box_upload_file(
                &*http,
                &token,
                parent_id,
                existing_file_id,
                &name,
                &data,
                options.expected_version.as_deref(),
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
            let token = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            // GET /files/{id}/content follows the redirect and returns the bytes.
            let url = format!("{}/files/{}/content", API_BASE, ref_);
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
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
            let token = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = format!("{}/files/{}", API_BASE, ref_);
            let req = ProviderHttpRequest::delete(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if resp.status == 404 {
                return Ok(()); // Already gone; idempotent.
            }
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };
            let url = format!("{}/files/{}?fields=etag", API_BASE, ref_);
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            Ok(parse_box_etag(&meta))
        }
    }

    // ── Streaming upload (buffer-then-upload) ────────────────────────────────

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
            let (token, root_folder_id) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let fid = s.root_folder_id.clone();
                (tok, fid)
            };

            let parent_folder_id = match root_folder_id {
                Some(id) => id,
                None => box_ensure_root(&*http, &token, &state).await?,
            };

            let resolved_parent = options
                .parent_ref
                .as_deref()
                .filter(|r| !r.is_empty())
                .unwrap_or(&parent_folder_id)
                .to_string();

            let existing_file_id = ref_
                .as_deref()
                .filter(|r| !r.is_empty())
                .map(|s| s.to_string());

            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.upload_buffers.insert(
                    stream_id.clone(),
                    UploadBuffer {
                        parent_id: resolved_parent,
                        name,
                        data: Vec::new(),
                        options,
                        existing_file_id,
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
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            let buf = s.upload_buffers.get_mut(&stream_id).ok_or_else(|| {
                ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
            })?;
            buf.data.extend_from_slice(&chunk);
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
            let (token, buf) = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let buf = s.upload_buffers.remove(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                (tok, buf)
            };

            box_upload_file(
                &*http,
                &token,
                &buf.parent_id,
                buf.existing_file_id.as_deref(),
                &buf.name,
                &buf.data,
                buf.options.expected_version.as_deref(),
            )
            .await
        }
    }

    fn upload_stream_abort(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.upload_buffers.remove(&stream_id);
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
            let url = format!("{}/files/{}/content", API_BASE, ref_);
            // Box redirects (302) to a CDN URL; Range header is preserved through redirect.
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
            let (token, root_folder_id) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let fid = s.root_folder_id.clone();
                (tok, fid)
            };

            let folder_id = match parent_ref {
                Some(ref p) if !p.is_empty() => p.clone(),
                _ => match root_folder_id {
                    Some(id) => id,
                    None => box_ensure_root(&*http, &token, &state).await?,
                },
            };

            let url = format!(
                "{}/folders/{}/items?fields=id,name,size,type,modified_at,etag&limit=1000",
                API_BASE, folder_id
            );
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            let entries = data
                .get("entries")
                .and_then(|e| e.as_array())
                .ok_or(ProviderError::InvalidResponse)?;

            let mut result = Vec::with_capacity(entries.len());
            for item in entries {
                let is_folder = item.get("type").and_then(|t| t.as_str()) == Some("folder");
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ref_ = parse_box_id(item);
                let size = item.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let modified_at = parse_box_modified(item);
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
            let (token, root_folder_id) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let fid = s.root_folder_id.clone();
                (tok, fid)
            };

            let parent_id = match parent_ref {
                Some(ref p) if !p.is_empty() => p.clone(),
                _ => match root_folder_id {
                    Some(id) => id,
                    None => box_ensure_root(&*http, &token, &state).await?,
                },
            };

            let body = serde_json::json!({
                "name": name,
                "parent": { "id": parent_id }
            });
            let body_bytes =
                serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
            let req = ProviderHttpRequest::post(format!("{}/folders", API_BASE))
                .header(bearer(&token))
                .header(("Content-Type".to_string(), "application/json".to_string()))
                .body(body_bytes);
            let resp = http.request(req).await?;

            if resp.status == 409 {
                // Already exists — find it by listing parent.
                let list_url = format!(
                    "{}/folders/{}/items?fields=id,name,type&limit=1000",
                    API_BASE, parent_id
                );
                let list_req = ProviderHttpRequest::get(list_url).header(bearer(&token));
                let list_resp = http.request(list_req).await?;
                if let Some(e) = map_http_status(list_resp.status, &list_resp.body) {
                    return Err(e);
                }
                let data = parse_json(&list_resp.body)?;
                let entries = data
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .ok_or(ProviderError::InvalidResponse)?;
                return entries
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(|t| t.as_str()) == Some("folder")
                            && e.get("name").and_then(|n| n.as_str()) == Some(name.as_str())
                    })
                    .map(parse_box_id)
                    .filter(|id| !id.is_empty())
                    .ok_or(ProviderError::InvalidResponse);
            }

            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let meta = parse_json(&resp.body)?;
            Ok(parse_box_id(&meta))
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
            let url = format!("{}/folders/{}?recursive=true", API_BASE, ref_);
            let req = ProviderHttpRequest::delete(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if resp.status == 404 {
                return Ok(());
            }
            if resp.status != 204 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            Ok(())
        }
    }

    // ── Share link (P10) — stub ───────────────────────────────────────────────

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for box".into(),
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
            "Presigned URLs not yet implemented for box".into(),
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
            Self {
                responses: Mutex::new(r),
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

    fn make_provider(responses: Vec<(u16, Vec<u8>)>) -> BoxProvider<MockHttp> {
        let p = BoxProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.access_token = Some("test_token".to_string());
            s.root_folder_id = Some("folder123".to_string());
        }
        p
    }

    fn file_json(id: &str, etag: &str) -> Vec<u8> {
        // New-file upload response wraps in "entries"
        serde_json::json!({
            "entries": [{ "id": id, "etag": etag, "type": "file" }]
        })
        .to_string()
        .into_bytes()
    }

    fn file_json_update(id: &str, etag: &str) -> Vec<u8> {
        // Overwrite response is a flat object
        serde_json::json!({ "id": id, "etag": etag, "type": "file" })
            .to_string()
            .into_bytes()
    }

    #[tokio::test]
    async fn upload_returns_ref_and_version() {
        let p = make_provider(vec![(201, file_json("file1", "etag1"))]);
        let result = p
            .upload(
                None,
                "test.bin".into(),
                b"hello".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.ref_, "file1");
        assert_eq!(result.version, "etag1");
    }

    #[tokio::test]
    async fn upload_overwrite_returns_ref_and_version() {
        let p = make_provider(vec![(200, file_json_update("file1", "etag2"))]);
        let result = p
            .upload(
                Some("file1".into()),
                "test.bin".into(),
                b"updated".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.ref_, "file1");
        assert_eq!(result.version, "etag2");
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
    async fn download_returns_body() {
        let p = make_provider(vec![(200, b"file content".to_vec())]);
        let data = p.download("file1".into()).await.unwrap();
        assert_eq!(data, b"file content");
    }

    #[tokio::test]
    async fn download_404_not_found() {
        let p = make_provider(vec![(404, b"not found".to_vec())]);
        let err = p.download("missing".into()).await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound));
    }

    #[tokio::test]
    async fn upload_stream_roundtrip() {
        let p = make_provider(vec![(201, file_json("stream1", "etag3"))]);
        let sid = p
            .upload_stream_open(None, "big.bin".into(), 10, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"world".to_vec())
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.ref_, "stream1");
        assert_eq!(result.version, "etag3");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![(200, b"streamed bytes".to_vec())]);
        let sid = p.download_stream_open("file1".into()).await.unwrap();
        let chunk = p.download_stream_read(sid.clone()).await.unwrap();
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk, Some(b"streamed bytes".to_vec()));
        assert_eq!(eof, None);
        p.download_stream_close(sid).await.unwrap();
    }
}
