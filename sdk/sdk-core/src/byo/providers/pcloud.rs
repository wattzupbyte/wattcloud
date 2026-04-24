// PCloudProvider — BYO storage backend for pCloud.
//
// Design notes:
//   - Auth: Bearer token in Authorization header (no auto-refresh).
//   - Refs: absolute file PATHS (e.g. `/WattcloudVault/data/file.bin`).
//   - Version: `hash` field from metadata (numeric u64 → String).
//   - Conflict: stat-before-write check when expected_version is set.
//   - All API calls are HTTP GET with query parameters (pCloud convention).
//     Uploads use POST with body.
//   - Streaming uploads: buffer-then-upload (same UploadBuffer pattern).
//   - Streaming downloads: RangedDownloadBuffer — getfilelink resolves a CDN URL
//     at open time, then 8 MiB Range requests are issued against the CDN URL.
//     CDN URLs have a short validity window; a long download may fail with 401/403
//     if the URL expires mid-stream. Caller must re-open the download to refresh.
//   - WattcloudVault root: `/WattcloudVault` — created at init().
//   - Mutex is never held across .await points.
//   - Region: "us" → https://api.pcloud.com, "eu" → https://eapi.pcloud.com.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    bearer, make_http_call_fn, map_http_status, new_stream_id, parse_json, MakeHeaders,
    RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const API_BASE_US: &str = "https://api.pcloud.com";
const API_BASE_EU: &str = "https://eapi.pcloud.com";
const PCLOUD_ROOT: &str = "/WattcloudVault";

// ─── State ────────────────────────────────────────────────────────────────────

/// In-progress buffer-then-upload session.
struct UploadBuffer {
    /// Absolute destination path of the file (e.g. `/WattcloudVault/data/file.bin`).
    path: String,
    /// Upload options (conflict version, etc.).
    options: UploadOptions,
}

/// Accumulated bytes for a buffered upload.
struct UploadBufferData {
    meta: UploadBuffer,
    data: Vec<u8>,
}

struct PCloudState {
    api_base: String,
    access_token: Option<String>,
    upload_buffers: HashMap<String, UploadBufferData>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
    /// Per-stream metadata needed to refresh the pCloud CDN URL when it
    /// expires (~10-15 min). Keyed by the same stream_id as download_buffers.
    download_refresh: HashMap<String, PCloudDownloadRefresh>,
}

/// Metadata required to re-issue a `getfilelink` call and refresh an expired
/// CDN URL for an in-flight download.
struct PCloudDownloadRefresh {
    ref_: String,
    token: String,
    api_base: String,
}

// ─── Provider ─────────────────────────────────────────────────────────────────

pub struct PCloudProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<PCloudState>>,
}

impl<H: ProviderHttpClient> PCloudProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(PCloudState {
                api_base: API_BASE_US.to_string(),
                access_token: None,
                upload_buffers: HashMap::new(),
                download_buffers: HashMap::new(),
                download_refresh: HashMap::new(),
            })),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Percent-encode a string for use in pCloud query parameters.
/// Preserves path separators (`/`) so full paths can be passed directly.
fn percent_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '/' => {
                encoded.push(c);
            }
            _ => {
                for b in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    encoded
}

/// Return the API base URL for a pCloud region string.
fn api_base_for_region(region: Option<&str>) -> &'static str {
    match region {
        Some("eu") => API_BASE_EU,
        _ => API_BASE_US,
    }
}

/// Extract the pCloud file/folder hash as a String.
/// pCloud returns `hash` as a numeric u64 in most contexts.
fn parse_pcloud_hash(meta: &serde_json::Value) -> String {
    // hash may be a number or a string
    if let Some(n) = meta.get("hash").and_then(|h| h.as_u64()) {
        return n.to_string();
    }
    meta.get("hash")
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parse a pCloud modified timestamp (RFC 2822-like: "Mon, 01 Jan 2024 00:00:00 +0000")
/// or ISO 8601 to Unix milliseconds. Best-effort; returns None if unparsable.
fn parse_pcloud_modified(meta: &serde_json::Value) -> Option<i64> {
    let s = meta.get("modified").and_then(|v| v.as_str())?;
    // pCloud uses RFC 2822 format. Delegate to the gdrive helper which handles ISO 8601.
    // For RFC 2822 we do a best-effort parse: try ISO 8601 first, fall back to None.
    crate::byo::providers::gdrive::parse_rfc3339_ms(s)
}

/// Check a pCloud JSON response for a non-zero `result` error code.
/// Returns `Ok(value)` on `result == 0`, or an appropriate `ProviderError`.
/// Resolve a pCloud CDN URL via `getfilelink`. Short-lived (~10-15 min).
///
/// Callable at stream-open time and as a mid-stream refresh on 401/403.
async fn fetch_pcloud_cdn_url<H: ProviderHttpClient>(
    http: &H,
    ref_: &str,
    token: &str,
    api_base: &str,
) -> Result<String, ProviderError> {
    let link_url = format!("{}/getfilelink?path={}", api_base, percent_encode(ref_));
    let req = ProviderHttpRequest::get(link_url).header(bearer(token));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let data = parse_json(&resp.body)?;
    check_pcloud_result(&data)?;

    let hosts = data
        .get("hosts")
        .and_then(|h| h.as_array())
        .ok_or(ProviderError::InvalidResponse)?;
    let host = hosts
        .first()
        .and_then(|h| h.as_str())
        .ok_or(ProviderError::InvalidResponse)?;
    let file_path = data
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or(ProviderError::InvalidResponse)?;
    let cdn_url = format!("https://{}{}", host, file_path);
    // P6/SSRF: `hosts[0]` is attacker-controlled (a hostile or compromised
    // pCloud account can return any host). Without the guard, a `hosts` of
    // `["169.254.169.254"]` would make every subsequent Range request hit
    // the cloud-metadata service. pCloud's real CDN lives under *.pcloud.com
    // and *.pcloud.link; restrict to those suffixes.
    super::url_guard::validate_response_url(&cdn_url, &["pcloud.com", "pcloud.link"])?;
    Ok(cdn_url)
}

fn check_pcloud_result(v: &serde_json::Value) -> Result<(), ProviderError> {
    let code = v.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
    match code {
        0 => Ok(()),
        2009 | 2005 => Err(ProviderError::NotFound),
        1000 | 2000 => Err(ProviderError::Unauthorized),
        _ => {
            let msg = v
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown pCloud error");
            Err(ProviderError::Provider(format!(
                "pCloud error {code}: {msg}"
            )))
        }
    }
}

/// Ensure the WattcloudVault root folder exists.
async fn pcloud_ensure_root<H: ProviderHttpClient>(
    http: &H,
    base: &str,
    token: &str,
) -> Result<(), ProviderError> {
    let url = format!("{}/createfolder?path={}", base, percent_encode(PCLOUD_ROOT));
    let req = ProviderHttpRequest::get(url).header(bearer(token));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let data = parse_json(&resp.body)?;
    let code = data.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
    // 0 = created, 2004 = already exists — both are fine.
    if code != 0 && code != 2004 {
        return check_pcloud_result(&data);
    }
    Ok(())
}

/// GET a pCloud stat for `path`. Returns the metadata object.
async fn pcloud_stat<H: ProviderHttpClient>(
    http: &H,
    base: &str,
    token: &str,
    path: &str,
) -> Result<serde_json::Value, ProviderError> {
    let url = format!("{}/stat?path={}", base, percent_encode(path));
    let req = ProviderHttpRequest::get(url).header(bearer(token));
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let data = parse_json(&resp.body)?;
    check_pcloud_result(&data)?;
    data.get("metadata")
        .cloned()
        .ok_or(ProviderError::InvalidResponse)
}

/// Upload bytes to `path` using the pCloud `/uploadfile` endpoint.
/// `path` must be an absolute path like `/WattcloudVault/data/file.bin`.
async fn pcloud_upload<H: ProviderHttpClient>(
    http: &H,
    base: &str,
    token: &str,
    path: &str,
    data: Vec<u8>,
    expected_version: Option<&str>,
) -> Result<UploadResult, ProviderError> {
    // Split path into folder + filename.
    let (folder, filename) = match path.rfind('/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => ("/", path),
    };
    let folder = if folder.is_empty() { "/" } else { folder };

    // Conflict check: stat first if expected_version is set.
    if let Some(expected) = expected_version {
        let meta = pcloud_stat(http, base, token, path).await;
        match meta {
            Ok(m) => {
                let current = parse_pcloud_hash(&m);
                if current != expected {
                    return Err(ProviderError::Conflict {
                        current_version: current,
                    });
                }
            }
            Err(ProviderError::NotFound) => {
                // File doesn't exist yet — allow the upload (treat as new).
            }
            Err(e) => return Err(e),
        }
    }

    let url = format!(
        "{}/uploadfile?path={}&filename={}&nopartial=1&renameifexists=0",
        base,
        percent_encode(folder),
        percent_encode(filename),
    );
    let req = ProviderHttpRequest::post(url)
        .header(bearer(token))
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
        .body(data);
    let resp = http.request(req).await?;
    if let Some(e) = map_http_status(resp.status, &resp.body) {
        return Err(e);
    }
    let data = parse_json(&resp.body)?;
    check_pcloud_result(&data)?;

    // Response: {"result":0,"metadata":[{"hash":N,...,"name":"...","path":"..."}]}
    let meta_arr = data
        .get("metadata")
        .and_then(|m| m.as_array())
        .ok_or(ProviderError::InvalidResponse)?;
    let meta = meta_arr.first().ok_or(ProviderError::InvalidResponse)?;
    let file_path = meta
        .get("path")
        .and_then(|p| p.as_str())
        .unwrap_or(path)
        .to_string();
    let version = parse_pcloud_hash(meta);

    Ok(UploadResult {
        ref_: file_path,
        version,
    })
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for PCloudProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pcloud
    }

    fn display_name(&self) -> String {
        "pCloud".to_string()
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
        let region = if s.api_base == API_BASE_EU {
            Some("eu".to_string())
        } else {
            Some("us".to_string())
        };
        ProviderConfig {
            type_: ProviderType::Pcloud,
            access_token: s.access_token.clone(),
            pcloud_region: region,
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
            let base = api_base_for_region(config.pcloud_region.as_deref()).to_string();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token = Some(token.clone());
                s.api_base = base.clone();
            }
            pcloud_ensure_root(&*http, &base, &token).await?;
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
            s.upload_buffers.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    async fn refresh_auth(&self) -> Result<(), ProviderError> {
        // pCloud tokens are refreshed externally.
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };

            // `ref_` is the full path for pCloud overwrites; None means new file.
            let path = match ref_.as_deref().filter(|r| !r.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    let parent = options
                        .parent_ref
                        .as_deref()
                        .filter(|r| !r.is_empty())
                        .unwrap_or(PCLOUD_ROOT);
                    format!("{}/{}", parent.trim_end_matches('/'), name)
                }
            };

            pcloud_upload(
                &*http,
                &base,
                &token,
                &path,
                data,
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };

            // Step 1: get a download link.
            let link_url = format!("{}/getfilelink?path={}", base, percent_encode(&ref_));
            let req = ProviderHttpRequest::get(link_url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            check_pcloud_result(&data)?;

            let hosts = data
                .get("hosts")
                .and_then(|h| h.as_array())
                .ok_or(ProviderError::InvalidResponse)?;
            let host = hosts
                .first()
                .and_then(|h| h.as_str())
                .ok_or(ProviderError::InvalidResponse)?;
            let file_path = data
                .get("path")
                .and_then(|p| p.as_str())
                .ok_or(ProviderError::InvalidResponse)?;

            // Step 2: download from CDN host.
            // B8: validate the pCloud-supplied CDN URL before issuing the GET
            // so a hostile `getfilelink` response can't redirect us to an
            // internal / metadata-service host. The streaming path already
            // does this via `fetch_pcloud_cdn_url` → `validate_response_url`;
            // the non-streaming path missed the check.
            let cdn_url = format!("https://{}{}", host, file_path);
            super::url_guard::validate_response_url(&cdn_url, &["pcloud.com", "pcloud.link"])?;
            let cdn_req = ProviderHttpRequest::get(cdn_url);
            let cdn_resp = http.request(cdn_req).await?;
            if let Some(e) = map_http_status(cdn_resp.status, &cdn_resp.body) {
                return Err(e);
            }
            Ok(cdn_resp.body)
        }
    }

    fn delete(&self, ref_: String) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };
            let url = format!("{}/deletefile?path={}", base, percent_encode(&ref_));
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            let code = data.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
            // 0 = deleted, 2009 = not found — both acceptable for idempotent delete.
            if code != 0 && code != 2009 {
                return check_pcloud_result(&data);
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };
            let meta = pcloud_stat(&*http, &base, &token, &ref_).await?;
            Ok(parse_pcloud_hash(&meta))
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
        let state = Arc::clone(&self.state);
        async move {
            let _token = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.access_token.clone().ok_or(ProviderError::Unauthorized)?
            };

            let path = match ref_.as_deref().filter(|r| !r.is_empty()) {
                Some(p) => p.to_string(),
                None => {
                    let parent = options
                        .parent_ref
                        .as_deref()
                        .filter(|r| !r.is_empty())
                        .unwrap_or(PCLOUD_ROOT);
                    format!("{}/{}", parent.trim_end_matches('/'), name)
                }
            };

            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.upload_buffers.insert(
                    stream_id.clone(),
                    UploadBufferData {
                        meta: UploadBuffer { path, options },
                        data: Vec::new(),
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
            let (token, base, buf) = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                let base = s.api_base.clone();
                let buf = s.upload_buffers.remove(&stream_id).ok_or_else(|| {
                    ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                })?;
                (tok, base, buf)
            };

            pcloud_upload(
                &*http,
                &base,
                &token,
                &buf.meta.path,
                buf.data,
                buf.meta.options.expected_version.as_deref(),
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };

            // Step 1: getfilelink → CDN URL (short-lived ~10-15 min).
            let cdn_url = fetch_pcloud_cdn_url(&*http, &ref_, &token, &base).await?;

            // Step 2: build RangedDownloadBuffer over the CDN URL. The CDN URL
            // carries its own auth (short-lived signed URL); no Bearer header needed.
            let make_headers: MakeHeaders = Arc::new(move |offset: u64, end: u64| {
                vec![("Range".to_string(), format!("bytes={offset}-{end}"))]
            });
            let http_call = make_http_call_fn(Arc::clone(&http));
            let buf = RangedDownloadBuffer::new(cdn_url, "GET", None, make_headers, http_call);
            let stream_id = new_stream_id();
            {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                s.download_buffers.insert(stream_id.clone(), buf);
                // Persist the metadata needed to refresh the CDN URL if it
                // expires mid-stream.
                s.download_refresh.insert(
                    stream_id.clone(),
                    PCloudDownloadRefresh {
                        ref_: ref_.clone(),
                        token,
                        api_base: base,
                    },
                );
            }
            Ok(stream_id)
        }
    }

    fn download_stream_read(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ProviderError>> {
        let http = Arc::clone(&self.http);
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

            // pCloud CDN URLs expire after ~10-15 min. A 401/403 mid-stream on
            // the CDN URL almost always means the URL expired. Auto-refresh once:
            // re-run `getfilelink`, update the buffer's URL, and retry the same
            // Range request. A second 401/403 is a real auth failure.
            if resp.status == 401 || resp.status == 403 {
                let refresh = {
                    let s = state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                    s.download_refresh
                        .get(&stream_id)
                        .map(|r| PCloudDownloadRefresh {
                            ref_: r.ref_.clone(),
                            token: r.token.clone(),
                            api_base: r.api_base.clone(),
                        })
                };
                let refresh = refresh.ok_or_else(|| {
                    ProviderError::Provider(
                        "pCloud stream has no refresh metadata — re-open the download".to_string(),
                    )
                })?;
                let fresh_url =
                    fetch_pcloud_cdn_url(&*http, &refresh.ref_, &refresh.token, &refresh.api_base)
                        .await?;
                // Update the buffer's URL. Rebuild the request with the fresh URL.
                let retry_req = {
                    let mut s = state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                    let buf = s.download_buffers.get_mut(&stream_id).ok_or_else(|| {
                        ProviderError::Provider(format!("unknown stream_id: {stream_id}"))
                    })?;
                    buf.url = fresh_url;
                    // Re-compose the Range request at the same offset (the failed
                    // request didn't advance the buffer).
                    match buf.next_request() {
                        None => return Ok(None),
                        Some((req, _size)) => req,
                    }
                };
                let retry_resp = http_call(retry_req).await?;
                if retry_resp.status == 401 || retry_resp.status == 403 {
                    return Err(ProviderError::Unauthorized);
                }
                let content_range = retry_resp.header("content-range").map(str::to_owned);
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                return match s.download_buffers.get_mut(&stream_id) {
                    None => Ok(None),
                    Some(buf) => buf.apply_response(
                        retry_resp.status,
                        retry_resp.body,
                        content_range.as_deref(),
                        requested,
                    ),
                };
            }

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
            s.download_refresh.remove(&stream_id);
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };

            let folder_path = parent_ref
                .as_deref()
                .filter(|p| !p.is_empty())
                .unwrap_or(PCLOUD_ROOT);

            let url = format!(
                "{}/listfolder?path={}&noshares=1",
                base,
                percent_encode(folder_path)
            );
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            check_pcloud_result(&data)?;

            let contents = data
                .get("metadata")
                .and_then(|m| m.get("contents"))
                .and_then(|c| c.as_array())
                .ok_or(ProviderError::InvalidResponse)?;

            let mut result = Vec::with_capacity(contents.len());
            for item in contents {
                let is_folder = item
                    .get("isfolder")
                    .and_then(|f| f.as_bool())
                    .unwrap_or(false);
                let name = item
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let ref_ = item
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = item.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                let modified_at = parse_pcloud_modified(item);
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
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };

            let parent = parent_ref
                .as_deref()
                .filter(|p| !p.is_empty())
                .unwrap_or(PCLOUD_ROOT);
            let new_path = format!("{}/{}", parent.trim_end_matches('/'), name);

            let url = format!("{}/createfolder?path={}", base, percent_encode(&new_path));
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            let code = data.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
            // 0 = created, 2004 = already exists — return the path in both cases.
            if code != 0 && code != 2004 {
                check_pcloud_result(&data)?;
            }
            // Return the created/existing folder path as the ref.
            let path = data
                .get("metadata")
                .and_then(|m| m.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or(&new_path)
                .to_string();
            Ok(path)
        }
    }

    fn delete_folder(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (token, base) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let tok = s.access_token.clone().ok_or(ProviderError::Unauthorized)?;
                (tok, s.api_base.clone())
            };
            let url = format!(
                "{}/deletefolderrecursive?path={}",
                base,
                percent_encode(&ref_)
            );
            let req = ProviderHttpRequest::get(url).header(bearer(&token));
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let data = parse_json(&resp.body)?;
            let code = data.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
            // 0 = deleted, 2005 = not found — both OK.
            if code != 0 && code != 2005 {
                return check_pcloud_result(&data);
            }
            Ok(())
        }
    }

    // ── Share link (P10) — stub ───────────────────────────────────────────────

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for pcloud".into(),
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
            "Presigned URLs not yet implemented for pcloud".into(),
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

    fn make_provider(responses: Vec<(u16, Vec<u8>)>) -> PCloudProvider<MockHttp> {
        let p = PCloudProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.access_token = Some("test_token".to_string());
            s.api_base = API_BASE_US.to_string();
        }
        p
    }

    fn upload_resp(path: &str, hash: u64) -> Vec<u8> {
        serde_json::json!({
            "result": 0,
            "metadata": [{ "path": path, "hash": hash, "name": "file.bin" }]
        })
        .to_string()
        .into_bytes()
    }

    fn getfilelink_resp(host: &str, path: &str) -> Vec<u8> {
        serde_json::json!({
            "result": 0,
            "hosts": [host],
            "path": path,
            "metadata": { "hash": 12345_u64 }
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn upload_returns_ref_and_version() {
        let path = "/WattcloudVault/file.bin";
        let p = make_provider(vec![(200, upload_resp(path, 99))]);
        let result = p
            .upload(
                None,
                "file.bin".into(),
                b"data".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.ref_, path);
        assert_eq!(result.version, "99");
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
        // Response 1: getfilelink; Response 2: CDN bytes
        let p = make_provider(vec![
            (200, getfilelink_resp("c1.pcloud.com", "/dl/abc")),
            (200, b"file bytes".to_vec()),
        ]);
        let data = p.download("/WattcloudVault/file.bin".into()).await.unwrap();
        assert_eq!(data, b"file bytes");
    }

    #[tokio::test]
    async fn upload_stream_roundtrip() {
        let path = "/WattcloudVault/big.bin";
        let p = make_provider(vec![(200, upload_resp(path, 42))]);
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
        assert_eq!(result.ref_, path);
        assert_eq!(result.version, "42");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![
            (200, getfilelink_resp("c1.pcloud.com", "/dl/xyz")),
            (200, b"streamed".to_vec()),
        ]);
        let sid = p
            .download_stream_open("/WattcloudVault/file.bin".into())
            .await
            .unwrap();
        let chunk = p.download_stream_read(sid.clone()).await.unwrap();
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk, Some(b"streamed".to_vec()));
        assert_eq!(eof, None);
        p.download_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn percent_encode_spaces_and_specials() {
        assert_eq!(
            percent_encode("/WattcloudVault/my file.bin"),
            "/WattcloudVault/my%20file.bin"
        );
        assert_eq!(percent_encode("/foo/bar"), "/foo/bar");
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[tokio::test]
    async fn download_stream_auto_refreshes_cdn_url_on_403() {
        // pCloud CDN URLs expire after ~10-15 min. On mid-stream 403, the
        // provider must call getfilelink again, swap the CDN URL in the
        // buffer, and retry the same Range request once.
        let p = make_provider(vec![
            // 1. initial getfilelink — returns first CDN URL
            (200, getfilelink_resp("c1.pcloud.com", "/dl/first")),
            // 2. first chunk request to the CDN URL — expired, returns 403
            (403, b"url expired".to_vec()),
            // 3. refresh: second getfilelink — returns fresh CDN URL
            (200, getfilelink_resp("c2.pcloud.com", "/dl/fresh")),
            // 4. retry chunk request on the fresh URL — succeeds
            (206, b"streamed-data".to_vec()),
        ]);
        let sid = p
            .download_stream_open("/WattcloudVault/file.bin".into())
            .await
            .unwrap();
        let chunk = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(
            chunk,
            Some(b"streamed-data".to_vec()),
            "retry after refresh must succeed"
        );
        p.download_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn download_stream_surface_unauthorized_after_second_403() {
        // If refresh also fails with 401/403, that's a real auth error —
        // surface it rather than looping indefinitely.
        let p = make_provider(vec![
            (200, getfilelink_resp("c1.pcloud.com", "/dl/first")),
            (403, b"expired".to_vec()),
            (200, getfilelink_resp("c2.pcloud.com", "/dl/fresh")),
            (403, b"actually forbidden".to_vec()),
        ]);
        let sid = p
            .download_stream_open("/WattcloudVault/file.bin".into())
            .await
            .unwrap();
        let err = p.download_stream_read(sid.clone()).await.unwrap_err();
        assert!(matches!(err, ProviderError::Unauthorized), "got {err:?}");
        p.download_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn download_stream_close_clears_refresh_state() {
        // Regression: verify download_refresh is wiped on close.
        let p = make_provider(vec![(200, getfilelink_resp("c1.pcloud.com", "/dl/first"))]);
        let sid = p
            .download_stream_open("/WattcloudVault/file.bin".into())
            .await
            .unwrap();
        {
            let s = p.state.lock().unwrap();
            assert!(s.download_refresh.contains_key(&sid));
        }
        p.download_stream_close(sid.clone()).await.unwrap();
        let s = p.state.lock().unwrap();
        assert!(
            !s.download_refresh.contains_key(&sid),
            "refresh state must be cleaned up"
        );
    }
}
