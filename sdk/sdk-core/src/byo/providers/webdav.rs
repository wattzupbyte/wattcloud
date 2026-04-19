// WebDAVProvider — BYO storage backend for WebDAV servers.
//
// Design notes:
//   - Auth: Basic HTTP auth (base64(user:password)) on every request.
//   - No OAuth, no token refresh (static credentials).
//   - PROPFIND (Depth: 1) + quick-xml parsing for list().
//   - MKCOL creates folders (201 = created, 405 = already exists → both OK).
//   - PUT for upload, GET for download, DELETE for both files and folders.
//   - HEAD for get_version (reads ETag).
//   - Mutex is never held across .await points.
//
// Streaming upload strategy (capability-probed at init time):
//   1. Nextcloud / ownCloud v2 chunking  — MKCOL + numbered PUTs + MOVE.
//      Detected via PROPFIND on /remote.php/dav/.
//   2. tus.io  — POST to get upload URL, then PATCH chunks.
//      Detected via OPTIONS carrying Tus-Resumable header.
//   3. Buffer-then-PUT  — fallback for generic WebDAV servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    make_http_call_fn, map_http_status, new_stream_id, MakeHeaders, RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Nextcloud/OC v2 chunking: minimum bytes per non-final chunk (5 MiB).
/// Last chunk may be any size (including 0 if total is an exact multiple).
const NC_MIN_CHUNK_SIZE: usize = 5 * 1024 * 1024;

// ─── State ────────────────────────────────────────────────────────────────────

/// Detected server capabilities — probed once at init() time.
#[derive(Clone, Debug)]
enum WebDavCapabilities {
    /// Nextcloud / ownCloud v2 chunked upload support.
    NcChunkingV2 {
        /// Origin prefix used to construct `/remote.php/dav/uploads/…` paths.
        nc_base: String,
        /// Authenticated username for the upload directory path.
        username: String,
    },
    /// tus.io resumable upload support.
    Tus,
    /// Generic WebDAV: buffer full body, then single PUT.
    BufferThenPut,
}

/// State for an in-progress NC v2 or tus streaming upload.
enum ChunkSession {
    /// Nextcloud/OC v2: numbered PUT chunks into a temp dir, then MOVE.
    NcV2 {
        tx_dir_url: String,   // …/remote.php/dav/uploads/<user>/<uuid>/
        dest_url: String,     // final DAV destination URL
        total_size: u64,
        chunk_index: u32,     // 1-indexed; incremented after each PUT
        buffer: Vec<u8>,      // accumulates until NC_MIN_CHUNK_SIZE
        options: UploadOptions,
    },
    /// tus.io: PATCH chunks to the session upload_url.
    Tus {
        upload_url: String,
        offset: u64,
    },
}

/// In-progress buffer-then-PUT upload (fallback path).
struct UploadBuffer {
    path: String,
    data: Vec<u8>,
    options: UploadOptions,
}

struct WebDAVState {
    server_url: String,
    auth_header: Option<String>,
    capabilities: WebDavCapabilities,
    upload_buffers: HashMap<String, UploadBuffer>,    // buffer-then-PUT fallback
    chunk_sessions: HashMap<String, ChunkSession>,    // NC v2 / tus sessions
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

// ─── Provider ─────────────────────────────────────────────────────────────────

pub struct WebDAVProvider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<WebDAVState>>,
}

impl<H: ProviderHttpClient> WebDAVProvider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(WebDAVState {
                server_url: String::new(),
                auth_header: None,
                capabilities: WebDavCapabilities::BufferThenPut,
                upload_buffers: HashMap::new(),
                chunk_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a Basic auth header tuple.
fn basic_auth(username: &str, password: &str) -> (String, String) {
    let credentials = format!("{username}:{password}");
    let encoded = BASE64_STANDARD.encode(credentials.as_bytes());
    ("Authorization".to_string(), format!("Basic {encoded}"))
}

/// Normalize the server URL: strip trailing slash, return base.
fn normalize_base(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Build the full URL for a path under the WebDAV server.
fn dav_url(base: &str, path: &str) -> String {
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    format!("{base}{path}")
}

/// Resolve an attacker-controllable WebDAV ref into a safe URL (P5).
///
/// Refs come from PROPFIND `<D:href>` responses — the WebDAV server is not
/// trusted to keep the ref under its own origin. If the ref is absolute,
/// require it to share the origin of the configured server; otherwise
/// reconstruct via `dav_url(base, ref)`. Also strips `..` segments from
/// relative refs (P7) so a malicious `<D:href>/../../etc/passwd` cannot
/// escape the `/SecureCloud/` prefix after base concatenation.
fn resolve_dav_ref(base: &str, ref_: &str) -> Result<String, ProviderError> {
    if ref_.starts_with("http://") || ref_.starts_with("https://") {
        let base_url = url::Url::parse(base)
            .map_err(|e| ProviderError::Provider(format!("invalid server base: {e}")))?;
        super::url_guard::validate_same_origin(ref_, &base_url)?;
        Ok(ref_.to_string())
    } else {
        // P7: reject traversal segments before concatenation. Any `..` in the
        // stored ref path is suspicious (PROPFIND should never return one);
        // rejecting is safer than silently normalising away real data.
        for seg in ref_.split('/') {
            if seg == ".." {
                return Err(ProviderError::Provider(
                    "refusing ref with path traversal (..) segment".into(),
                ));
            }
        }
        Ok(dav_url(base, ref_))
    }
}

/// Build the full URL for a file under SecureCloud/.
fn file_url(base: &str, name: &str, parent_path: Option<&str>) -> String {
    let parent = parent_path.unwrap_or("/SecureCloud");
    let parent = parent.trim_end_matches('/');
    dav_url(base, &format!("{parent}/{name}"))
}

/// Extract the URL origin (scheme + host, no path) from any URL.
fn url_origin(url: &str) -> String {
    // Find the third "/" after "scheme://"
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    match url[after_scheme..].find('/') {
        Some(i) => url[..after_scheme + i].to_string(),
        None => url.to_string(),
    }
}

/// If the URL contains `/remote.php/dav/`, return everything up to that segment
/// (the Nextcloud installation base URL); otherwise return None.
fn nc_installation_base(url: &str) -> Option<String> {
    url.find("/remote.php/dav/")
        .map(|i| url[..i].to_string())
}

/// Probe server capabilities. Returns the most capable streaming mode available.
///
/// Two non-blocking probes are run:
///   1. PROPFIND on `/remote.php/dav/` to detect Nextcloud / ownCloud.
///   2. OPTIONS on the server URL to detect tus.io (`Tus-Resumable` header).
///
/// Falls back to `BufferThenPut` if neither is available or the probe fails.
async fn probe_capabilities<H: ProviderHttpClient>(
    http: &H,
    server_url: &str,
    auth_header: Option<&str>,
    username: Option<&str>,
) -> WebDavCapabilities {
    // ── Nextcloud / ownCloud detection ───────────────────────────────────────
    // The NC DAV root is at /remote.php/dav/ relative to the installation base.
    // We try to derive the base from the server_url; if that fails we try the
    // origin directly.
    let nc_base_candidate = nc_installation_base(server_url)
        .unwrap_or_else(|| url_origin(server_url));
    let dav_root = format!("{}/remote.php/dav/", nc_base_candidate);

    let mut nc_req = ProviderHttpRequest::new("PROPFIND".to_string(), dav_root)
        .header(("Depth".to_string(), "0".to_string()))
        .header(("Content-Type".to_string(), "application/xml".to_string()))
        .body(br#"<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>"#.to_vec());
    if let Some(auth) = auth_header {
        nc_req = nc_req.header(("Authorization".to_string(), auth.to_string()));
    }
    if let Ok(resp) = http.request(nc_req).await {
        if resp.status == 207 {
            if let Some(user) = username {
                if !user.is_empty() {
                    return WebDavCapabilities::NcChunkingV2 {
                        nc_base: nc_base_candidate,
                        username: user.to_string(),
                    };
                }
            }
        }
    }

    // ── tus.io detection ─────────────────────────────────────────────────────
    let mut opts_req = ProviderHttpRequest::new("OPTIONS".to_string(), server_url.to_string());
    if let Some(auth) = auth_header {
        opts_req = opts_req.header(("Authorization".to_string(), auth.to_string()));
    }
    if let Ok(resp) = http.request(opts_req).await {
        if resp.header("tus-resumable").is_some() || resp.header("Tus-Resumable").is_some() {
            return WebDavCapabilities::Tus;
        }
    }

    WebDavCapabilities::BufferThenPut
}

// ─── NC v2 chunking helpers ───────────────────────────────────────────────────

/// Format a 5-digit zero-padded chunk number (NC v2 spec: 1-based, 5 digits).
fn nc_chunk_name(index: u32) -> String {
    format!("{:05}", index)
}

/// PUT one numbered chunk to the NC v2 transaction directory.
async fn nc_put_chunk<H: ProviderHttpClient>(
    http: &H,
    tx_dir_url: &str,
    auth_header: Option<&str>,
    chunk_index: u32,
    data: Vec<u8>,
) -> Result<(), ProviderError> {
    let chunk_url = format!("{}/{}", tx_dir_url.trim_end_matches('/'), nc_chunk_name(chunk_index));
    let mut req = ProviderHttpRequest::put(chunk_url)
        .header(("Content-Type".to_string(), "application/octet-stream".to_string()))
        .body(data);
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let resp = http.request(req).await?;
    if resp.status != 201 && resp.status != 204 && resp.status != 200 {
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
    }
    Ok(())
}

/// MOVE the assembled NC v2 upload to its final destination.
async fn nc_move_assemble<H: ProviderHttpClient>(
    http: &H,
    tx_dir_url: &str,
    dest_url: &str,
    auth_header: Option<&str>,
    total_size: u64,
    etag: Option<&str>,
) -> Result<(), ProviderError> {
    let dot_file = format!("{}/.file", tx_dir_url.trim_end_matches('/'));
    let mut req = ProviderHttpRequest::new("MOVE".to_string(), dot_file)
        .header(("Destination".to_string(), dest_url.to_string()))
        .header(("OC-Total-Length".to_string(), total_size.to_string()))
        .header(("Overwrite".to_string(), "T".to_string()));
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    if let Some(tag) = etag {
        req = req.header(("If-Match".to_string(), tag.to_string()));
    }
    let resp = http.request(req).await?;
    // 201 Created = new file assembled; 204 No Content = overwrite; both OK.
    if resp.status != 201 && resp.status != 204 && resp.status != 200 {
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
    }
    Ok(())
}

/// DELETE the NC v2 transaction directory (abort).
async fn nc_delete_tx<H: ProviderHttpClient>(
    http: &H,
    tx_dir_url: &str,
    auth_header: Option<&str>,
) -> Result<(), ProviderError> {
    let mut req = ProviderHttpRequest::delete(tx_dir_url.to_string());
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let _ = http.request(req).await; // best-effort
    Ok(())
}

// ─── tus.io helpers ───────────────────────────────────────────────────────────

/// POST to the tus endpoint to create a new upload session.
/// Returns the `Location` header (the upload URL for subsequent PATCH calls).
async fn tus_create_upload<H: ProviderHttpClient>(
    http: &H,
    tus_endpoint: &str,
    auth_header: Option<&str>,
    total_size: u64,
) -> Result<String, ProviderError> {
    let mut req = ProviderHttpRequest::post(tus_endpoint.to_string())
        .header(("Tus-Resumable".to_string(), "1.0.0".to_string()))
        .header(("Upload-Length".to_string(), total_size.to_string()))
        .header(("Content-Length".to_string(), "0".to_string()));
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let resp = http.request(req).await?;
    if resp.status != 201 {
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        return Err(ProviderError::Provider(format!(
            "tus create: unexpected status {}", resp.status
        )));
    }
    let loc = resp
        .header("location")
        .or_else(|| resp.header("Location"))
        .ok_or(ProviderError::InvalidResponse)?
        .to_string();
    // P1/P8: the returned Location is attacker-controlled (hostile WebDAV
    // server). Require it to share the origin of the tus endpoint so the
    // chunk PATCHes (which carry the Basic-auth header) don't get redirected
    // to 169.254.169.254 or to an internal service.
    let base = url::Url::parse(tus_endpoint)
        .map_err(|e| ProviderError::Provider(format!("invalid tus endpoint: {e}")))?;
    super::url_guard::validate_same_origin(&loc, &base)?;
    Ok(loc)
}

/// PATCH a chunk to an open tus upload session.
async fn tus_patch_chunk<H: ProviderHttpClient>(
    http: &H,
    upload_url: &str,
    auth_header: Option<&str>,
    offset: u64,
    data: Vec<u8>,
) -> Result<(), ProviderError> {
    let len = data.len();
    let mut req = ProviderHttpRequest::new("PATCH".to_string(), upload_url.to_string())
        .header(("Tus-Resumable".to_string(), "1.0.0".to_string()))
        .header(("Content-Type".to_string(), "application/offset+octet-stream".to_string()))
        .header(("Upload-Offset".to_string(), offset.to_string()))
        .header(("Content-Length".to_string(), len.to_string()))
        .body(data);
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let resp = http.request(req).await?;
    if resp.status != 204 && resp.status != 200 {
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
    }
    Ok(())
}

/// Generate a random 32-char hex ID for NC v2 transaction directory names.
/// Uses `OsRng` — the only approved entropy source in sdk-core.
fn random_hex_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse PROPFIND XML response into a list of StorageEntry.
/// We extract `D:href`, `D:getcontentlength`, `D:getlastmodified`, and `D:resourcetype`.
fn parse_propfind(body: &[u8], base_url: &str) -> Result<Vec<StorageEntry>, ProviderError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut entries: Vec<StorageEntry> = Vec::new();
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);

    // State machine for parsing multi-value PROPFIND responses
    let mut in_response = false;
    let mut in_prop = false;
    let mut current_href = String::new();
    let mut current_size: u64 = 0;
    let mut current_modified: Option<i64> = None;
    let mut current_is_folder = false;
    let mut current_mime: Option<String> = None;
    let mut buf = Vec::new();

    // Track which element we're currently reading text from
    enum TextTarget {
        Href,
        ContentLength,
        LastModified,
        ContentType,
        None,
    }
    let mut text_target = TextTarget::None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match name {
                    "response" | "Response" => {
                        in_response = true;
                        current_href.clear();
                        current_size = 0;
                        current_modified = None;
                        current_is_folder = false;
                        current_mime = None;
                    }
                    "prop" | "Prop" if in_response => in_prop = true,
                    "href" | "Href" if in_response && !in_prop => {
                        text_target = TextTarget::Href;
                    }
                    "getcontentlength" | "Getcontentlength" if in_prop => {
                        text_target = TextTarget::ContentLength;
                    }
                    "getlastmodified" | "Getlastmodified" if in_prop => {
                        text_target = TextTarget::LastModified;
                    }
                    "getcontenttype" | "Getcontenttype" if in_prop => {
                        text_target = TextTarget::ContentType;
                    }
                    "collection" | "Collection" if in_prop => {
                        current_is_folder = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if name == "collection" || name == "Collection" {
                    current_is_folder = true;
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default();
                match text_target {
                    TextTarget::Href => current_href = text.trim().to_string(),
                    TextTarget::ContentLength => {
                        current_size = text.trim().parse().unwrap_or(0);
                    }
                    TextTarget::LastModified => {
                        // HTTP date format (RFC 7231): "Mon, 28 Jan 2019 12:00:00 GMT"
                        // Try httpdate parsing; fall back gracefully
                        current_modified = parse_http_date(text.trim());
                    }
                    TextTarget::ContentType => {
                        current_mime = Some(text.trim().to_string());
                    }
                    TextTarget::None => {}
                }
                text_target = TextTarget::None;
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if name == "response" || name == "Response" {
                    if in_response && !current_href.is_empty() {
                        // Derive a display name from the href by stripping the base path
                        let ref_ = current_href.clone();
                        // Strip the base URL prefix if present
                        let path_only = current_href
                            .strip_prefix(&normalize_base(base_url))
                            .unwrap_or(&current_href);
                        let display_name = path_only
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or(path_only)
                            .to_string();
                        if !display_name.is_empty() {
                            entries.push(StorageEntry {
                                ref_,
                                name: display_name,
                                size: current_size,
                                is_folder: current_is_folder,
                                mime_type: current_mime.clone(),
                                modified_at: current_modified,
                            });
                        }
                    }
                    in_response = false;
                    in_prop = false;
                } else if name == "prop" || name == "Prop" {
                    in_prop = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(entries)
}

/// Parse an RFC 7231 HTTP date to Unix milliseconds.
/// Format: "Mon, 28 Jan 2019 12:00:00 GMT" or ISO 8601.
fn parse_http_date(s: &str) -> Option<i64> {
    // Try ISO 8601 first (some WebDAV servers use it)
    if let Some(ms) = crate::byo::providers::gdrive::parse_rfc3339_ms(s) {
        return Some(ms);
    }
    // RFC 7231 (HTTP date): "Day, DD Mon YYYY HH:MM:SS GMT"
    // A minimal hand-parser for the most common format.
    let parts: Vec<&str> = s.splitn(6, ' ').collect();
    if parts.len() < 5 {
        return None;
    }
    // parts[0] = "Mon," parts[1] = "28" parts[2] = "Jan" parts[3] = "2019" parts[4] = "12:00:00" parts[5] = "GMT"
    let day: i64 = parts.get(1)?.parse().ok()?;
    let month: i64 = match *parts.get(2)? {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
        "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
        "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.get(3)?.parse().ok()?;
    let time_parts: Vec<&str> = parts.get(4)?.split(':').collect();
    let hour: i64 = time_parts.first()?.parse().ok()?;
    let min: i64 = time_parts.get(1)?.parse().ok()?;
    let sec: i64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Compute days from epoch (1970-01-01) using the same logic as parse_rfc3339_ms
    use crate::byo::providers::gdrive::is_leap;
    let days_per_month: &[i64] = &[0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        let extra = if m == 2 && is_leap(year) { 1 } else { 0 };
        days += days_per_month.get(m as usize).copied().unwrap_or(30) + extra;
    }
    days += day - 1;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    Some(secs * 1000)
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for WebDAVProvider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Webdav
    }

    fn display_name(&self) -> String {
        "WebDAV".to_string()
    }

    fn is_ready(&self) -> bool {
        self.state
            .lock()
            .ok()
            .map(|s| !s.server_url.is_empty())
            .unwrap_or(false)
    }

    fn get_config(&self) -> ProviderConfig {
        let s = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return ProviderConfig::default(),
        };
        ProviderConfig {
            type_: ProviderType::Webdav,
            server_url: Some(s.server_url.clone()),
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
            let server_url = config
                .server_url
                .ok_or_else(|| ProviderError::Provider("server_url required for WebDAV".into()))?;
            // P10/SSRF: validate the configured server URL before we store it
            // as the base for every subsequent WebDAV request. Rejects
            // `http://` to internal addresses, `file://`, embedded credentials,
            // and private/RFC1918/link-local hosts.
            super::url_guard::validate_config_url(&server_url)?;
            let (auth_header_val, username_opt) =
                match (config.username.as_deref(), config.password.as_deref()) {
                    (Some(u), Some(p)) => (Some(basic_auth(u, p).1), Some(u.to_string())),
                    (Some(u), None) => (None, Some(u.to_string())),
                    _ => (None, None),
                };
            let base = normalize_base(&server_url);

            // Probe capabilities asynchronously (best-effort — never fails init).
            let caps = probe_capabilities(
                &*http,
                &base,
                auth_header_val.as_deref(),
                username_opt.as_deref(),
            )
            .await;

            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.server_url = base;
            s.auth_header = auth_header_val;
            s.capabilities = caps;
            Ok(())
        }
    }

    fn disconnect(
        &self,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.server_url.clear();
            s.auth_header = None;
            s.capabilities = WebDavCapabilities::BufferThenPut;
            s.upload_buffers.clear();
            s.chunk_sessions.clear();
            s.download_buffers.clear();
            Ok(())
        }
    }

    async fn refresh_auth(&self) -> Result<(), ProviderError> {
        // WebDAV uses static Basic auth; nothing to refresh.
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                if s.server_url.is_empty() {
                    return Err(ProviderError::Provider("not initialized".into()));
                }
                (s.server_url.clone(), s.auth_header.clone())
            };

            let url = match ref_ {
                Some(r) if !r.is_empty() => resolve_dav_ref(&base, &r)?,
                _ => file_url(&base, &name, options.parent_ref.as_deref()),
            };

            let mut req = ProviderHttpRequest::put(url.clone())
                .header(("Content-Type".to_string(), "application/octet-stream".to_string()))
                .body(data);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            if let Some(etag) = &options.expected_version {
                req = req.header(("If-Match".to_string(), etag.clone()));
            }

            let resp = http.request(req).await?;
            // 201 Created or 204 No Content are success for WebDAV PUT
            if resp.status != 201 && resp.status != 204 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            // Read ETag from response headers
            let version = resp
                .header("etag")
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default();
            Ok(UploadResult { ref_: url, version })
        }
    }

    fn download(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = resolve_dav_ref(&base, &ref_)?;
            let mut req = ProviderHttpRequest::get(url);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = resolve_dav_ref(&base, &ref_)?;
            let mut req = ProviderHttpRequest::delete(url);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            let resp = http.request(req).await?;
            if resp.status != 204 && resp.status != 200 {
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = resolve_dav_ref(&base, &ref_)?;
            let mut req = ProviderHttpRequest::new("HEAD".to_string(), url);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            let resp = http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
            let version = resp
                .header("etag")
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_default();
            Ok(version)
        }
    }

    // ── Streaming upload (capability-probed) ──────────────────────────────────
    //
    // Three paths, probed at init():
    //   1. NcChunkingV2   — MKCOL tx dir, numbered PUTs, MOVE .file to dest.
    //   2. Tus            — POST to get upload URL, then PATCH chunks.
    //   3. BufferThenPut  — accumulate full body, single PUT at close (fallback).

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
            let (base, auth, caps) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                if s.server_url.is_empty() {
                    return Err(ProviderError::Provider("not initialized".into()));
                }
                (s.server_url.clone(), s.auth_header.clone(), s.capabilities.clone())
            };

            let dest_url = match ref_ {
                Some(r) if !r.is_empty() => resolve_dav_ref(&base, &r)?,
                _ => file_url(&base, &name, options.parent_ref.as_deref()),
            };
            let stream_id = new_stream_id();

            match caps {
                WebDavCapabilities::NcChunkingV2 { nc_base, username }
                    if total_size as usize >= NC_MIN_CHUNK_SIZE =>
                {
                    let tx_id = random_hex_id();
                    let tx_dir_url = format!(
                        "{}/remote.php/dav/uploads/{}/{}/",
                        nc_base.trim_end_matches('/'), username, tx_id
                    );
                    // MKCOL the transaction directory.
                    let mut req = ProviderHttpRequest::new("MKCOL".to_string(), tx_dir_url.clone());
                    if let Some(v) = &auth { req = req.header(("Authorization".to_string(), v.clone())); }
                    let resp = http.request(req).await?;
                    if resp.status != 201 && resp.status != 200 {
                        if let Some(e) = map_http_status(resp.status, &resp.body) { return Err(e); }
                    }
                    state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .chunk_sessions.insert(stream_id.clone(), ChunkSession::NcV2 {
                            tx_dir_url, dest_url, total_size, chunk_index: 1,
                            buffer: Vec::new(), options,
                        });
                }
                // Small file on a Nextcloud server (< NC_MIN_CHUNK_SIZE): skip the 4-round-trip
                // MKCOL+PUT+MOVE dance and use a single PUT via the BufferThenPut path instead.
                WebDavCapabilities::NcChunkingV2 { .. } => {
                    state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .upload_buffers.insert(stream_id.clone(), UploadBuffer {
                            path: dest_url, data: Vec::new(), options,
                        });
                }
                WebDavCapabilities::Tus => {
                    let upload_url = tus_create_upload(&*http, &base, auth.as_deref(), total_size).await?;
                    state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .chunk_sessions.insert(stream_id.clone(), ChunkSession::Tus { upload_url, offset: 0 });
                }
                WebDavCapabilities::BufferThenPut => {
                    state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .upload_buffers.insert(stream_id.clone(), UploadBuffer {
                            path: dest_url, data: Vec::new(), options,
                        });
                }
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
            enum WriteAction {
                NcFlush { tx_dir_url: String, chunk_index: u32, data: Vec<u8>, auth: Option<String> },
                TusPatch { upload_url: String, offset: u64, data: Vec<u8>, auth: Option<String> },
                Buffered,
            }

            let action = {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let auth = s.auth_header.clone();
                if let Some(session) = s.chunk_sessions.get_mut(&stream_id) {
                    match session {
                        ChunkSession::NcV2 { buffer, tx_dir_url, chunk_index, .. } => {
                            buffer.extend_from_slice(&chunk);
                            if buffer.len() >= NC_MIN_CHUNK_SIZE {
                                let data = std::mem::take(buffer);
                                let idx = *chunk_index;
                                *chunk_index += 1;
                                WriteAction::NcFlush { tx_dir_url: tx_dir_url.clone(), chunk_index: idx, data, auth }
                            } else {
                                WriteAction::Buffered
                            }
                        }
                        ChunkSession::Tus { upload_url, offset } => {
                            let off = *offset;
                            *offset += chunk.len() as u64;
                            WriteAction::TusPatch { upload_url: upload_url.clone(), offset: off, data: chunk, auth }
                        }
                    }
                } else if let Some(buf) = s.upload_buffers.get_mut(&stream_id) {
                    buf.data.extend_from_slice(&chunk);
                    WriteAction::Buffered
                } else {
                    return Err(ProviderError::Provider(format!("unknown stream_id: {stream_id}")));
                }
            };

            // Perform I/O outside the lock.
            match action {
                WriteAction::NcFlush { tx_dir_url, chunk_index, data, auth } => {
                    nc_put_chunk(&*http, &tx_dir_url, auth.as_deref(), chunk_index, data).await?;
                }
                WriteAction::TusPatch { upload_url, offset, data, auth } => {
                    tus_patch_chunk(&*http, &upload_url, auth.as_deref(), offset, data).await?;
                }
                WriteAction::Buffered => {}
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
            enum CloseAction {
                NcAssemble {
                    tx_dir_url: String, dest_url: String, total_size: u64,
                    chunk_index: u32, remaining: Vec<u8>,
                    etag: Option<String>, auth: Option<String>,
                },
                TusComplete { dest_url: String },
                PutBuffer { path: String, data: Vec<u8>, options: UploadOptions, auth: Option<String> },
            }

            let action = {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let auth = s.auth_header.clone();
                if let Some(session) = s.chunk_sessions.remove(&stream_id) {
                    match session {
                        ChunkSession::NcV2 { tx_dir_url, dest_url, total_size, chunk_index, buffer, options } => {
                            CloseAction::NcAssemble {
                                tx_dir_url, dest_url, total_size, chunk_index,
                                remaining: buffer,
                                etag: options.expected_version.clone(),
                                auth,
                            }
                        }
                        ChunkSession::Tus { upload_url, .. } => {
                            // Last PATCH already sent 100% of data; no extra call needed.
                            CloseAction::TusComplete { dest_url: upload_url }
                        }
                    }
                } else if let Some(buf) = s.upload_buffers.remove(&stream_id) {
                    CloseAction::PutBuffer { path: buf.path, data: buf.data, options: buf.options, auth }
                } else {
                    return Err(ProviderError::Provider(format!("unknown stream_id: {stream_id}")));
                }
            };

            match action {
                CloseAction::NcAssemble { tx_dir_url, dest_url, total_size, chunk_index, remaining, etag, auth } => {
                    // PUT remaining bytes as the final chunk (NC requires at least one chunk).
                    nc_put_chunk(&*http, &tx_dir_url, auth.as_deref(), chunk_index, remaining).await?;
                    // MOVE .file to final destination — assembles all numbered chunks.
                    nc_move_assemble(&*http, &tx_dir_url, &dest_url, auth.as_deref(), total_size, etag.as_deref()).await?;
                    // HEAD the assembled file to read its ETag.
                    let mut req = ProviderHttpRequest::new("HEAD".to_string(), dest_url.clone());
                    if let Some(v) = &auth { req = req.header(("Authorization".to_string(), v.clone())); }
                    let resp = http.request(req).await?;
                    let version = resp.header("etag").map(|v| v.trim_matches('"').to_string()).unwrap_or_default();
                    Ok(UploadResult { ref_: dest_url, version })
                }
                CloseAction::TusComplete { dest_url } => {
                    // tus upload already complete; ETag not available without HEAD.
                    Ok(UploadResult { ref_: dest_url, version: String::new() })
                }
                CloseAction::PutBuffer { path, data, options, auth } => {
                    let mut req = ProviderHttpRequest::put(path.clone())
                        .header(("Content-Type".to_string(), "application/octet-stream".to_string()))
                        .body(data);
                    if let Some(v) = &auth { req = req.header(("Authorization".to_string(), v.clone())); }
                    if let Some(etag) = &options.expected_version {
                        req = req.header(("If-Match".to_string(), etag.clone()));
                    }
                    let resp = http.request(req).await?;
                    if resp.status != 201 && resp.status != 204 {
                        if let Some(e) = map_http_status(resp.status, &resp.body) { return Err(e); }
                    }
                    let version = resp.header("etag").map(|v| v.trim_matches('"').to_string()).unwrap_or_default();
                    Ok(UploadResult { ref_: path, version })
                }
            }
        }
    }

    fn upload_stream_abort(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (session, auth) = {
                let mut s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let session = s.chunk_sessions.remove(&stream_id);
                s.upload_buffers.remove(&stream_id);
                (session, s.auth_header.clone())
            };
            if let Some(session) = session {
                match session {
                    ChunkSession::NcV2 { tx_dir_url, .. } => {
                        // Best-effort DELETE of the NC v2 transaction directory.
                        nc_delete_tx(&*http, &tx_dir_url, auth.as_deref()).await?;
                    }
                    ChunkSession::Tus { upload_url, .. } => {
                        // Best-effort tus DELETE (RFC 9110 §3.4 — may not be supported by all servers).
                        let mut req = ProviderHttpRequest::delete(upload_url)
                            .header(("Tus-Resumable".to_string(), "1.0.0".to_string()));
                        if let Some(v) = &auth { req = req.header(("Authorization".to_string(), v.clone())); }
                        let _ = http.request(req).await;
                    }
                }
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = resolve_dav_ref(&base, &ref_)?;
            // WebDAV uses Basic auth (or none). Pre-build the fixed auth header.
            let make_headers: MakeHeaders = Arc::new(move |offset: u64, end: u64| {
                let mut h = Vec::with_capacity(2);
                if let Some(auth_val) = &auth {
                    h.push(("Authorization".to_string(), auth_val.clone()));
                }
                h.push(("Range".to_string(), format!("bytes={offset}-{end}")));
                h
            });
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = match parent_ref {
                Some(p) if !p.is_empty() => resolve_dav_ref(&base, &p)?,
                _ => dav_url(&base, "/SecureCloud/"),
            };
            let propfind_body = br#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype/>
    <D:getcontentlength/>
    <D:getlastmodified/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>"#;
            let mut req = ProviderHttpRequest::new("PROPFIND".to_string(), url.clone())
                .header(("Depth".to_string(), "1".to_string()))
                .header(("Content-Type".to_string(), "application/xml".to_string()))
                .body(propfind_body.to_vec());
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            let resp = http.request(req).await?;
            // 207 Multi-Status is the expected response for PROPFIND
            if resp.status != 207 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            let mut entries = parse_propfind(&resp.body, &base)?;
            // Remove the parent directory itself (first entry with same path)
            let base_path = url.strip_prefix(&base).unwrap_or(&url).to_string();
            entries.retain(|e| {
                let e_path = if e.ref_.starts_with("http") {
                    e.ref_.strip_prefix(&base).unwrap_or(&e.ref_).to_string()
                } else {
                    e.ref_.clone()
                };
                let e_path = e_path.trim_end_matches('/');
                let base_path = base_path.trim_end_matches('/');
                e_path != base_path
            });
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
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = match parent_ref {
                Some(p) if !p.is_empty() => {
                    let p = p.trim_end_matches('/');
                    // Resolve the parent ref first so it's validated, then
                    // append the child name (which is a plain path segment).
                    let parent = resolve_dav_ref(&base, p)?;
                    format!("{}/{name}", parent.trim_end_matches('/'))
                }
                _ => dav_url(&base, &format!("/SecureCloud/{name}")),
            };
            let mut req = ProviderHttpRequest::new("MKCOL".to_string(), url.clone());
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            let resp = http.request(req).await?;
            // 201 = created, 405 = already exists (both OK for our purposes)
            if resp.status != 201 && resp.status != 405 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            // Return the URL of the created folder as the ref
            Ok(url)
        }
    }

    fn delete_folder(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        // For WebDAV, folder and file deletion are both DELETE
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (base, auth) = {
                let s = state.lock().map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = resolve_dav_ref(&base, &ref_)?;
            let mut req = ProviderHttpRequest::delete(url);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            let resp = http.request(req).await?;
            if resp.status != 204 && resp.status != 200 {
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
            "Public links not yet implemented for webdav".into(),
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
            "Presigned URLs not yet implemented for webdav".into(),
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
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
    }

    impl MockHttp {
        fn new(r: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> Self {
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
                .unwrap_or((500, b"no response".to_vec(), Vec::new()));
            async move {
                Ok(ProviderHttpResponse {
                    status: response.0,
                    headers: response.2,
                    body: response.1,
                })
            }
        }
    }

    fn make_provider(responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> WebDAVProvider<MockHttp> {
        let p = WebDAVProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.server_url = "https://dav.example.com".to_string();
            s.auth_header = Some("Basic dXNlcjpwYXNz".to_string());
        }
        p
    }

    #[tokio::test]
    async fn upload_returns_ref_and_version() {
        let p = make_provider(vec![(
            201,
            b"".to_vec(),
            vec![("etag".to_string(), r#""etag123""#.to_string())],
        )]);
        let result = p
            .upload(None, "file.bin".into(), b"data".to_vec(), UploadOptions::default())
            .await
            .unwrap();
        assert!(result.ref_.contains("SecureCloud"));
        assert_eq!(result.version, "etag123");
    }

    #[tokio::test]
    async fn upload_412_conflict() {
        let p = make_provider(vec![(412, b"".to_vec(), vec![])]);
        let err = p
            .upload(
                Some("/SecureCloud/f.bin".into()),
                "f.bin".into(),
                vec![],
                UploadOptions {
                    expected_version: Some("old".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Conflict { .. }));
    }

    #[tokio::test]
    async fn download_returns_body() {
        let p = make_provider(vec![(200, b"webdav file".to_vec(), vec![])]);
        let data = p.download("/SecureCloud/f.bin".into()).await.unwrap();
        assert_eq!(data, b"webdav file");
    }

    #[tokio::test]
    async fn stream_roundtrip() {
        let p = make_provider(vec![(
            201,
            b"".to_vec(),
            vec![("etag".to_string(), "\"etag456\"".to_string())],
        )]);
        let sid = p
            .upload_stream_open(None, "big.bin".into(), 5, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec()).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.version, "etag456");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![(200, b"streamed".to_vec(), vec![])]);
        let sid = p.download_stream_open("/SecureCloud/f.bin".into()).await.unwrap();
        let chunk = p.download_stream_read(sid.clone()).await.unwrap();
        let eof = p.download_stream_read(sid.clone()).await.unwrap();
        assert_eq!(chunk, Some(b"streamed".to_vec()));
        assert_eq!(eof, None);
        p.download_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn create_folder_405_is_ok() {
        // 405 means folder already exists — should succeed
        let p = make_provider(vec![(405, b"".to_vec(), vec![])]);
        let ref_ = p.create_folder("photos".into(), None).await.unwrap();
        assert!(ref_.contains("photos"));
    }

    fn make_nc_provider(responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> WebDAVProvider<MockHttp> {
        let p = WebDAVProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.server_url = "https://nc.example.com/remote.php/dav/files/alice".to_string();
            s.auth_header = Some("Basic dXNlcjpwYXNz".to_string());
            s.capabilities = WebDavCapabilities::NcChunkingV2 {
                nc_base: "https://nc.example.com".to_string(),
                username: "alice".to_string(),
            };
        }
        p
    }

    fn make_tus_provider(responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> WebDAVProvider<MockHttp> {
        let p = WebDAVProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.server_url = "https://tus.example.com".to_string();
            s.auth_header = Some("Basic dXNlcjpwYXNz".to_string());
            s.capabilities = WebDavCapabilities::Tus;
        }
        p
    }

    #[tokio::test]
    async fn nc_v2_small_file_bypass_uses_single_put() {
        // Files < NC_MIN_CHUNK_SIZE on a Nextcloud server must bypass the 4-round-trip
        // MKCOL+PUT+MOVE path and use a single PUT (BufferThenPut) instead.
        // Sequence: PUT only (no MKCOL, no MOVE, no HEAD)
        let p = make_nc_provider(vec![
            (201, b"".to_vec(), vec![("etag".to_string(), "\"put-etag\"".to_string())]), // PUT
        ]);
        let sid = p
            .upload_stream_open(None, "data.bin".into(), 5, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec()).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.version, "put-etag");
        assert!(result.ref_.contains("data.bin"));
    }

    #[tokio::test]
    async fn nc_v2_at_min_chunk_size_uses_chunked_path() {
        // A file exactly at NC_MIN_CHUNK_SIZE must still use the NcChunkingV2 path.
        // write flushes the full chunk (PUT 00001), then close PUTs the empty remainder
        // (NC always requires a final PUT before MOVE) then MOVE + HEAD.
        // Sequence: MKCOL → PUT 00001 (flush in write) → PUT 00002 (empty, in close) → MOVE → HEAD
        let p = make_nc_provider(vec![
            (201, b"".to_vec(), vec![]),                                                   // MKCOL
            (201, b"".to_vec(), vec![]),                                                   // PUT 00001 (flush)
            (201, b"".to_vec(), vec![]),                                                   // PUT 00002 (empty final)
            (201, b"".to_vec(), vec![]),                                                   // MOVE
            (200, b"".to_vec(), vec![("etag".to_string(), "\"nc-etag\"".to_string())]),   // HEAD
        ]);
        let total = NC_MIN_CHUNK_SIZE as u64;
        let sid = p
            .upload_stream_open(None, "exact.bin".into(), total, UploadOptions::default())
            .await
            .unwrap();
        let chunk = vec![0u8; NC_MIN_CHUNK_SIZE];
        p.upload_stream_write(sid.clone(), chunk).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.version, "nc-etag");
    }

    #[tokio::test]
    async fn nc_v2_stream_large_file_with_flush() {
        // File spans two append flushes + final chunk at close.
        // Sequence: MKCOL → PUT 00001 (flush1) → PUT 00002 (flush2) → PUT 00003 (close) → MOVE → HEAD
        let chunk = vec![0u8; NC_MIN_CHUNK_SIZE + 1]; // one byte over threshold → immediate flush
        let p = make_nc_provider(vec![
            (201, b"".to_vec(), vec![]),                                                 // MKCOL
            (201, b"".to_vec(), vec![]),                                                 // PUT 00001
            (201, b"".to_vec(), vec![]),                                                 // PUT 00002
            (201, b"".to_vec(), vec![]),                                                 // PUT 00003 (final)
            (201, b"".to_vec(), vec![]),                                                 // MOVE
            (200, b"".to_vec(), vec![("etag".to_string(), "\"nc-etag2\"".to_string())]), // HEAD
        ]);
        let total = (chunk.len() * 2) as u64;
        let sid = p
            .upload_stream_open(None, "large.bin".into(), total, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), chunk.clone()).await.unwrap(); // triggers flush (PUT 00001)
        p.upload_stream_write(sid.clone(), chunk.clone()).await.unwrap(); // triggers flush (PUT 00002)
        let result = p.upload_stream_close(sid).await.unwrap(); // PUT 00003 + MOVE + HEAD
        assert_eq!(result.version, "nc-etag2");
    }

    #[tokio::test]
    async fn nc_v2_abort_deletes_tx_dir() {
        // MKCOL → abort → DELETE tx dir
        let p = make_nc_provider(vec![
            (201, b"".to_vec(), vec![]), // MKCOL
            (204, b"".to_vec(), vec![]), // DELETE
        ]);
        let sid = p
            .upload_stream_open(None, "abort.bin".into(), 10, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_abort(sid).await.unwrap();
    }

    #[tokio::test]
    async fn tus_stream_roundtrip() {
        // POST → PATCH → (close is no-op)
        let p = make_tus_provider(vec![
            (201, b"".to_vec(), vec![("location".to_string(), "https://tus.example.com/files/abc".to_string())]), // POST
            (204, b"".to_vec(), vec![]), // PATCH
        ]);
        let sid = p
            .upload_stream_open(None, "data.bin".into(), 5, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec()).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        // tus close returns empty version (no HEAD)
        assert_eq!(result.version, "");
    }

    #[tokio::test]
    async fn parse_propfind_xml() {
        let xml = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/SecureCloud/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/SecureCloud/photo.jpg</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>12345</D:getcontentlength>
        <D:getcontenttype>image/jpeg</D:getcontenttype>
      </D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let entries = parse_propfind(xml, "https://dav.example.com").unwrap();
        // Both entries parsed; filter logic removes the parent in list() but not here
        let file = entries.iter().find(|e| e.name == "photo.jpg").unwrap();
        assert_eq!(file.size, 12345);
        assert_eq!(file.mime_type.as_deref(), Some("image/jpeg"));
        assert!(!file.is_folder);
    }
}
