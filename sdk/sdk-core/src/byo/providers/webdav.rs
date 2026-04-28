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

use crate::api::{ProviderHttpClient, ProviderHttpRequest, StreamingPutClient};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    fmt_if_match, make_http_call_fn, map_http_status, new_stream_id, normalize_etag, MakeHeaders,
    RangedDownloadBuffer,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Nextcloud/OC v2 chunking: minimum bytes per non-final chunk (5 MiB).
/// Last chunk may be any size (including 0 if total is an exact multiple).
const NC_MIN_CHUNK_SIZE: usize = 5 * 1024 * 1024;
/// Only run the `DAV:quota-available-bytes` preflight for uploads that would
/// genuinely hurt on failure. A 5 MiB save to a quota-exhausted server will
/// fail fast anyway, so the extra round trip isn't worth it; a 5 GiB upload
/// that starts and dies at 90 % is a much worse user experience. 100 MiB
/// is the practical inflection point on residential uplinks.
const PREFLIGHT_QUOTA_MIN_BYTES: u64 = 100 * 1024 * 1024;

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
    /// Generic WebDAV: stream the body via a single PUT with a streamed
    /// request body (fetch `ReadableStream` + `duplex: 'half'` on WASM,
    /// reqwest `Body::wrap_stream` on native). Selected when the HTTP
    /// client reports `supports_streaming_put()` AND neither NC nor tus
    /// applies.
    StreamingPut,
    /// Generic WebDAV, last-resort fallback: buffer the full body then
    /// issue a single PUT. Used only on browsers that predate streaming
    /// request bodies (Safari < 17, etc.). Memory footprint scales with
    /// file size — callers that cross a practical cap should upgrade the
    /// browser or put a NC/tus/streaming-capable server in front.
    BufferThenPut,
}

/// State for an in-progress NC v2 or tus streaming upload.
enum ChunkSession {
    /// Nextcloud/OC v2: numbered PUT chunks into a temp dir, then MOVE.
    NcV2 {
        tx_dir_url: String, // …/remote.php/dav/uploads/<user>/<uuid>/
        dest_url: String,   // final DAV destination URL
        total_size: u64,
        chunk_index: u32, // 1-indexed; incremented after each PUT
        buffer: Vec<u8>,  // accumulates until NC_MIN_CHUNK_SIZE
        options: UploadOptions,
    },
    /// tus.io: PATCH chunks to the session upload_url.
    Tus { upload_url: String, offset: u64 },
    /// Streamed PUT: single request with a streamed body.
    StreamingPut {
        /// Final destination URL (also the upload target — no intermediate).
        dest_url: String,
        /// Handle returned by `StreamingPutClient::put_stream_open`.
        stream_handle: String,
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
    upload_buffers: HashMap<String, UploadBuffer>, // buffer-then-PUT fallback
    chunk_sessions: HashMap<String, ChunkSession>, // NC v2 / tus sessions
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
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{base}{path}")
}

/// Resolve an attacker-controllable WebDAV ref into a safe URL (P5).
///
/// Refs come from PROPFIND `<D:href>` responses — the WebDAV server is not
/// trusted to keep the ref under its own origin. If the ref is absolute,
/// require it to share the origin of the configured server; if it is
/// server-absolute (leading `/`), join against the base's origin; otherwise
/// (bare name / sub-path) join against the full base. Also strips `..`
/// segments (P7) so a malicious `<D:href>/../../etc/passwd` cannot escape.
fn resolve_dav_ref(base: &str, ref_: &str) -> Result<String, ProviderError> {
    if ref_.starts_with("http://") || ref_.starts_with("https://") {
        let base_url = url::Url::parse(base)
            .map_err(|e| ProviderError::Provider(format!("invalid server base: {e}")))?;
        super::url_guard::validate_same_origin(ref_, &base_url)?;
        return Ok(ref_.to_string());
    }
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
    if ref_.starts_with('/') {
        // Server-absolute ref. Nextcloud returns hrefs like
        // `/remote.php/dav/files/alice/WattcloudVault/photo.jpg` — if the
        // user's configured `server_url` already includes that same DAV
        // prefix (the canonical NC setup), concatenating base + ref
        // produces a doubled path ( `…/files/alice/remote.php/dav/files/alice/…` )
        // that 404s. Joining against the base's origin gives the correct
        // URL the server originally told us about.
        let origin = url_origin(base);
        Ok(format!("{origin}{ref_}"))
    } else {
        // Relative ref (bare name or sub-path) — join against the full base.
        Ok(dav_url(base, ref_))
    }
}

/// Build the full URL for a file under WattcloudVault/.
fn file_url(base: &str, name: &str, parent_path: Option<&str>) -> String {
    let parent = parent_path.unwrap_or("/WattcloudVault");
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

/// Return the URL path portion of any URL or server-absolute href.
/// `https://dav.example/foo/bar` → `/foo/bar`
/// `/remote.php/dav/files/alice/WattcloudVault/` → unchanged
/// Used by `list()` to normalise parent/child ref comparisons when the server
/// mixes absolute hrefs and full URLs.
fn url_path(s: &str) -> &str {
    if let Some(scheme_end) = s.find("://") {
        let after_scheme = &s[scheme_end + 3..];
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[slash..],
            None => "/",
        }
    } else {
        s
    }
}

/// If the URL contains `/remote.php/dav/`, return everything up to that segment
/// (the Nextcloud installation base URL); otherwise return None.
fn nc_installation_base(url: &str) -> Option<String> {
    url.find("/remote.php/dav/").map(|i| url[..i].to_string())
}

/// Decode `%XX` sequences in a URL path segment, preserving UTF-8.
/// PROPFIND `<D:href>` bodies arrive percent-encoded (`My%20Folder`); the
/// display name we expose to the UI should be the decoded form (`My Folder`).
/// Invalid escapes are passed through verbatim — the alternative (error) would
/// render a legitimately-named file unopenable.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Distinguish a genuine Nextcloud / ownCloud 207 from an unrelated proxy that
/// happens to answer PROPFIND on `/remote.php/dav/`. Returns true when any of
/// three fingerprints matches:
///   * `Server: Nextcloud` or `Server: ownCloud`
///   * response body carries `xmlns:oc="http://owncloud.org/ns"` or
///     `xmlns:nc="http://nextcloud.org/ns"`
///   * `DAV:` header lists a Nextcloud/ownCloud capability token
fn is_nc_response(resp: &crate::api::provider_http::ProviderHttpResponse) -> bool {
    if let Some(server) = resp.header("server") {
        let s = server.to_ascii_lowercase();
        if s.contains("nextcloud") || s.contains("owncloud") {
            return true;
        }
    }
    if let Some(dav) = resp.header("dav") {
        // Nextcloud advertises `nc-chunking` / `nc-uploads` tokens in its DAV
        // capabilities header since v19; ownCloud uses `oc-*` tokens.
        let d = dav.to_ascii_lowercase();
        if d.contains("nc-") || d.contains("oc-") {
            return true;
        }
    }
    let body = std::str::from_utf8(&resp.body).unwrap_or("");
    body.contains("xmlns:oc=\"http://owncloud.org/ns\"")
        || body.contains("xmlns:nc=\"http://nextcloud.org/ns\"")
}

/// Probe server capabilities. Returns the most capable streaming mode available.
///
/// Two server probes are run (NC PROPFIND, tus OPTIONS). `can_stream_put`
/// short-circuits the fallback ladder so generic servers get the streamed-PUT
/// path when the caller (browser / runtime) supports it.
///
/// Priority: `NcChunkingV2` → `Tus` → `StreamingPut` → `BufferThenPut`.
async fn probe_capabilities<H: ProviderHttpClient>(
    http: &H,
    server_url: &str,
    auth_header: Option<&str>,
    username: Option<&str>,
    can_stream_put: bool,
) -> WebDavCapabilities {
    // ── Nextcloud / ownCloud detection ───────────────────────────────────────
    // The NC DAV root is at /remote.php/dav/ relative to the installation base.
    // We try to derive the base from the server_url; if that fails we try the
    // origin directly.
    let nc_base_candidate =
        nc_installation_base(server_url).unwrap_or_else(|| url_origin(server_url));
    let dav_root = format!("{}/remote.php/dav/", nc_base_candidate);

    let mut nc_req = ProviderHttpRequest::new("PROPFIND".to_string(), dav_root)
        .header(("Depth".to_string(), "0".to_string()))
        .header(("Content-Type".to_string(), "application/xml".to_string()))
        .body(br#"<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>"#.to_vec());
    if let Some(auth) = auth_header {
        nc_req = nc_req.header(("Authorization".to_string(), auth.to_string()));
    }
    if let Ok(resp) = http.request(nc_req).await {
        // A bare 207 is not enough: any proxy that forwards PROPFIND anywhere
        // can happen to answer 207 on this path. Confirm via one of the NC/OC
        // fingerprints: Server: Nextcloud/ownCloud, or NC-namespace XML in the
        // body (xmlns:oc or xmlns:nc), or the `DAV:` capabilities header
        // listing NC-specific tokens. Missing all of them → not NC, fall
        // through to the tus probe and then BufferThenPut. False-negative is
        // cheaper than false-positive (which would wedge every chunked upload
        // on MKCOL /uploads/).
        if resp.status == 207 && is_nc_response(&resp) {
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

    if can_stream_put {
        WebDavCapabilities::StreamingPut
    } else {
        WebDavCapabilities::BufferThenPut
    }
}

/// Authenticated `PROPFIND Depth: 0` on the configured server root. Used by
/// [`init`] to fail fast when the user-supplied credentials are wrong — and
/// now when the server itself is broken.
///
/// Tolerated: 2xx/207 (expected), 404/405 (server exposes DAV only on a
/// sub-path — e.g. Apache mod_dav limited to `/dav/`; real auth errors
/// surface on the first real operation).
/// Propagated via `map_http_status`: 401 → Unauthorized, 403 → Forbidden,
/// 408/429 → RateLimited, 5xx → Provider (broken server, fail init rather
/// than storing credentials for a dead host).
async fn verify_webdav_auth<H: ProviderHttpClient>(
    http: &H,
    server_url: &str,
    auth_header: Option<&str>,
) -> Result<(), ProviderError> {
    let mut req = ProviderHttpRequest::new("PROPFIND".to_string(), server_url.to_string())
        .header(("Depth".to_string(), "0".to_string()))
        .header(("Content-Type".to_string(), "application/xml".to_string()))
        .body(br#"<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>"#.to_vec());
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let resp = http.request(req).await?;
    if matches!(resp.status, 200..=299 | 404 | 405) {
        return Ok(());
    }
    Err(map_http_status(resp.status, &resp.body).unwrap_or_else(|| {
        ProviderError::Provider(format!("HTTP {} from {}", resp.status, server_url))
    }))
}

/// Query `DAV:quota-available-bytes` via PROPFIND (RFC 4331). Returns `None`
/// on every kind of failure — generic Apache mod_dav doesn't expose quota
/// properties, and the user shouldn't be blocked from uploading against a
/// silent server. Nextcloud, ownCloud, Box-DAV, and most commercial WebDAV
/// servers implement the property.
///
/// The property's value is decimal bytes. RFC 4331 §3 allows an
/// implementation to report "effectively infinite" as any very large number;
/// we treat any u64 parse as the truth and rely on the comparison with
/// `total_size` to decide whether to block.
async fn query_webdav_quota<H: ProviderHttpClient>(
    http: &H,
    target_url: &str,
    auth_header: Option<&str>,
) -> Option<u64> {
    let mut req = ProviderHttpRequest::new("PROPFIND".to_string(), target_url.to_string())
        .header(("Depth".to_string(), "0".to_string()))
        .header(("Content-Type".to_string(), "application/xml".to_string()))
        .body(
            br#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:quota-available-bytes/>
  </D:prop>
</D:propfind>"#
                .to_vec(),
        );
    if let Some(auth) = auth_header {
        req = req.header(("Authorization".to_string(), auth.to_string()));
    }
    let resp = http.request(req).await.ok()?;
    if resp.status != 207 {
        return None;
    }
    parse_quota_available(&resp.body)
}

/// Extract `<quota-available-bytes>NNN</quota-available-bytes>` from a
/// PROPFIND multistatus body. Works regardless of namespace prefix (uses
/// `local_name`). Returns `None` when the element is missing or the text
/// doesn't parse as `u64`.
fn parse_quota_available(body: &[u8]) -> Option<u64> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut capture = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                if name.eq_ignore_ascii_case("quota-available-bytes") {
                    capture = true;
                }
            }
            Ok(Event::Text(t)) if capture => {
                let decoded = t.decode().ok()?;
                return quick_xml::escape::unescape(&decoded)
                    .ok()?
                    .trim()
                    .parse::<u64>()
                    .ok();
            }
            Ok(Event::End(_)) => {
                capture = false;
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
    None
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
    let chunk_url = format!(
        "{}/{}",
        tx_dir_url.trim_end_matches('/'),
        nc_chunk_name(chunk_index)
    );
    let mut req = ProviderHttpRequest::put(chunk_url)
        .header((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ))
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
        req = req.header(("If-Match".to_string(), fmt_if_match(tag)));
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
            "tus create: unexpected status {}",
            resp.status
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
        .header((
            "Content-Type".to_string(),
            "application/offset+octet-stream".to_string(),
        ))
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
                let text: std::borrow::Cow<str> = e
                    .decode()
                    .ok()
                    .and_then(|d| quick_xml::escape::unescape(&d).ok().map(|u| u.into_owned()))
                    .map(std::borrow::Cow::Owned)
                    .unwrap_or(std::borrow::Cow::Borrowed(""));
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
                        let raw_display_name = path_only
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or(path_only);
                        // Decode %XX so the UI shows "My Folder" instead of
                        // "My%20Folder". The stored ref_ stays encoded so
                        // subsequent requests round-trip verbatim against
                        // the server that gave us the path.
                        let display_name = percent_decode(raw_display_name);
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
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
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

impl<H: ProviderHttpClient + StreamingPutClient + Send + Sync + 'static> StorageProvider
    for WebDAVProvider<H>
{
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
            // `can_stream_put` reflects whether the runtime/browser supports
            // a streaming fetch request body: if true, generic servers get
            // `StreamingPut` instead of `BufferThenPut` as the fallback.
            let can_stream_put = http.supports_streaming_put();
            let caps = probe_capabilities(
                &*http,
                &base,
                auth_header_val.as_deref(),
                username_opt.as_deref(),
                can_stream_put,
            )
            .await;

            // Credential check (parity with S3's HEAD-bucket): send one
            // authenticated PROPFIND against the configured root and propagate
            // 401/403 as `Unauthorized`/`Forbidden`. Without this, init()
            // silently stored whatever creds the user typed and the first
            // hint of a wrong password was a failed upload minutes later.
            // The NC and tus probes above don't test auth reliably — the NC
            // probe hits `/remote.php/dav/` which 404s on non-NC servers
            // (indistinguishable from auth failure), and OPTIONS is commonly
            // unauthenticated.
            verify_webdav_auth(&*http, &base, auth_header_val.as_deref()).await?;

            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
            s.server_url = base;
            s.auth_header = auth_header_val;
            s.capabilities = caps;
            Ok(())
        }
    }

    fn disconnect(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let state = Arc::clone(&self.state);
        async move {
            let mut s = state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                .header((
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                ))
                .body(data);
            if let Some(auth_val) = &auth {
                req = req.header(("Authorization".to_string(), auth_val.clone()));
            }
            if let Some(etag) = &options.expected_version {
                req = req.header(("If-Match".to_string(), fmt_if_match(etag)));
            }

            let resp = http.request(req).await?;
            // 201 Created or 204 No Content are success for WebDAV PUT
            if resp.status != 201 && resp.status != 204 {
                if let Some(e) = map_http_status(resp.status, &resp.body) {
                    return Err(e);
                }
            }
            // Read ETag from response headers
            let version = resp.header("etag").map(normalize_etag).unwrap_or_default();
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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

    fn delete(&self, ref_: String) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let http = Arc::clone(&self.http);
        let state = Arc::clone(&self.state);
        async move {
            let (base, auth) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
            let version = resp.header("etag").map(normalize_etag).unwrap_or_default();
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                if s.server_url.is_empty() {
                    return Err(ProviderError::Provider("not initialized".into()));
                }
                (
                    s.server_url.clone(),
                    s.auth_header.clone(),
                    s.capabilities.clone(),
                )
            };

            let dest_url = match ref_ {
                Some(r) if !r.is_empty() => resolve_dav_ref(&base, &r)?,
                _ => file_url(&base, &name, options.parent_ref.as_deref()),
            };

            // RFC 4331 preflight: query `DAV:quota-available-bytes` on the
            // configured server root (Nextcloud / ownCloud return the user's
            // total-account quota here). Skip for small uploads (not worth
            // the round trip), for unknown sizes, and for servers that don't
            // expose the property — blocking on a silent server would
            // regress uploads that used to succeed. Only fails the upload
            // when we positively learned the destination can't hold it.
            if total_size >= PREFLIGHT_QUOTA_MIN_BYTES {
                if let Some(available) = query_webdav_quota(&*http, &base, auth.as_deref()).await {
                    if total_size > available {
                        return Err(ProviderError::InsufficientSpace {
                            needed: total_size,
                            available,
                        });
                    }
                }
            }

            let stream_id = new_stream_id();

            match caps {
                WebDavCapabilities::NcChunkingV2 { nc_base, username }
                    if total_size as usize >= NC_MIN_CHUNK_SIZE =>
                {
                    let tx_id = random_hex_id();
                    let tx_dir_url = format!(
                        "{}/remote.php/dav/uploads/{}/{}/",
                        nc_base.trim_end_matches('/'),
                        username,
                        tx_id
                    );
                    // MKCOL the transaction directory.
                    let mut req = ProviderHttpRequest::new("MKCOL".to_string(), tx_dir_url.clone());
                    if let Some(v) = &auth {
                        req = req.header(("Authorization".to_string(), v.clone()));
                    }
                    let resp = http.request(req).await?;
                    if resp.status != 201 && resp.status != 200 {
                        if let Some(e) = map_http_status(resp.status, &resp.body) {
                            return Err(e);
                        }
                    }
                    state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .chunk_sessions
                        .insert(
                            stream_id.clone(),
                            ChunkSession::NcV2 {
                                tx_dir_url,
                                dest_url,
                                total_size,
                                chunk_index: 1,
                                buffer: Vec::new(),
                                options,
                            },
                        );
                }
                // Small file on a Nextcloud server (< NC_MIN_CHUNK_SIZE): skip the 4-round-trip
                // MKCOL+PUT+MOVE dance and use a single PUT via the BufferThenPut path instead.
                WebDavCapabilities::NcChunkingV2 { .. } => {
                    state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .upload_buffers
                        .insert(
                            stream_id.clone(),
                            UploadBuffer {
                                path: dest_url,
                                data: Vec::new(),
                                options,
                            },
                        );
                }
                WebDavCapabilities::Tus => {
                    let upload_url =
                        tus_create_upload(&*http, &base, auth.as_deref(), total_size).await?;
                    state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .chunk_sessions
                        .insert(
                            stream_id.clone(),
                            ChunkSession::Tus {
                                upload_url,
                                offset: 0,
                            },
                        );
                }
                WebDavCapabilities::StreamingPut => {
                    let mut hdrs = vec![(
                        "Content-Type".to_string(),
                        "application/octet-stream".to_string(),
                    )];
                    if let Some(v) = &auth {
                        hdrs.push(("Authorization".to_string(), v.clone()));
                    }
                    if let Some(etag) = &options.expected_version {
                        hdrs.push(("If-Match".to_string(), fmt_if_match(etag)));
                    }
                    let stream_handle = http
                        .put_stream_open(dest_url.clone(), hdrs, Some(total_size))
                        .await?;
                    state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .chunk_sessions
                        .insert(
                            stream_id.clone(),
                            ChunkSession::StreamingPut {
                                dest_url,
                                stream_handle,
                            },
                        );
                }
                WebDavCapabilities::BufferThenPut => {
                    state
                        .lock()
                        .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                        .upload_buffers
                        .insert(
                            stream_id.clone(),
                            UploadBuffer {
                                path: dest_url,
                                data: Vec::new(),
                                options,
                            },
                        );
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
                NcFlush {
                    tx_dir_url: String,
                    chunk_index: u32,
                    data: Vec<u8>,
                    auth: Option<String>,
                },
                TusPatch {
                    upload_url: String,
                    offset: u64,
                    data: Vec<u8>,
                    auth: Option<String>,
                },
                StreamPush {
                    stream_handle: String,
                    data: Vec<u8>,
                },
                Buffered,
            }

            let action = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let auth = s.auth_header.clone();
                if let Some(session) = s.chunk_sessions.get_mut(&stream_id) {
                    match session {
                        ChunkSession::NcV2 {
                            buffer,
                            tx_dir_url,
                            chunk_index,
                            ..
                        } => {
                            buffer.extend_from_slice(&chunk);
                            if buffer.len() >= NC_MIN_CHUNK_SIZE {
                                let data = std::mem::take(buffer);
                                let idx = *chunk_index;
                                *chunk_index += 1;
                                WriteAction::NcFlush {
                                    tx_dir_url: tx_dir_url.clone(),
                                    chunk_index: idx,
                                    data,
                                    auth,
                                }
                            } else {
                                WriteAction::Buffered
                            }
                        }
                        ChunkSession::Tus { upload_url, offset } => {
                            let off = *offset;
                            *offset += chunk.len() as u64;
                            WriteAction::TusPatch {
                                upload_url: upload_url.clone(),
                                offset: off,
                                data: chunk,
                                auth,
                            }
                        }
                        ChunkSession::StreamingPut { stream_handle, .. } => {
                            WriteAction::StreamPush {
                                stream_handle: stream_handle.clone(),
                                data: chunk,
                            }
                        }
                    }
                } else if let Some(buf) = s.upload_buffers.get_mut(&stream_id) {
                    buf.data.extend_from_slice(&chunk);
                    WriteAction::Buffered
                } else {
                    return Err(ProviderError::Provider(format!(
                        "unknown stream_id: {stream_id}"
                    )));
                }
            };

            // Perform I/O outside the lock.
            match action {
                WriteAction::NcFlush {
                    tx_dir_url,
                    chunk_index,
                    data,
                    auth,
                } => {
                    nc_put_chunk(&*http, &tx_dir_url, auth.as_deref(), chunk_index, data).await?;
                }
                WriteAction::TusPatch {
                    upload_url,
                    offset,
                    data,
                    auth,
                } => {
                    tus_patch_chunk(&*http, &upload_url, auth.as_deref(), offset, data).await?;
                }
                WriteAction::StreamPush {
                    stream_handle,
                    data,
                } => {
                    http.put_stream_write(stream_handle, data).await?;
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
                    tx_dir_url: String,
                    dest_url: String,
                    total_size: u64,
                    chunk_index: u32,
                    remaining: Vec<u8>,
                    etag: Option<String>,
                    auth: Option<String>,
                },
                TusComplete {
                    dest_url: String,
                },
                PutBuffer {
                    path: String,
                    data: Vec<u8>,
                    options: UploadOptions,
                    auth: Option<String>,
                },
                StreamingClose {
                    dest_url: String,
                    stream_handle: String,
                },
            }

            let action = {
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                let auth = s.auth_header.clone();
                if let Some(session) = s.chunk_sessions.remove(&stream_id) {
                    match session {
                        ChunkSession::NcV2 {
                            tx_dir_url,
                            dest_url,
                            total_size,
                            chunk_index,
                            buffer,
                            options,
                        } => CloseAction::NcAssemble {
                            tx_dir_url,
                            dest_url,
                            total_size,
                            chunk_index,
                            remaining: buffer,
                            etag: options.expected_version.clone(),
                            auth,
                        },
                        ChunkSession::Tus { upload_url, .. } => {
                            // Last PATCH already sent 100% of data; no extra call needed.
                            CloseAction::TusComplete {
                                dest_url: upload_url,
                            }
                        }
                        ChunkSession::StreamingPut {
                            dest_url,
                            stream_handle,
                        } => CloseAction::StreamingClose {
                            dest_url,
                            stream_handle,
                        },
                    }
                } else if let Some(buf) = s.upload_buffers.remove(&stream_id) {
                    CloseAction::PutBuffer {
                        path: buf.path,
                        data: buf.data,
                        options: buf.options,
                        auth,
                    }
                } else {
                    return Err(ProviderError::Provider(format!(
                        "unknown stream_id: {stream_id}"
                    )));
                }
            };

            match action {
                CloseAction::NcAssemble {
                    tx_dir_url,
                    dest_url,
                    total_size,
                    chunk_index,
                    remaining,
                    etag,
                    auth,
                } => {
                    // PUT remaining bytes as the final chunk (NC requires at least one chunk).
                    nc_put_chunk(&*http, &tx_dir_url, auth.as_deref(), chunk_index, remaining)
                        .await?;
                    // MOVE .file to final destination — assembles all numbered chunks.
                    nc_move_assemble(
                        &*http,
                        &tx_dir_url,
                        &dest_url,
                        auth.as_deref(),
                        total_size,
                        etag.as_deref(),
                    )
                    .await?;
                    // HEAD the assembled file to read its ETag.
                    let mut req = ProviderHttpRequest::new("HEAD".to_string(), dest_url.clone());
                    if let Some(v) = &auth {
                        req = req.header(("Authorization".to_string(), v.clone()));
                    }
                    let resp = http.request(req).await?;
                    let version = resp.header("etag").map(normalize_etag).unwrap_or_default();
                    Ok(UploadResult {
                        ref_: dest_url,
                        version,
                    })
                }
                CloseAction::TusComplete { dest_url } => {
                    // tus upload already complete; ETag not available without HEAD.
                    Ok(UploadResult {
                        ref_: dest_url,
                        version: String::new(),
                    })
                }
                CloseAction::PutBuffer {
                    path,
                    data,
                    options,
                    auth,
                } => {
                    let mut req = ProviderHttpRequest::put(path.clone())
                        .header((
                            "Content-Type".to_string(),
                            "application/octet-stream".to_string(),
                        ))
                        .body(data);
                    if let Some(v) = &auth {
                        req = req.header(("Authorization".to_string(), v.clone()));
                    }
                    if let Some(etag) = &options.expected_version {
                        req = req.header(("If-Match".to_string(), fmt_if_match(etag)));
                    }
                    let resp = http.request(req).await?;
                    if resp.status != 201 && resp.status != 204 {
                        if let Some(e) = map_http_status(resp.status, &resp.body) {
                            return Err(e);
                        }
                    }
                    let version = resp.header("etag").map(normalize_etag).unwrap_or_default();
                    Ok(UploadResult {
                        ref_: path,
                        version,
                    })
                }
                CloseAction::StreamingClose {
                    dest_url,
                    stream_handle,
                } => {
                    let resp = http.put_stream_close(stream_handle).await?;
                    if resp.status != 201 && resp.status != 204 && resp.status != 200 {
                        if let Some(e) = map_http_status(resp.status, &resp.body) {
                            return Err(e);
                        }
                    }
                    let version = resp.header("etag").map(normalize_etag).unwrap_or_default();
                    Ok(UploadResult {
                        ref_: dest_url,
                        version,
                    })
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
                let mut s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                        if let Some(v) = &auth {
                            req = req.header(("Authorization".to_string(), v.clone()));
                        }
                        let _ = http.request(req).await;
                    }
                    ChunkSession::StreamingPut { stream_handle, .. } => {
                        // Best-effort — aborting a half-uploaded PUT simply
                        // cancels the fetch; the server is free to 400 or
                        // discard the partial body.
                        let _ = http.put_stream_abort(stream_handle).await;
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
            let (base, auth) = {
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
                (s.server_url.clone(), s.auth_header.clone())
            };
            let url = match parent_ref {
                Some(p) if !p.is_empty() => resolve_dav_ref(&base, &p)?,
                _ => dav_url(&base, "/WattcloudVault/"),
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
            // Filter out the parent directory itself (the first entry PROPFIND
            // returns at Depth:1 is always the requested resource). Compare
            // URL paths rather than strings: NC returns server-absolute
            // hrefs like `/remote.php/dav/files/alice/WattcloudVault/` while
            // our request URL is an absolute URL. Normalising both to their
            // URL paths lets us compare regardless of shape.
            let request_path = url_path(&url).trim_end_matches('/').to_string();
            entries.retain(|e| {
                let e_path = url_path(&e.ref_).trim_end_matches('/');
                e_path != request_path
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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
                _ => dav_url(&base, &format!("/WattcloudVault/{name}")),
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
                let s = state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
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

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "Public links not yet implemented for webdav".into(),
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
            "Presigned URLs not yet implemented for webdav".into(),
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::type_complexity, clippy::manual_async_fn)]
mod tests {
    use super::*;
    use crate::api::{ProviderHttpRequest, ProviderHttpResponse, StreamingPutClient};
    use std::sync::Mutex;

    /// Mock that records a single streaming PUT: headers on open, the
    /// concatenated chunk bytes on close, and returns a canned response.
    #[derive(Default)]
    struct StreamRecorder {
        enabled: bool,
        chunks: Mutex<Vec<u8>>,
        headers: Mutex<Vec<(String, String)>>,
        close_response: Mutex<Option<(u16, Vec<u8>, Vec<(String, String)>)>>,
    }

    struct MockHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        stream: StreamRecorder,
    }

    impl MockHttp {
        fn new(r: Vec<(u16, Vec<u8>, Vec<(String, String)>)>) -> Self {
            Self {
                responses: Mutex::new(r),
                stream: StreamRecorder::default(),
            }
        }

        /// Enable the StreamingPutClient path and stage the response the
        /// close call will return.
        fn with_streaming(mut self, close: (u16, Vec<u8>, Vec<(String, String)>)) -> Self {
            self.stream.enabled = true;
            *self.stream.close_response.lock().unwrap() = Some(close);
            self
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

    impl StreamingPutClient for MockHttp {
        fn supports_streaming_put(&self) -> bool {
            self.stream.enabled
        }

        fn put_stream_open(
            &self,
            _url: String,
            headers: Vec<(String, String)>,
            _content_length: Option<u64>,
        ) -> impl std::future::Future<Output = Result<String, ProviderError>> + Send {
            *self.stream.headers.lock().unwrap() = headers;
            async move { Ok("mock-stream-1".to_string()) }
        }

        fn put_stream_write(
            &self,
            _handle: String,
            chunk: Vec<u8>,
        ) -> impl std::future::Future<Output = Result<(), ProviderError>> + Send {
            self.stream.chunks.lock().unwrap().extend_from_slice(&chunk);
            async move { Ok(()) }
        }

        fn put_stream_close(
            &self,
            _handle: String,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            let resp = self
                .stream
                .close_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or((500, b"no streaming response".to_vec(), vec![]));
            async move {
                Ok(ProviderHttpResponse {
                    status: resp.0,
                    headers: resp.2,
                    body: resp.1,
                })
            }
        }

        fn put_stream_abort(
            &self,
            _handle: String,
        ) -> impl std::future::Future<Output = Result<(), ProviderError>> + Send {
            async move { Ok(()) }
        }
    }

    fn make_provider(
        responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>,
    ) -> WebDAVProvider<MockHttp> {
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
            .upload(
                None,
                "file.bin".into(),
                b"data".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert!(result.ref_.contains("WattcloudVault"));
        assert_eq!(result.version, "etag123");
    }

    #[tokio::test]
    async fn upload_412_conflict() {
        let p = make_provider(vec![(412, b"".to_vec(), vec![])]);
        let err = p
            .upload(
                Some("/WattcloudVault/f.bin".into()),
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
        let data = p.download("/WattcloudVault/f.bin".into()).await.unwrap();
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
        p.upload_stream_write(sid.clone(), b"hello".to_vec())
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        assert_eq!(result.version, "etag456");
    }

    #[tokio::test]
    async fn download_stream_roundtrip() {
        let p = make_provider(vec![(200, b"streamed".to_vec(), vec![])]);
        let sid = p
            .download_stream_open("/WattcloudVault/f.bin".into())
            .await
            .unwrap();
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

    fn make_nc_provider(
        responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>,
    ) -> WebDAVProvider<MockHttp> {
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

    fn make_tus_provider(
        responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>,
    ) -> WebDAVProvider<MockHttp> {
        let p = WebDAVProvider::new(MockHttp::new(responses));
        {
            let mut s = p.state.lock().unwrap();
            s.server_url = "https://tus.example.com".to_string();
            s.auth_header = Some("Basic dXNlcjpwYXNz".to_string());
            s.capabilities = WebDavCapabilities::Tus;
        }
        p
    }

    fn make_streaming_provider(
        close: (u16, Vec<u8>, Vec<(String, String)>),
    ) -> WebDAVProvider<MockHttp> {
        let p = WebDAVProvider::new(MockHttp::new(vec![]).with_streaming(close));
        {
            let mut s = p.state.lock().unwrap();
            s.server_url = "https://dav.example.com".to_string();
            s.auth_header = Some("Basic dXNlcjpwYXNz".to_string());
            s.capabilities = WebDavCapabilities::StreamingPut;
        }
        p
    }

    #[test]
    fn parse_quota_available_extracts_nc_response() {
        let body = br#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/remote.php/dav/files/alice/</d:href>
    <d:propstat>
      <d:prop>
        <d:quota-available-bytes>5368709120</d:quota-available-bytes>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
        assert_eq!(parse_quota_available(body), Some(5_368_709_120));
    }

    #[test]
    fn parse_quota_available_missing_returns_none() {
        // Server that doesn't implement RFC 4331 returns propstat with 404
        // and no value for the requested property.
        let body = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        assert_eq!(parse_quota_available(body), None);
    }

    #[tokio::test]
    async fn large_upload_rejected_when_quota_insufficient() {
        // Server returns 207 with quota-available-bytes=100 but caller wants
        // to upload 100 MiB + 1 byte (just over the preflight threshold).
        let quota_body = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:propstat><D:prop>
      <D:quota-available-bytes>100</D:quota-available-bytes>
    </D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;

        let p = make_provider(vec![(207, quota_body.to_vec(), vec![])]);
        {
            let mut s = p.state.lock().unwrap();
            s.capabilities = WebDavCapabilities::BufferThenPut;
        }
        let err = p
            .upload_stream_open(
                None,
                "big.bin".into(),
                PREFLIGHT_QUOTA_MIN_BYTES + 1,
                UploadOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::InsufficientSpace {
                needed,
                available: 100
            } if needed == PREFLIGHT_QUOTA_MIN_BYTES + 1
        ));
    }

    #[tokio::test]
    async fn large_upload_allowed_when_server_hides_quota() {
        // 207 without the quota element (generic mod_dav): skip silently,
        // proceed to the capability path.
        let quota_body = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:propstat><D:prop><D:resourcetype/></D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;

        let p = make_provider(vec![
            (207, quota_body.to_vec(), vec![]),
            (201, b"".to_vec(), vec![("etag".into(), "\"x\"".into())]), // PUT
        ]);
        {
            let mut s = p.state.lock().unwrap();
            s.capabilities = WebDavCapabilities::BufferThenPut;
        }
        let sid = p
            .upload_stream_open(
                None,
                "big.bin".into(),
                PREFLIGHT_QUOTA_MIN_BYTES + 1,
                UploadOptions::default(),
            )
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"x".to_vec())
            .await
            .unwrap();
        p.upload_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn quota_preflight_skipped_for_small_uploads() {
        // Under the threshold — no PROPFIND issued; mock only needs the PUT.
        let p = make_provider(vec![(
            201,
            b"".to_vec(),
            vec![("etag".into(), "\"x\"".into())],
        )]);
        {
            let mut s = p.state.lock().unwrap();
            s.capabilities = WebDavCapabilities::BufferThenPut;
        }
        let sid = p
            .upload_stream_open(None, "tiny.bin".into(), 128, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"x".to_vec())
            .await
            .unwrap();
        p.upload_stream_close(sid).await.unwrap();
    }

    #[tokio::test]
    async fn streaming_put_roundtrip_forwards_chunks_and_parses_etag() {
        // Two chunks pushed via the streaming client, close returns 201 + ETag.
        let p = make_streaming_provider((
            201,
            b"".to_vec(),
            vec![("etag".to_string(), "\"stream-etag\"".to_string())],
        ));

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

        assert_eq!(result.version, "stream-etag");
        // Body accumulated inside the MockHttp stream recorder reflects
        // everything the Rust side pushed across the boundary.
        assert_eq!(&p.http.stream.chunks.lock().unwrap()[..], b"helloworld");
        // Content-Length header was forwarded on open (known total_size).
        let hdrs = p.http.stream.headers.lock().unwrap();
        assert!(hdrs
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/octet-stream"));
        assert!(hdrs
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Basic dXNlcjpwYXNz"));
    }

    #[tokio::test]
    async fn streaming_put_abort_calls_put_stream_abort() {
        let p = make_streaming_provider((200, vec![], vec![])); // close never reached
        let sid = p
            .upload_stream_open(None, "x".into(), 10, UploadOptions::default())
            .await
            .unwrap();
        // No writes; go straight to abort.
        p.upload_stream_abort(sid).await.unwrap();
    }

    #[tokio::test]
    async fn streaming_put_supports_expected_version_as_if_match() {
        let p = make_streaming_provider((
            204,
            b"".to_vec(),
            vec![("etag".to_string(), "\"new-v\"".to_string())],
        ));
        let sid = p
            .upload_stream_open(
                None,
                "x".into(),
                3,
                UploadOptions {
                    expected_version: Some("prev-v".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"abc".to_vec())
            .await
            .unwrap();
        p.upload_stream_close(sid).await.unwrap();
        let hdrs = p.http.stream.headers.lock().unwrap();
        assert!(
            hdrs.iter()
                .any(|(k, v)| k == "If-Match" && v == "\"prev-v\""),
            "got {:?}",
            *hdrs
        );
    }

    #[tokio::test]
    async fn nc_v2_small_file_bypass_uses_single_put() {
        // Files < NC_MIN_CHUNK_SIZE on a Nextcloud server must bypass the 4-round-trip
        // MKCOL+PUT+MOVE path and use a single PUT (BufferThenPut) instead.
        // Sequence: PUT only (no MKCOL, no MOVE, no HEAD)
        let p = make_nc_provider(vec![
            (
                201,
                b"".to_vec(),
                vec![("etag".to_string(), "\"put-etag\"".to_string())],
            ), // PUT
        ]);
        let sid = p
            .upload_stream_open(None, "data.bin".into(), 5, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec())
            .await
            .unwrap();
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
            (201, b"".to_vec(), vec![]), // MKCOL
            (201, b"".to_vec(), vec![]), // PUT 00001 (flush)
            (201, b"".to_vec(), vec![]), // PUT 00002 (empty final)
            (201, b"".to_vec(), vec![]), // MOVE
            (
                200,
                b"".to_vec(),
                vec![("etag".to_string(), "\"nc-etag\"".to_string())],
            ), // HEAD
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
            (201, b"".to_vec(), vec![]), // MKCOL
            (201, b"".to_vec(), vec![]), // PUT 00001
            (201, b"".to_vec(), vec![]), // PUT 00002
            (201, b"".to_vec(), vec![]), // PUT 00003 (final)
            (201, b"".to_vec(), vec![]), // MOVE
            (
                200,
                b"".to_vec(),
                vec![("etag".to_string(), "\"nc-etag2\"".to_string())],
            ), // HEAD
        ]);
        let total = (chunk.len() * 2) as u64;
        let sid = p
            .upload_stream_open(None, "large.bin".into(), total, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), chunk.clone())
            .await
            .unwrap(); // triggers flush (PUT 00001)
        p.upload_stream_write(sid.clone(), chunk.clone())
            .await
            .unwrap(); // triggers flush (PUT 00002)
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
            (
                201,
                b"".to_vec(),
                vec![(
                    "location".to_string(),
                    "https://tus.example.com/files/abc".to_string(),
                )],
            ), // POST
            (204, b"".to_vec(), vec![]), // PATCH
        ]);
        let sid = p
            .upload_stream_open(None, "data.bin".into(), 5, UploadOptions::default())
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), b"hello".to_vec())
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();
        // tus close returns empty version (no HEAD)
        assert_eq!(result.version, "");
    }

    // ── init() credential validation ──────────────────────────────────────────

    /// Helper: spin up a fresh WebDAVProvider and run init() against a mock
    /// HTTP client with the given response queue. probe_capabilities consumes
    /// two responses (NC PROPFIND + tus OPTIONS) before verify_webdav_auth
    /// consumes its PROPFIND — so `responses` must supply three entries in
    /// that order.
    fn init_webdav_provider(
        responses: Vec<(u16, Vec<u8>, Vec<(String, String)>)>,
    ) -> (WebDAVProvider<MockHttp>, ProviderConfig) {
        let p = WebDAVProvider::new(MockHttp::new(responses));
        let cfg = ProviderConfig {
            type_: ProviderType::Webdav,
            server_url: Some("https://dav.example.com".to_string()),
            username: Some("alice".to_string()),
            password: Some("s3cr3t".to_string()),
            ..Default::default()
        };
        (p, cfg)
    }

    #[tokio::test]
    async fn init_succeeds_when_credentials_accepted() {
        // probe NC PROPFIND → 404 (non-NC); probe OPTIONS → 200; verify PROPFIND → 207.
        let (p, cfg) = init_webdav_provider(vec![
            (404, b"".to_vec(), vec![]),
            (200, b"".to_vec(), vec![]),
            (207, b"".to_vec(), vec![]),
        ]);
        p.init(cfg).await.unwrap();
        assert!(p.is_ready());
    }

    #[tokio::test]
    async fn init_fails_fast_on_401() {
        // Regression: init() silently accepted wrong credentials because
        // probe_capabilities never fails. Now a 401 from the dedicated
        // auth probe propagates as ProviderError::Unauthorized.
        let (p, cfg) = init_webdav_provider(vec![
            (401, b"".to_vec(), vec![]), // NC PROPFIND
            (200, b"".to_vec(), vec![]), // OPTIONS (often unauthenticated)
            (401, b"".to_vec(), vec![]), // verify_webdav_auth
        ]);
        let err = p.init(cfg).await.unwrap_err();
        assert!(matches!(err, ProviderError::Unauthorized), "got {err:?}");
        assert!(!p.is_ready());
    }

    #[tokio::test]
    async fn init_fails_fast_on_403() {
        let (p, cfg) = init_webdav_provider(vec![
            (403, b"".to_vec(), vec![]),
            (200, b"".to_vec(), vec![]),
            (403, b"".to_vec(), vec![]),
        ]);
        let err = p.init(cfg).await.unwrap_err();
        assert!(matches!(err, ProviderError::Forbidden), "got {err:?}");
        assert!(!p.is_ready());
    }

    #[tokio::test]
    async fn init_fails_fast_on_5xx() {
        // Broken server: don't silently succeed — the user would then
        // see operation-time failures with no explanation.
        let (p, cfg) = init_webdav_provider(vec![
            (404, b"".to_vec(), vec![]),            // NC PROPFIND
            (200, b"".to_vec(), vec![]),            // OPTIONS
            (502, b"Bad Gateway".to_vec(), vec![]), // verify_webdav_auth
        ]);
        let err = p.init(cfg).await.unwrap_err();
        assert!(matches!(err, ProviderError::Provider(_)), "got {err:?}");
        assert!(!p.is_ready());
    }

    #[tokio::test]
    async fn init_tolerates_root_propfind_404() {
        // Some servers expose DAV only under a sub-path and return 404 for
        // PROPFIND on the root. init() must not fail init() in that case —
        // the user's operations target /WattcloudVault/ (created on demand).
        let (p, cfg) = init_webdav_provider(vec![
            (404, b"".to_vec(), vec![]),
            (200, b"".to_vec(), vec![]),
            (404, b"".to_vec(), vec![]),
        ]);
        // 404 on root PROPFIND is not an auth error; init must still succeed.
        p.init(cfg).await.unwrap();
        assert!(p.is_ready());
    }

    // ── resolve_dav_ref ───────────────────────────────────────────────────────

    #[test]
    fn resolve_dav_ref_abs_path_joins_origin_not_base() {
        // Regression: Nextcloud returns absolute-path hrefs from PROPFIND, and
        // the user's `server_url` typically already includes the NC DAV prefix.
        // resolve_dav_ref used to do `{base}{ref}` and produce a doubled path.
        let base = "https://cloud.example.com/remote.php/dav/files/alice";
        let ref_ = "/remote.php/dav/files/alice/WattcloudVault/photo.jpg";
        let resolved = resolve_dav_ref(base, ref_).unwrap();
        assert_eq!(
            resolved,
            "https://cloud.example.com/remote.php/dav/files/alice/WattcloudVault/photo.jpg",
            "abs-path refs must join the base origin, not the full base URL"
        );
    }

    #[test]
    fn resolve_dav_ref_relative_ref_joins_full_base() {
        // Non-abs refs (bare name) still stitch onto the full base so upload
        // target URLs remain correct for callers that pass a plain filename.
        let base = "https://dav.example.com/webdav";
        assert_eq!(
            resolve_dav_ref(base, "WattcloudVault/file.bin").unwrap(),
            "https://dav.example.com/webdav/WattcloudVault/file.bin"
        );
    }

    #[test]
    fn resolve_dav_ref_absolute_url_passes_through_same_origin() {
        let base = "https://dav.example.com/webdav";
        let ref_ = "https://dav.example.com/webdav/WattcloudVault/a";
        assert_eq!(resolve_dav_ref(base, ref_).unwrap(), ref_);
    }

    #[test]
    fn resolve_dav_ref_absolute_url_cross_origin_rejected() {
        let base = "https://dav.example.com/webdav";
        let ref_ = "https://attacker.example.com/webdav/WattcloudVault/a";
        assert!(resolve_dav_ref(base, ref_).is_err());
    }

    #[test]
    fn resolve_dav_ref_rejects_path_traversal() {
        let base = "https://dav.example.com/webdav";
        assert!(resolve_dav_ref(base, "/WattcloudVault/../../etc/passwd").is_err());
        assert!(resolve_dav_ref(base, "WattcloudVault/../etc/passwd").is_err());
    }

    #[tokio::test]
    async fn parse_propfind_xml() {
        let xml = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/WattcloudVault/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/WattcloudVault/photo.jpg</D:href>
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

    #[test]
    fn url_path_normalises_mixed_shapes() {
        assert_eq!(url_path("https://dav.example.com/a/b"), "/a/b");
        assert_eq!(url_path("https://dav.example.com/"), "/");
        assert_eq!(url_path("https://dav.example.com"), "/");
        assert_eq!(
            url_path("/remote.php/dav/files/alice/x/"),
            "/remote.php/dav/files/alice/x/"
        );
        assert_eq!(url_path("bare/path"), "bare/path");
    }

    #[test]
    fn is_nc_response_matches_known_fingerprints() {
        use crate::api::provider_http::ProviderHttpResponse;
        let base = |headers: Vec<(&str, &str)>, body: &str| ProviderHttpResponse {
            status: 207,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        };
        // Server header identifying NC / OC.
        assert!(is_nc_response(&base(
            vec![("server", "Nextcloud/27.1.0")],
            ""
        )));
        assert!(is_nc_response(&base(vec![("Server", "ownCloud/10")], "")));
        // DAV capability header with NC/OC tokens.
        assert!(is_nc_response(&base(
            vec![("DAV", "1, 3, extended-mkcol, nc-uploads")],
            ""
        )));
        // NC namespace in response body.
        assert!(is_nc_response(&base(
            vec![],
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">"
        )));
        // No fingerprints → not NC (was previously misclassified by bare 207).
        assert!(!is_nc_response(&base(
            vec![("server", "nginx/1.25")],
            "<d:multistatus xmlns:d=\"DAV:\"></d:multistatus>"
        )));
    }

    #[test]
    fn percent_decode_handles_common_encodings() {
        assert_eq!(percent_decode("My%20Folder"), "My Folder");
        assert_eq!(percent_decode("%C3%A9tude"), "étude"); // UTF-8 two-byte seq
        assert_eq!(percent_decode("a+b"), "a+b"); // `+` is not decoded (RFC 3986)
        assert_eq!(percent_decode("no-percent"), "no-percent");
        // Invalid escape: pass through verbatim rather than erroring.
        assert_eq!(percent_decode("%GZ"), "%GZ");
        // Short trailing escape: pass through.
        assert_eq!(percent_decode("ab%2"), "ab%2");
    }

    #[tokio::test]
    async fn parse_propfind_decodes_display_name() {
        let xml = br#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/WattcloudVault/My%20Folder/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/WattcloudVault/My%20Folder/caf%C3%A9.sc</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>42</D:getcontentlength>
      </D:prop>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let entries = parse_propfind(xml, "https://dav.example.com").unwrap();
        let folder = entries.iter().find(|e| e.is_folder).unwrap();
        assert_eq!(folder.name, "My Folder", "folder name should decode %20");
        // Stored ref preserves the encoded form so it round-trips against the
        // server verbatim.
        assert!(folder.ref_.contains("My%20Folder"));
        let file = entries.iter().find(|e| !e.is_folder).unwrap();
        assert_eq!(file.name, "café.sc", "file name should decode %C3%A9 as é");
    }
}
