// S3-family storage provider implementation.
//
// Covers: AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO, and any
// S3-compatible endpoint.
//
// API: S3 REST API (CreateMultipartUpload / UploadPart / CompleteMultipartUpload)
// Auth: AWS Signature Version 4, UNSIGNED-PAYLOAD (acceptable over TLS)
// Ref: object key (e.g. "SecureCloud/abc123.v7")
// Version: ETag from object HEAD/GET response headers
// Conflict: ETag-based optimistic concurrency via If-Match (PUT)
// Upload: single PUT for blobs; multipart (8 MiB parts) for streams
// Listing: ListObjectsV2 with prefix + "/" delimiter
//
// All object keys are prefixed with "SecureCloud/" to avoid namespace
// collisions with user-managed objects in the same bucket.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    current_time_ms, make_http_call_fn, map_http_status, new_stream_id, MakeHeaders,
    RangedDownloadBuffer,
};

const SECURECLOUD_PREFIX: &str = "SecureCloud/";
/// Minimum S3 part size (all parts except the last must be ≥ 5 MiB).
#[allow(dead_code)]
const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
/// Preferred part size (8 MiB — matches SFTP relay chunks, comfortably above minimum).
const PART_SIZE: usize = 8 * 1024 * 1024;
/// Maximum TTL for presigned URLs (24 hours per plan security constraint).
const MAX_PRESIGN_TTL: u32 = 86_400;

// ─── SigV4 signing ────────────────────────────────────────────────────────────

mod sigv4 {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Format a Unix timestamp (seconds) as an ISO8601 compact string: `YYYYMMDDTHHMMSSZ`.
    pub fn iso8601(ts_secs: i64) -> String {
        let secs = ts_secs as u64;
        // Very simple integer-only ISO8601 formatter; avoids chrono/time dependency.
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days = secs / 86400; // days since Unix epoch

        // Gregorian calendar conversion (Gregorian proleptic calendar, 1970-01-01 = day 0).
        let (year, month, day) = days_to_ymd(days);
        format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{s:02}Z")
    }

    /// Return the date part (`YYYYMMDD`) from a Unix timestamp.
    pub fn date(ts_secs: i64) -> String {
        let days = ts_secs as u64 / 86400;
        let (y, m, d) = days_to_ymd(days);
        format!("{y:04}{m:02}{d:02}")
    }

    fn days_to_ymd(days: u64) -> (u64, u64, u64) {
        // Algorithm from http://howardhinnant.github.io/date_algorithms.html
        let z = days + 719468;
        let era = z / 146097;
        let doe = z % 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        (y, m, d)
    }

    /// Compute SHA-256 and return as lowercase hex.
    pub fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex_lower(&hasher.finalize())
    }

    /// Compute HMAC-SHA256.
    #[allow(clippy::expect_used)] // HMAC-SHA256 accepts any key length; key is always 32 bytes here
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const EMPTY_BODY_SHA256: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Percent-encode a string per RFC 3986 (only unreserved chars are not encoded).
    /// `encode_slash`: if false, "/" is left as-is (for URI path segments).
    pub fn percent_encode(s: &str, encode_slash: bool) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                out.push(c);
            } else if c == '/' && !encode_slash {
                out.push('/');
            } else {
                for byte in c.to_string().as_bytes() {
                    out.push_str(&format!("%{byte:02X}"));
                }
            }
        }
        out
    }

    /// Build the AWS SigV4 Authorization header for a request.
    ///
    /// `method`: uppercase HTTP method ("GET", "PUT", etc.)
    /// `path`: URI path (already percent-encoded)
    /// `query`: query string (already sorted, percent-encoded key=value pairs joined by &)
    /// `host`: Host header value
    /// `additional_headers`: sorted list of (lowercase_name, value) pairs to sign
    /// `payload_hash`: "UNSIGNED-PAYLOAD" or SHA256 of body
    /// `region`, `access_key`, `secret_key`
    /// `ts_secs`: timestamp (seconds since Unix epoch)
    ///
    /// Returns the `Authorization` header value.
    #[allow(clippy::too_many_arguments)]
    pub fn authorization(
        method: &str,
        path: &str,
        query: &str,
        host: &str,
        additional_headers: &[(String, String)],
        payload_hash: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        ts_secs: i64,
    ) -> String {
        let ts = iso8601(ts_secs);
        let date = date(ts_secs);
        let credential_scope = format!("{date}/{region}/s3/aws4_request");

        // Build canonical headers: host + x-amz-content-sha256 + x-amz-date + additional.
        let mut canon_headers: Vec<(String, String)> = vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), ts.clone()),
        ];
        for (k, v) in additional_headers {
            canon_headers.push((k.to_lowercase(), v.trim().to_string()));
        }
        canon_headers.sort_by(|a, b| a.0.cmp(&b.0));
        canon_headers.dedup_by(|a, b| {
            if a.0 == b.0 { b.1.push(','); b.1.push_str(&a.1); true } else { false }
        });

        let signed_headers: String = canon_headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canonical_headers: String = canon_headers.iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect();

        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{ts}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
             SignedHeaders={signed_headers}, Signature={signature}"
        )
    }

    /// Build a presigned URL for a GET request.
    ///
    /// Returns the full URL with SigV4 query parameters appended.
    #[allow(clippy::too_many_arguments)]
    pub fn presign_url(
        base_url: &str,
        host: &str,
        path: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        ts_secs: i64,
        ttl_secs: u32,
    ) -> String {
        let ts = iso8601(ts_secs);
        let date = date(ts_secs);
        let credential_scope = format!("{date}/{region}/s3/aws4_request");
        let credential = format!("{access_key}/{credential_scope}");

        // Build canonical query string (params must be sorted by name).
        //
        // B13: do NOT put `X-Amz-Content-Sha256` in the query string — standard
        // SigV4 presigned URLs only carry it as a signed *header* (and we don't
        // sign any non-host header here, so it isn't part of `signed_headers`
        // either). Some S3-compatible endpoints (R2, MinIO) reject unknown
        // query parameters on presigned GETs.
        let signed_headers = "host";
        let mut query_params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
            ("X-Amz-Credential", percent_encode(&credential, true)),
            ("X-Amz-Date", ts.clone()),
            ("X-Amz-Expires", ttl_secs.to_string()),
            ("X-Amz-SignedHeaders", signed_headers.to_string()),
        ];
        query_params.sort_by(|a, b| a.0.cmp(b.0));
        let query: String = query_params.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_headers = format!("host:{host}\n");
        let canonical_request = format!(
            "GET\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{EMPTY_BODY_SHA256}"
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{ts}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let sig = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        format!("{base_url}?{query}&X-Amz-Signature={sig}")
    }
}

// ─── State ────────────────────────────────────────────────────────────────────

struct MultipartSession {
    upload_id: String,
    key: String,
    parts: Vec<(u32, String)>, // (part_number, etag)
    next_part: u32,
    buffer: Vec<u8>,
}

struct S3State {
    config: Option<S3Config>,
    upload_sessions: HashMap<String, MultipartSession>,
    download_buffers: HashMap<String, RangedDownloadBuffer>,
}

#[derive(Clone)]
struct S3Config {
    endpoint: String,
    host: String,
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    path_style: bool,
}

fn lock_err() -> ProviderError {
    ProviderError::Provider("state lock poisoned".to_string())
}

// ─── Provider struct ──────────────────────────────────────────────────────────

pub struct S3Provider<H: ProviderHttpClient> {
    http: Arc<H>,
    state: Arc<Mutex<S3State>>,
}

impl<H: ProviderHttpClient> S3Provider<H> {
    pub fn new(http: H) -> Self {
        Self {
            http: Arc::new(http),
            state: Arc::new(Mutex::new(S3State {
                config: None,
                upload_sessions: HashMap::new(),
                download_buffers: HashMap::new(),
            })),
        }
    }

    /// Validate an S3 bucket name against the AWS naming rules (P3).
    ///
    /// Length 3–63, lowercase letters/digits/hyphens/periods, starts and ends
    /// with alphanumeric, no consecutive periods, no IP-like all-numeric, and
    /// must not start with the `xn--` / `sthree-` reserved prefixes. This
    /// prevents a malicious bucket name (e.g. `.attacker.com`) from being
    /// interpolated into the virtual-hosted host and redirecting signed
    /// requests to an attacker-controlled domain.
    fn is_valid_s3_bucket_name(s: &str) -> bool {
        if s.len() < 3 || s.len() > 63 { return false; }
        if !s.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '.')) { return false; }
        let first = match s.chars().next() { Some(c) => c, None => return false };
        let last = match s.chars().last() { Some(c) => c, None => return false };
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() { return false; }
        if s.contains("..") { return false; }
        if s.starts_with("xn--") || s.starts_with("sthree-") { return false; }
        // Reject all-numeric-with-dots (would match an IPv4 literal).
        if s.chars().all(|c| c.is_ascii_digit() || c == '.') { return false; }
        true
    }

    /// Resolve config fields into an `S3Config` (normalises endpoint, detects path-style).
    fn build_config(cfg: &ProviderConfig) -> Result<S3Config, ProviderError> {
        let region = cfg.s3_region.clone().unwrap_or_else(|| "us-east-1".to_string());
        let bucket = cfg.s3_bucket.clone().ok_or_else(|| ProviderError::Provider("s3_bucket required".into()))?;
        let access_key_id = cfg.s3_access_key_id.clone().ok_or_else(|| ProviderError::Provider("s3_access_key_id required".into()))?;
        let secret_access_key = cfg.s3_secret_access_key.clone().ok_or_else(|| ProviderError::Provider("s3_secret_access_key required".into()))?;
        let path_style = cfg.s3_path_style.unwrap_or(false);

        // P3/SSRF: validate the endpoint for scheme + private-IP before
        // trusting it as the target for every signed S3 request. Previously
        // accepted http://169.254.169.254 (AWS metadata) and other internal
        // hosts verbatim.
        let (endpoint, host) = if let Some(ep) = &cfg.s3_endpoint {
            let ep = ep.trim_end_matches('/');
            let parsed = super::url_guard::validate_config_url(ep)?;
            let host = parsed
                .host_str()
                .ok_or_else(|| ProviderError::Provider("s3_endpoint has no host".into()))?
                .to_string();
            (ep.to_string(), host)
        } else if path_style {
            let host = format!("s3.{region}.amazonaws.com");
            (format!("https://{host}"), host)
        } else {
            // P3: bucket name flows into the virtual-hosted hostname — validate
            // against S3 bucket naming rules (3–63 chars, [a-z0-9.-] with
            // stricter start/end). This also blocks a hostile bucket such as
            // `.attacker.com` (would yield `.attacker.com.s3.us-east-1…`).
            if !Self::is_valid_s3_bucket_name(&bucket) {
                return Err(ProviderError::Provider(format!(
                    "invalid s3_bucket name: {bucket}"
                )));
            }
            let host = format!("{bucket}.s3.{region}.amazonaws.com");
            (format!("https://{host}"), host)
        };

        Ok(S3Config { endpoint, host, region, bucket, access_key_id, secret_access_key, path_style })
    }

    /// Build the full URL for an object key, respecting path-style vs virtual-hosted.
    fn object_url(cfg: &S3Config, key: &str) -> String {
        let encoded_key = sigv4::percent_encode(key, false);
        if cfg.path_style || cfg.s3_path_style_from_ep(&cfg.endpoint) {
            format!("{}/{}/{}", cfg.endpoint, cfg.bucket, encoded_key)
        } else {
            format!("{}/{}", cfg.endpoint, encoded_key)
        }
    }

    /// Build the path component for signing (without host and without query string).
    fn object_path(cfg: &S3Config, key: &str) -> String {
        let encoded_key = sigv4::percent_encode(key, false);
        if cfg.path_style || cfg.s3_path_style_from_ep(&cfg.endpoint) {
            format!("/{}/{}", cfg.bucket, encoded_key)
        } else {
            format!("/{}", encoded_key)
        }
    }

    fn bucket_url(cfg: &S3Config) -> String {
        if cfg.path_style || cfg.s3_path_style_from_ep(&cfg.endpoint) {
            format!("{}/{}", cfg.endpoint, cfg.bucket)
        } else {
            cfg.endpoint.clone()
        }
    }

    fn bucket_path(cfg: &S3Config) -> String {
        if cfg.path_style || cfg.s3_path_style_from_ep(&cfg.endpoint) {
            format!("/{}", cfg.bucket)
        } else {
            "/".to_string()
        }
    }

    /// Build SigV4 Authorization + date headers for a request.
    fn auth_headers(
        cfg: &S3Config,
        method: &str,
        path: &str,
        query: &str,
        additional_headers: &[(String, String)],
        ts_secs: i64,
    ) -> Vec<(String, String)> {
        let payload_hash = "UNSIGNED-PAYLOAD";
        let auth = sigv4::authorization(
            method, path, query, &cfg.host, additional_headers, payload_hash,
            &cfg.region, &cfg.access_key_id, &cfg.secret_access_key, ts_secs,
        );
        let ts = sigv4::iso8601(ts_secs);
        vec![
            ("Authorization".to_string(), auth),
            ("x-amz-date".to_string(), ts),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ]
    }

    fn now_secs() -> i64 {
        current_time_ms() / 1000
    }

    /// Upload a part for a multipart upload. Returns the ETag.
    async fn upload_part(
        http: &Arc<H>,
        cfg: &S3Config,
        key: &str,
        upload_id: &str,
        part_number: u32,
        data: Vec<u8>,
    ) -> Result<String, ProviderError> {
        let query = format!(
            "partNumber={}&uploadId={}",
            part_number,
            sigv4::percent_encode(upload_id, true)
        );
        let path = Self::object_path(cfg, key);
        let url = format!("{}?{}", Self::object_url(cfg, key), query);
        let ts = Self::now_secs();
        let size = data.len();
        let mut hdrs = Self::auth_headers(cfg, "PUT", &path, &query, &[], ts);
        hdrs.push(("content-length".to_string(), size.to_string()));

        let req = ProviderHttpRequest {
            method: "PUT".to_string(),
            url,
            headers: hdrs,
            body: Some(data),
        };
        let resp = http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let etag = resp.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| v.trim_matches('"').to_string())
            .ok_or_else(|| ProviderError::Provider("no ETag in UploadPart response".into()))?;
        Ok(etag)
    }
}

trait S3PathStyleCheck {
    fn s3_path_style_from_ep(&self, ep: &str) -> bool;
}
impl S3PathStyleCheck for S3Config {
    fn s3_path_style_from_ep(&self, _ep: &str) -> bool {
        self.path_style
    }
}

// ─── StorageProvider impl ─────────────────────────────────────────────────────

impl<H: ProviderHttpClient + Send + Sync + 'static> StorageProvider for S3Provider<H> {
    fn provider_type(&self) -> ProviderType {
        ProviderType::S3
    }

    fn display_name(&self) -> String {
        let kind = self.state.lock()
            .ok()
            .and_then(|s| s.config.as_ref().map(|c| {
                if c.host.contains("r2.cloudflarestorage.com") { "Cloudflare R2" }
                else if c.host.contains("backblazeb2.com") { "Backblaze B2" }
                else if c.host.contains("wasabisys.com") { "Wasabi" }
                else { "S3" }
            }))
            .unwrap_or("S3");
        kind.to_string()
    }

    fn is_ready(&self) -> bool {
        self.state.lock().map(|s| s.config.is_some()).unwrap_or(false)
    }

    fn get_config(&self) -> ProviderConfig {
        ProviderConfig { type_: ProviderType::S3, ..Default::default() }
    }

    async fn init(&self, cfg: ProviderConfig) -> Result<(), ProviderError> {
        let s3cfg = Self::build_config(&cfg)?;

        // HEAD bucket — verifies credentials and bucket access.
        let bucket_path = Self::bucket_path(&s3cfg);
        let bucket_url = Self::bucket_url(&s3cfg);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&s3cfg, "HEAD", &bucket_path, "", &[], ts);
        let req = ProviderHttpRequest {
            method: "HEAD".to_string(),
            url: bucket_url,
            headers: hdrs,
            body: None,
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        self.state.lock().map_err(|_| lock_err())?.config = Some(s3cfg);
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), ProviderError> {
        self.state.lock().map_err(|_| lock_err())?.config = None;
        Ok(())
    }

    async fn refresh_auth(&self) -> Result<(), ProviderError> {
        // S3 uses static credentials; no refresh needed.
        Ok(())
    }

    async fn upload(
        &self,
        _ref_: Option<String>,
        name: String,
        data: Vec<u8>,
        options: UploadOptions,
    ) -> Result<UploadResult, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let key = format!("{SECURECLOUD_PREFIX}{name}");
        let path = Self::object_path(&cfg, &key);
        let url = Self::object_url(&cfg, &key);
        let ts = Self::now_secs();
        let size = data.len();

        let mut extra: Vec<(String, String)> = vec![
            ("content-type".to_string(), options.mime_type.unwrap_or_else(|| "application/octet-stream".to_string())),
            ("content-length".to_string(), size.to_string()),
        ];
        if let Some(ev) = &options.expected_version {
            extra.push(("if-match".to_string(), format!("\"{}\"", ev.trim_matches('"'))));
        }

        let mut hdrs = Self::auth_headers(&cfg, "PUT", &path, "", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest { method: "PUT".to_string(), url, headers: hdrs, body: Some(data) };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        let etag = resp.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| v.trim_matches('"').to_string())
            .unwrap_or_default();
        Ok(UploadResult { ref_: key, version: etag })
    }

    async fn download(&self, ref_: String) -> Result<Vec<u8>, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "GET", &path, "", &[], ts);

        let req = ProviderHttpRequest { method: "GET".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        Ok(resp.body)
    }

    async fn delete(&self, ref_: String) -> Result<(), ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "DELETE", &path, "", &[], ts);

        let req = ProviderHttpRequest { method: "DELETE".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if resp.status == 204 || resp.status == 200 || resp.status == 404 {
            return Ok(());
        }
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        Ok(())
    }

    async fn get_version(&self, ref_: String) -> Result<String, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "HEAD", &path, "", &[], ts);

        let req = ProviderHttpRequest { method: "HEAD".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let etag = resp.headers.iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| v.trim_matches('"').to_string())
            .ok_or_else(|| ProviderError::Provider("no ETag in HEAD response".into()))?;
        Ok(etag)
    }

    async fn upload_stream_open(
        &self,
        _ref_: Option<String>,
        name: String,
        _total_size: u64,
        options: UploadOptions,
    ) -> Result<String, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let key = format!("{SECURECLOUD_PREFIX}{name}");
        let path = Self::object_path(&cfg, &key);
        let url = format!("{}?uploads", Self::object_url(&cfg, &key));
        let ts = Self::now_secs();
        let content_type = options.mime_type.unwrap_or_else(|| "application/octet-stream".to_string());
        let extra = vec![("content-type".to_string(), content_type)];
        let mut hdrs = Self::auth_headers(&cfg, "POST", &path, "uploads", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest { method: "POST".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        // Parse UploadId from XML response.
        let upload_id = parse_upload_id(&resp.body)?;
        let stream_id = new_stream_id();

        self.state.lock().map_err(|_| lock_err())?.upload_sessions.insert(
            stream_id.clone(),
            MultipartSession { upload_id, key, parts: vec![], next_part: 1, buffer: vec![] },
        );
        Ok(stream_id)
    }

    async fn upload_stream_write(
        &self,
        stream_id: String,
        chunk: Vec<u8>,
    ) -> Result<(), ProviderError> {
        // Buffer the chunk; flush complete parts immediately when buffer ≥ PART_SIZE.
        let (http_clone, cfg, upload_id, key, part_number, to_upload) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let cfg = state.config.clone().ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state.upload_sessions.get_mut(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            session.buffer.extend_from_slice(&chunk);

            if session.buffer.len() < PART_SIZE {
                return Ok(());
            }
            let data: Vec<u8> = session.buffer.drain(..PART_SIZE).collect();
            let part_number = session.next_part;
            session.next_part += 1;
            (Arc::clone(&self.http), cfg, session.upload_id.clone(), session.key.clone(), part_number, data)
        };

        let etag = Self::upload_part(&http_clone, &cfg, &key, &upload_id, part_number, to_upload).await?;

        let mut state = self.state.lock().map_err(|_| lock_err())?;
        let session = state.upload_sessions.get_mut(&stream_id)
            .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
        session.parts.push((part_number, etag));
        Ok(())
    }

    async fn upload_stream_close(
        &self,
        stream_id: String,
    ) -> Result<UploadResult, ProviderError> {
        // Flush any remaining buffer as the final part, then complete.
        let (cfg, upload_id, key, parts, final_buf, part_number) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let cfg = state.config.clone().ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state.upload_sessions.remove(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            let part_number = session.next_part;
            (cfg, session.upload_id, session.key, session.parts, session.buffer, part_number)
        };

        // Upload the final (possibly partial) part if it has data.
        let mut parts_final = parts;
        if !final_buf.is_empty() {
            let etag = Self::upload_part(&self.http, &cfg, &key, &upload_id, part_number, final_buf).await?;
            parts_final.push((part_number, etag));
        }

        if parts_final.is_empty() {
            return Err(ProviderError::Provider("cannot complete multipart upload with zero parts".into()));
        }

        // Build CompleteMultipartUpload XML.
        // P4: XML-escape ETags before interpolation. Strictly, AWS S3 returns
        // MD5-hex ETags — but S3-compatible endpoints (Wasabi, R2, MinIO,
        // Ceph) have weaker guarantees and a hostile-compatible server could
        // return an ETag containing `"</ETag></Part>…` to inject additional
        // parts into the CompleteMultipartUpload body. Escaping neutralises
        // this; we do not reject since we don't know the endpoint's format.
        let xml_parts: String = parts_final.iter()
            .map(|(n, etag)| format!(
                "<Part><PartNumber>{n}</PartNumber><ETag>\"{}\"</ETag></Part>",
                xml_escape(etag)
            ))
            .collect::<Vec<_>>()
            .join("");
        let xml_body = format!("<CompleteMultipartUpload>{xml_parts}</CompleteMultipartUpload>");

        let query = format!("uploadId={}", sigv4::percent_encode(&upload_id, true));
        let path = Self::object_path(&cfg, &key);
        let url = format!("{}?{}", Self::object_url(&cfg, &key), query);
        let ts = Self::now_secs();
        let body_bytes = xml_body.into_bytes();
        let extra = vec![
            ("content-type".to_string(), "application/xml".to_string()),
            ("content-length".to_string(), body_bytes.len().to_string()),
        ];
        let mut hdrs = Self::auth_headers(&cfg, "POST", &path, &query, &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest { method: "POST".to_string(), url, headers: hdrs, body: Some(body_bytes) };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        let etag = parse_xml_text(&resp.body, "ETag")
            .map(|e| e.trim_matches('"').to_string())
            .unwrap_or_default();
        Ok(UploadResult { ref_: key, version: etag })
    }

    async fn upload_stream_abort(&self, stream_id: String) -> Result<(), ProviderError> {
        let (cfg, upload_id, key) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let cfg = state.config.clone().ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state.upload_sessions.remove(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            (cfg, session.upload_id, session.key)
        };

        let query = format!("uploadId={}", sigv4::percent_encode(&upload_id, true));
        let path = Self::object_path(&cfg, &key);
        let url = format!("{}?{}", Self::object_url(&cfg, &key), query);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "DELETE", &path, &query, &[], ts);

        let req = ProviderHttpRequest { method: "DELETE".to_string(), url, headers: hdrs, body: None };
        let _ = self.http.request(req).await; // best-effort
        Ok(())
    }

    async fn download_stream_open(&self, ref_: String) -> Result<String, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
        // `ref_` is the key returned by upload/upload_stream_close, which already
        // includes SECURECLOUD_PREFIX. Do NOT re-prefix — matches `download()`.
        let url = Self::object_url(&cfg, &ref_);
        let path = Self::object_path(&cfg, &ref_);

        // S3 SigV4 must sign the Range header on each chunk. Capture config + path;
        // re-sign on every make_headers call with a fresh timestamp.
        let make_headers: MakeHeaders = {
            let cfg = cfg.clone();
            let path = path.clone();
            Arc::new(move |offset: u64, end: u64| {
                // B11: title-case per RFC 7233; SigV4 canonical headers lowercase
                // everything anyway but we send exactly what we sign.
                let range_header = ("Range".to_string(), format!("bytes={offset}-{end}"));
                let ts = Self::now_secs();
                let mut hdrs = Self::auth_headers(&cfg, "GET", &path, "", std::slice::from_ref(&range_header), ts);
                hdrs.push(range_header);
                hdrs
            })
        };
        let http_call = make_http_call_fn(Arc::clone(&self.http));
        let buf = RangedDownloadBuffer::new(url, "GET", None, make_headers, http_call);
        let stream_id = new_stream_id();
        self.state.lock().map_err(|_| lock_err())?
            .download_buffers.insert(stream_id.clone(), buf);
        Ok(stream_id)
    }

    async fn download_stream_read(&self, stream_id: String) -> Result<Option<Vec<u8>>, ProviderError> {
        let (req, requested, http_call) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let buf = state.download_buffers.get_mut(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            match buf.next_request() {
                None => return Ok(None),
                Some((req, size)) => (req, size, Arc::clone(&buf.http_call)),
            }
        };
        let resp = http_call(req).await?;
        let content_range = resp.header("content-range").map(str::to_owned);
        let mut state = self.state.lock().map_err(|_| lock_err())?;
        match state.download_buffers.get_mut(&stream_id) {
            None => Ok(None),
            Some(buf) => buf.apply_response(resp.status, resp.body, content_range.as_deref(), requested),
        }
    }

    async fn download_stream_close(&self, stream_id: String) -> Result<(), ProviderError> {
        self.state.lock().map_err(|_| lock_err())?.download_buffers.remove(&stream_id);
        Ok(())
    }

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider("S3 does not support provider-native public links; use presigned URLs (B1) instead".into()))
    }

    async fn revoke_public_link(&self, _ref_: String) -> Result<(), ProviderError> {
        Ok(()) // no-op
    }

    async fn create_presigned_url(&self, ref_: String, ttl_seconds: u32) -> Result<String, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let ttl = ttl_seconds.min(MAX_PRESIGN_TTL);
        let path = Self::object_path(&cfg, &ref_);
        let obj_url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();

        let url = sigv4::presign_url(
            &obj_url, &cfg.host, &path,
            &cfg.region, &cfg.access_key_id, &cfg.secret_access_key,
            ts, ttl,
        );
        Ok(url)
    }

    async fn list(&self, parent_ref: Option<String>) -> Result<Vec<StorageEntry>, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let prefix = match &parent_ref {
            Some(p) if !p.is_empty() => {
                if p.ends_with('/') { p.clone() } else { format!("{p}/") }
            }
            _ => SECURECLOUD_PREFIX.to_string(),
        };

        // B14: SigV4 requires the canonical query string to be sorted
        // lexicographically by parameter name. Assemble as pairs, sort, then
        // join so adding a future parameter out of order can't silently break
        // the signature.
        let mut params: Vec<(&str, String)> = vec![
            ("delimiter", sigv4::percent_encode("/", true)),
            ("list-type", "2".to_string()),
            ("prefix", sigv4::percent_encode(&prefix, true)),
        ];
        params.sort_by(|a, b| a.0.cmp(b.0));
        let query = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let bucket_path = Self::bucket_path(&cfg);
        let url = format!("{}?{}", Self::bucket_url(&cfg), query);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "GET", &bucket_path, &query, &[], ts);

        let req = ProviderHttpRequest { method: "GET".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        parse_list_response(&resp.body, &prefix)
    }

    async fn create_folder(
        &self,
        name: String,
        parent_ref: Option<String>,
    ) -> Result<String, ProviderError> {
        let cfg = self.state.lock().map_err(|_| lock_err())?.config.clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let key = match parent_ref {
            Some(p) if !p.is_empty() => {
                let p = if p.ends_with('/') { p } else { format!("{p}/") };
                format!("{p}{name}/")
            }
            _ => format!("{SECURECLOUD_PREFIX}{name}/"),
        };
        let path = Self::object_path(&cfg, &key);
        let url = Self::object_url(&cfg, &key);
        let ts = Self::now_secs();
        let extra = vec![("content-length".to_string(), "0".to_string())];
        let mut hdrs = Self::auth_headers(&cfg, "PUT", &path, "", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest { method: "PUT".to_string(), url, headers: hdrs, body: None };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        Ok(key)
    }

    async fn delete_folder(&self, ref_: String) -> Result<(), ProviderError> {
        // Delete only the "/" marker object. Contents are managed by the caller.
        self.delete(ref_).await
    }
}

// ─── XML helpers ─────────────────────────────────────────────────────────────

/// Extract the first text content of a named XML element.
/// Minimal XML entity escape for attribute / text values. Used to neutralise
/// server-supplied ETags in CompleteMultipartUpload bodies (P4).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn parse_xml_text(xml: &[u8], tag: &str) -> Option<String> {
    let text = std::str::from_utf8(xml).ok()?;
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)?;
    Some(text[start..start + end].to_string())
}

/// Extract the UploadId from a CreateMultipartUpload XML response.
fn parse_upload_id(xml: &[u8]) -> Result<String, ProviderError> {
    parse_xml_text(xml, "UploadId")
        .ok_or_else(|| ProviderError::Provider("missing UploadId in CreateMultipartUpload response".into()))
}

/// Parse a ListObjectsV2 XML response into StorageEntry items.
fn parse_list_response(xml: &[u8], prefix: &str) -> Result<Vec<StorageEntry>, ProviderError> {
    let text = std::str::from_utf8(xml)
        .map_err(|_| ProviderError::Provider("ListObjectsV2 response is not valid UTF-8".into()))?;

    let mut entries = Vec::new();

    // Parse <CommonPrefixes> → folders
    let mut pos = 0;
    while let Some(cp_start) = text[pos..].find("<CommonPrefixes>") {
        let abs_start = pos + cp_start + "<CommonPrefixes>".len();
        let cp_end = text[abs_start..].find("</CommonPrefixes>")
            .ok_or(ProviderError::InvalidResponse)?;
        let cp_block = &text[abs_start..abs_start + cp_end];

        if let Some(prefix_val) = xml_text(cp_block, "Prefix") {
            let folder_name = prefix_val.trim_end_matches('/')
                .split('/').next_back().unwrap_or(&prefix_val).to_string();
            if !folder_name.is_empty() {
                entries.push(StorageEntry {
                    ref_: prefix_val.clone(),
                    name: folder_name,
                    size: 0,
                    is_folder: true,
                    mime_type: None,
                    modified_at: None,
                });
            }
        }
        pos = abs_start + cp_end + "</CommonPrefixes>".len();
    }

    // Parse <Contents> → files
    pos = 0;
    while let Some(c_start) = text[pos..].find("<Contents>") {
        let abs_start = pos + c_start + "<Contents>".len();
        let c_end = text[abs_start..].find("</Contents>")
            .ok_or(ProviderError::InvalidResponse)?;
        let c_block = &text[abs_start..abs_start + c_end];

        if let (Some(key), Some(size_str)) = (xml_text(c_block, "Key"), xml_text(c_block, "Size")) {
            // Skip the prefix directory marker itself (zero-byte key ending in "/")
            if key == prefix || key.ends_with('/') && size_str == "0" {
                pos = abs_start + c_end + "</Contents>".len();
                continue;
            }
            let file_name = key.split('/').next_back().unwrap_or(&key).to_string();
            let size = size_str.parse::<u64>().unwrap_or(0);
            let modified_at = xml_text(c_block, "LastModified").and_then(|s| parse_iso8601_ms(&s));

            entries.push(StorageEntry {
                ref_: key,
                name: file_name,
                size,
                is_folder: false,
                mime_type: None,
                modified_at,
            });
        }
        pos = abs_start + c_end + "</Contents>".len();
    }

    Ok(entries)
}

/// Extract the text content of a named XML element within a block.
fn xml_text(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)?;
    Some(block[start..start + end].to_string())
}

/// Parse an S3 ISO8601 timestamp ("2024-01-15T12:00:00.000Z") to Unix milliseconds.
fn parse_iso8601_ms(s: &str) -> Option<i64> {
    // Very simple parsing: extract fields from fixed-position string.
    // Accepts: YYYY-MM-DDTHH:MM:SS[.sss]Z
    let s = s.trim_end_matches('Z').trim_end_matches(|c: char| c == '.' || c.is_ascii_digit());
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 { return None; }
    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() < 3 || time_parts.len() < 3 { return None; }
    // Rough conversion: not accounting for leap years in this simple helper.
    let days = gregorian_to_unix_days(date_parts[0], date_parts[1], date_parts[2])?;
    let secs = days * 86400 + time_parts[0] * 3600 + time_parts[1] * 60 + time_parts[2];
    Some((secs * 1000) as i64)
}

fn gregorian_to_unix_days(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 { return None; }
    // Zeller's congruence-derived days since epoch
    let m = if month <= 2 { month + 12 } else { month };
    let y = if month <= 2 { year - 1 } else { year };
    let jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 + 1720994;
    jdn.checked_sub(2440588)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::api::ProviderHttpResponse;
    use std::sync::Mutex;

    // ── MockHttp ──────────────────────────────────────────────────────────────

    struct MockHttp {
        responses: Mutex<Vec<(u16, Vec<u8>, Vec<(String, String)>)>>,
        requests: Mutex<Vec<(String, String, Vec<u8>)>>, // (method, url, body)
    }

    impl MockHttp {
        fn new(responses: Vec<(u16, &str)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses.into_iter()
                        .map(|(s, b)| (s, b.as_bytes().to_vec(), vec![]))
                        .collect(),
                ),
                requests: Mutex::new(vec![]),
            }
        }

        fn with_headers(responses: Vec<(u16, &str, Vec<(&str, &str)>)>) -> Self {
            Self {
                responses: Mutex::new(
                    responses.into_iter()
                        .map(|(s, b, h)| (s, b.as_bytes().to_vec(),
                            h.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()))
                        .collect(),
                ),
                requests: Mutex::new(vec![]),
            }
        }

        fn last_request(&self) -> Option<(String, String)> {
            self.requests.lock().ok()?.last()
                .map(|(m, u, _)| (m.clone(), u.clone()))
        }

        fn request_count(&self) -> usize {
            self.requests.lock().map(|r| r.len()).unwrap_or(0)
        }
    }

    impl ProviderHttpClient for MockHttp {
        fn request(
            &self,
            req: ProviderHttpRequest,
        ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send
        {
            self.requests.lock().unwrap().push((req.method.clone(), req.url.clone(), req.body.clone().unwrap_or_default()));
            let mut responses = self.responses.lock().unwrap();
            let result = if responses.is_empty() {
                Err(ProviderError::Provider("no more mock responses".to_string()))
            } else {
                let (status, body, headers) = responses.remove(0);
                Ok(ProviderHttpResponse { status, headers, body })
            };
            std::future::ready(result)
        }
    }

    fn s3_cfg(path_style: bool) -> ProviderConfig {
        ProviderConfig {
            type_: ProviderType::S3,
            s3_endpoint: Some("https://s3.example.com".to_string()),
            s3_region: Some("us-east-1".to_string()),
            s3_bucket: Some("my-bucket".to_string()),
            s3_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
            s3_secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
            s3_path_style: Some(path_style),
            ..Default::default()
        }
    }

    // ── SigV4 unit tests ─────────────────────────────────────────────────────

    #[test]
    fn sigv4_date_formatting() {
        // Unix epoch = 1970-01-01T00:00:00Z
        assert_eq!(sigv4::iso8601(0), "19700101T000000Z");
        assert_eq!(sigv4::date(0), "19700101");
        // 1 day + 1 hour + 1 minute + 1 second later = 1970-01-02T01:01:01Z
        assert_eq!(sigv4::iso8601(86400 + 3600 + 60 + 1), "19700102T010101Z");
        // 2024-01-15 = 19737 days since epoch → 19737 * 86400 = 1705276800.
        // + 11h54m56s = 11*3600 + 54*60 + 56 = 39600 + 3240 + 56 = 42896
        // = 1705319696. The actual ISO8601 for this is 2024-01-15T11:54:56Z.
        assert_eq!(sigv4::iso8601(1705319696), "20240115T115456Z");
        assert_eq!(sigv4::date(1705319696), "20240115");
    }

    #[test]
    fn sigv4_percent_encode() {
        assert_eq!(sigv4::percent_encode("hello world", true), "hello%20world");
        assert_eq!(sigv4::percent_encode("a/b/c", false), "a/b/c");
        assert_eq!(sigv4::percent_encode("a/b/c", true), "a%2Fb%2Fc");
        assert_eq!(sigv4::percent_encode("abc-_.", true), "abc-_.");
    }

    #[test]
    fn sigv4_authorization_header_is_deterministic() {
        // Same inputs must always produce the same Authorization header.
        let auth1 = sigv4::authorization(
            "GET", "/my-bucket/SecureCloud/file.v7", "",
            "s3.example.com", &[],
            "UNSIGNED-PAYLOAD", "us-east-1",
            "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            1705319696,
        );
        let auth2 = sigv4::authorization(
            "GET", "/my-bucket/SecureCloud/file.v7", "",
            "s3.example.com", &[],
            "UNSIGNED-PAYLOAD", "us-east-1",
            "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            1705319696,
        );
        assert_eq!(auth1, auth2);
        assert!(auth1.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth1.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert!(auth1.contains("Signature="));
    }

    #[test]
    fn sigv4_presign_url_contains_required_params() {
        let url = sigv4::presign_url(
            "https://s3.example.com/my-bucket/SecureCloud/file.v7",
            "s3.example.com",
            "/my-bucket/SecureCloud/file.v7",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            1705319696,
            3600,
        );
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Expires=3600"));
        assert!(url.contains("X-Amz-Signature="));
        assert!(url.contains("X-Amz-Credential="));
    }

    // ── SigV4 official test vectors ──────────────────────────────────────────
    //
    // Computed against the AWS SigV4 test suite credentials:
    //   Access Key:  AKIDEXAMPLE
    //   Secret Key:  wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
    //   Region:      us-east-1
    //   DateTime:    20150830T123600Z (= 1440938160 unix secs)
    //
    // Our implementation always adds x-amz-content-sha256 to signed headers
    // (required for S3 specifically). Expected signatures were verified
    // independently with a Python reference implementation.

    const VEC_ACCESS: &str = "AKIDEXAMPLE";
    const VEC_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const VEC_TS: i64 = 1440938160; // 20150830T123600Z
    const VEC_HOST: &str = "example.amazonaws.com";
    const VEC_REGION: &str = "us-east-1";

    fn vec_sig(auth: &str) -> &str {
        // Extract Signature=... from Authorization header
        auth.split("Signature=").nth(1).unwrap_or("")
    }

    #[test]
    fn sigv4_vector_get_vanilla() {
        let auth = sigv4::authorization(
            "GET", "/", "",
            VEC_HOST, &[],
            "UNSIGNED-PAYLOAD", VEC_REGION,
            VEC_ACCESS, VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(vec_sig(&auth), "f8815cdb11f23ac0476d526ba474c2f76561dcc4405465cd093a230e86a592d6");
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn sigv4_vector_get_vanilla_query() {
        let auth = sigv4::authorization(
            "GET", "/", "Param1=value1&Param2=value2",
            VEC_HOST, &[],
            "UNSIGNED-PAYLOAD", VEC_REGION,
            VEC_ACCESS, VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(vec_sig(&auth), "599617b2e955f7f516469582df558e5752fd5e59153cc8a0a53bbbe08b345659");
    }

    #[test]
    fn sigv4_vector_post_vanilla_query() {
        let auth = sigv4::authorization(
            "POST", "/", "Param1=value1&Param2=value2",
            VEC_HOST, &[],
            "UNSIGNED-PAYLOAD", VEC_REGION,
            VEC_ACCESS, VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(vec_sig(&auth), "4ec8141c5a9b7ec9287ac6c560764f09b5cfcf3141b6c775dc5718ca1a088709");
    }

    #[test]
    fn sigv4_vector_get_utf8() {
        // Already percent-encoded path — implementation must not double-encode
        let auth = sigv4::authorization(
            "GET", "/%E1%88%B4", "",
            VEC_HOST, &[],
            "UNSIGNED-PAYLOAD", VEC_REGION,
            VEC_ACCESS, VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(vec_sig(&auth), "bec65300a6ac49a96bd3ede872abd38da64a4a3f7614af90c3b40d8e172ec4b3");
    }

    #[test]
    fn sigv4_vector_header_duplicate_merge_order() {
        // Duplicate headers must be merged in original-request order (value2 first, then value1).
        // The canonical form must be "my-header1:value2,value1", not reversed.
        let auth = sigv4::authorization(
            "GET", "/", "",
            VEC_HOST,
            &[
                ("My-Header1".to_string(), "value2".to_string()),
                ("My-Header1".to_string(), "value1".to_string()),
            ],
            "UNSIGNED-PAYLOAD", VEC_REGION,
            VEC_ACCESS, VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(vec_sig(&auth), "13edcc510734a17cdf8354e9d67d4f839adec8efb1474a3f58103d2fc8e8930c");
        assert!(auth.contains("my-header1") || auth.contains("SignedHeaders=host;my-header1"));
    }

    // ── Provider integration tests ────────────────────────────────────────────

    #[tokio::test]
    async fn init_head_bucket_success() {
        let http = MockHttp::with_headers(vec![(200, "", vec![])]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        assert!(p.is_ready());
    }

    #[tokio::test]
    async fn init_missing_bucket_returns_forbidden() {
        let http = MockHttp::new(vec![(403, "")]);
        let p = S3Provider::new(http);
        let result = p.init(s3_cfg(true)).await;
        assert!(matches!(result, Err(ProviderError::Forbidden)));
    }

    #[tokio::test]
    async fn upload_single_put_no_mkcol() {
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),                                    // HEAD bucket (init)
            (200, "", vec![("ETag", "\"abc123\"")]),              // PUT object
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let result = p.upload(None, "vault.db".to_string(), b"hello".to_vec(), UploadOptions::default()).await.unwrap();
        assert_eq!(result.version, "abc123");
        assert_eq!(result.ref_, "SecureCloud/vault.db");
        // Exactly 2 HTTP calls (init + PUT)
        assert_eq!(p.http.request_count(), 2);
    }

    #[tokio::test]
    async fn get_version_returns_etag() {
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),                              // init
            (200, "", vec![("ETag", "\"deadbeef\"")]),      // HEAD object
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let version = p.get_version("SecureCloud/file.v7".to_string()).await.unwrap();
        assert_eq!(version, "deadbeef");
    }

    #[tokio::test]
    async fn multipart_upload_flow() {
        // Responses: init(HEAD), CreateMultipart(POST), UploadPart×2(PUT,PUT), Complete(POST)
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),
            (200, "<InitiateMultipartUploadResult><UploadId>up123</UploadId></InitiateMultipartUploadResult>", vec![]),
            (200, "", vec![("ETag", "\"part1etag\"")]),
            (200, "", vec![("ETag", "\"part2etag\"")]),
            (200, "<CompleteMultipartUploadResult><ETag>\"final\"</ETag></CompleteMultipartUploadResult>", vec![]),
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();

        let sid = p.upload_stream_open(None, "big.v7".to_string(), 20_000_000, UploadOptions::default()).await.unwrap();
        // Two parts: each PART_SIZE (8 MiB)
        p.upload_stream_write(sid.clone(), vec![0u8; PART_SIZE]).await.unwrap();
        p.upload_stream_write(sid.clone(), vec![1u8; PART_SIZE]).await.unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();

        assert_eq!(result.ref_, "SecureCloud/big.v7");
        assert_eq!(p.http.request_count(), 5);
    }

    #[tokio::test]
    async fn list_objects_v2_parsed_correctly() {
        let xml = r#"<ListBucketResult>
  <CommonPrefixes><Prefix>SecureCloud/docs/</Prefix></CommonPrefixes>
  <Contents><Key>SecureCloud/vault.db</Key><Size>4096</Size><LastModified>2024-01-15T12:34:56.000Z</LastModified></Contents>
  <Contents><Key>SecureCloud/</Key><Size>0</Size><LastModified>2024-01-10T00:00:00.000Z</LastModified></Contents>
</ListBucketResult>"#;
        let http = MockHttp::new(vec![
            (200, ""),   // init
            (200, xml),  // list
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let entries = p.list(None).await.unwrap();

        assert_eq!(entries.len(), 2);
        let folder = entries.iter().find(|e| e.is_folder).unwrap();
        assert_eq!(folder.name, "docs");
        let file = entries.iter().find(|e| !e.is_folder).unwrap();
        assert_eq!(file.name, "vault.db");
        assert_eq!(file.size, 4096);
    }

    #[tokio::test]
    async fn presigned_url_ttl_capped_at_max() {
        let http = MockHttp::with_headers(vec![(200, "", vec![])]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();

        // Request 7 days (604800s) — must be capped at 86400s (24 hours).
        let url = p.create_presigned_url("SecureCloud/file.v7".to_string(), 604_800).await.unwrap();
        assert!(url.contains("X-Amz-Expires=86400"));
    }

    #[tokio::test]
    async fn create_folder_puts_slash_object() {
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),
            (200, "", vec![("ETag", "\"ef\"")]),
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let ref_ = p.create_folder("docs".to_string(), None).await.unwrap();
        assert_eq!(ref_, "SecureCloud/docs/");
        let (method, url) = p.http.last_request().unwrap();
        assert_eq!(method, "PUT");
        assert!(url.contains("SecureCloud/docs/"));
    }

    #[tokio::test]
    async fn delete_returns_ok_on_404() {
        let http = MockHttp::new(vec![
            (200, ""),  // init
            (404, ""),  // DELETE (already deleted)
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        // 404 on DELETE = already deleted = OK
        p.delete("SecureCloud/gone.v7".to_string()).await.unwrap();
    }

    #[test]
    fn parse_xml_text_helper() {
        let xml = b"<UploadId>my-upload-id-123</UploadId>";
        assert_eq!(parse_xml_text(xml, "UploadId"), Some("my-upload-id-123".to_string()));
        assert_eq!(parse_xml_text(xml, "MissingTag"), None);
    }
}
