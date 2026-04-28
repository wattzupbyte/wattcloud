// S3-family storage provider implementation.
//
// Covers: AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO, and any
// S3-compatible endpoint.
//
// API: S3 REST API (CreateMultipartUpload / UploadPart / CompleteMultipartUpload)
// Auth: AWS Signature Version 4, UNSIGNED-PAYLOAD (acceptable over TLS)
// Ref: object key (e.g. "WattcloudVault/abc123.v7")
// Version: ETag from object HEAD/GET response headers
// Conflict: ETag-based optimistic concurrency via If-Match (PUT)
// Upload: single PUT for blobs; multipart (8 MiB parts) for streams
// Listing: ListObjectsV2 with prefix + "/" delimiter
//
// All object keys are prefixed with "WattcloudVault/" to avoid namespace
// collisions with user-managed objects in the same bucket.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::{ProviderHttpClient, ProviderHttpRequest};
use crate::byo::provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
use crate::byo::providers::{
    current_time_ms, make_http_call_fn, map_http_status, new_stream_id, normalize_etag,
    MakeHeaders, RangedDownloadBuffer,
};

const VAULT_ROOT_PREFIX: &str = "WattcloudVault/";
/// Minimum S3 part size (all parts except the last must be ≥ 5 MiB).
#[allow(dead_code)]
const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
/// Preferred part size (8 MiB — matches SFTP relay chunks, comfortably above minimum).
const PART_SIZE: usize = 8 * 1024 * 1024;
/// S3 multipart upload hard limit: 10 000 parts per object.
const MAX_PARTS: u32 = 10_000;
/// Derived maximum object size for our chunking strategy: `MAX_PARTS × PART_SIZE`
/// (≈ 78.1 GiB). Objects larger than this cannot fit in the multipart part
/// window and are rejected at `upload_stream_open` with a clear error.
const MAX_MULTIPART_OBJECT_BYTES: u64 = MAX_PARTS as u64 * PART_SIZE as u64;
/// S3 single-PUT hard limit (protocol ceiling — AWS rejects PUTs > 5 GiB).
/// Typed as `u64` because `usize` is 32-bit on `wasm32-unknown-unknown`,
/// where the literal `5 * 1024 * 1024 * 1024` overflows.
const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
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
            if a.0 == b.0 {
                b.1.push(',');
                b.1.push_str(&a.1);
                true
            } else {
                false
            }
        });

        let signed_headers: String = canon_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = canon_headers
            .iter()
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
        let query: String = query_params
            .iter()
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
    /// ETag the caller believes the object currently has. Checked via HEAD
    /// at `upload_stream_close` time — If-Match can't be used on
    /// `CompleteMultipartUpload`, and the stored ETag format
    /// (`<hex>-<N>`) wouldn't match a fresh single-PUT content-MD5 anyway.
    expected_version: Option<String>,
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
    /// In-bucket prefix. Empty → vault at `{bucket}/WattcloudVault/` (historical).
    /// Non-empty → always has a trailing `/` (normalised) and leading slash stripped,
    /// so the vault lands at `{bucket}/{base_path}WattcloudVault/`.
    base_path: String,
}

/// Normalise a user-supplied S3 prefix:
/// trims whitespace, strips leading/trailing slashes, appends a trailing `/`
/// when non-empty. Empty in → empty out (no prefixing applied). Mirrors
/// `normalizeBasePath` in the TypeScript SFTP path so the two layers agree on
/// the canonical form.
fn normalize_s3_base_path(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
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
        if s.len() < 3 || s.len() > 63 {
            return false;
        }
        if !s
            .chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-' | '.'))
        {
            return false;
        }
        let first = match s.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let last = match s.chars().last() {
            Some(c) => c,
            None => return false,
        };
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return false;
        }
        if s.contains("..") {
            return false;
        }
        if s.starts_with("xn--") || s.starts_with("sthree-") {
            return false;
        }
        // Reject all-numeric-with-dots (would match an IPv4 literal).
        if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return false;
        }
        true
    }

    /// Resolve config fields into an `S3Config` (normalises endpoint, detects path-style).
    fn build_config(cfg: &ProviderConfig) -> Result<S3Config, ProviderError> {
        let region = cfg
            .s3_region
            .clone()
            .unwrap_or_else(|| "us-east-1".to_string());
        let bucket = cfg
            .s3_bucket
            .clone()
            .ok_or_else(|| ProviderError::Provider("s3_bucket required".into()))?;
        let access_key_id = cfg
            .s3_access_key_id
            .clone()
            .ok_or_else(|| ProviderError::Provider("s3_access_key_id required".into()))?;
        let secret_access_key = cfg
            .s3_secret_access_key
            .clone()
            .ok_or_else(|| ProviderError::Provider("s3_secret_access_key required".into()))?;
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

        let base_path = normalize_s3_base_path(cfg.s3_base_path.as_deref().unwrap_or(""));

        Ok(S3Config {
            endpoint,
            host,
            region,
            bucket,
            access_key_id,
            secret_access_key,
            path_style,
            base_path,
        })
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
            method,
            path,
            query,
            &cfg.host,
            additional_headers,
            payload_hash,
            &cfg.region,
            &cfg.access_key_id,
            &cfg.secret_access_key,
            ts_secs,
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

    /// HEAD-probe and compare the object's current ETag against `expected`.
    ///
    /// Why not `If-Match`? On S3, a multipart-completed object has ETag
    /// `<hex>-<N>` while a subsequent single-PUT of the same key produces a
    /// fresh content-MD5 — so `If-Match: "<hex>-<N>"` would always 412 on the
    /// second save. `CompleteMultipartUpload` also doesn't accept `If-Match`.
    /// HEAD-compare + normalise gives both paths identical semantics. There
    /// is a small TOCTOU window; acceptable for BYO where vault writes from
    /// a single user rarely race.
    async fn check_expected_version(
        http: &Arc<H>,
        cfg: &S3Config,
        key: &str,
        expected: &str,
    ) -> Result<(), ProviderError> {
        let path = Self::object_path(cfg, key);
        let url = Self::object_url(cfg, key);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(cfg, "HEAD", &path, "", &[], ts);
        let req = ProviderHttpRequest {
            method: "HEAD".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
        let resp = http.request(req).await?;
        if resp.status == 404 {
            // Caller expected a specific version; the object no longer exists.
            return Err(ProviderError::Conflict {
                current_version: String::new(),
            });
        }
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let current = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| normalize_etag(v))
            .unwrap_or_default();
        if normalize_etag(expected) != current {
            return Err(ProviderError::Conflict {
                current_version: current,
            });
        }
        Ok(())
    }

    /// AbortMultipartUpload against (key, upload_id). 204 is success, 404 is
    /// idempotent (upload already gone); any other status means parts may
    /// still be accruing storage charges.
    async fn abort_multipart(
        http: &Arc<H>,
        cfg: &S3Config,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProviderError> {
        let query = format!("uploadId={}", sigv4::percent_encode(upload_id, true));
        let path = Self::object_path(cfg, key);
        let url = format!("{}?{}", Self::object_url(cfg, key), query);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(cfg, "DELETE", &path, &query, &[], ts);
        let req = ProviderHttpRequest {
            method: "DELETE".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
        let resp = http.request(req).await?;
        if resp.status != 204 && resp.status != 200 && resp.status != 404 {
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
        }
        Ok(())
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
        let etag = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| normalize_etag(v))
            .ok_or_else(|| ProviderError::Provider("no ETag in UploadPart response".into()))?;
        Ok(etag)
    }
}

trait S3PathStyleCheck {
    fn s3_path_style_from_ep(&self, ep: &str) -> bool;
}
impl S3Config {
    /// Full object-key prefix for the vault root: `{base_path}WattcloudVault/`.
    /// When `base_path` is empty this equals `VAULT_ROOT_PREFIX`, preserving
    /// the historical on-disk layout for vaults that predate the prefix field.
    fn vault_prefix(&self) -> String {
        format!("{}{VAULT_ROOT_PREFIX}", self.base_path)
    }
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
        let kind = self
            .state
            .lock()
            .ok()
            .and_then(|s| {
                s.config.as_ref().map(|c| {
                    if c.host.contains("r2.cloudflarestorage.com") {
                        "Cloudflare R2"
                    } else if c.host.contains("backblazeb2.com") {
                        "Backblaze B2"
                    } else if c.host.contains("wasabisys.com") {
                        "Wasabi"
                    } else {
                        "S3"
                    }
                })
            })
            .unwrap_or("S3");
        kind.to_string()
    }

    fn is_ready(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.config.is_some())
            .unwrap_or(false)
    }

    fn get_config(&self) -> ProviderConfig {
        // Return connection metadata but never credentials — matches the
        // WebDAV provider's contract: callers that need display info use this;
        // callers that need live credentials go through the provider methods,
        // which resolve them from the worker's encrypted config registry.
        let s = match self.state.lock() {
            Ok(s) => s,
            Err(_) => {
                return ProviderConfig {
                    type_: ProviderType::S3,
                    ..Default::default()
                }
            }
        };
        let cfg = match s.config.as_ref() {
            Some(c) => c,
            None => {
                return ProviderConfig {
                    type_: ProviderType::S3,
                    ..Default::default()
                }
            }
        };
        ProviderConfig {
            type_: ProviderType::S3,
            s3_endpoint: Some(cfg.endpoint.clone()),
            s3_region: Some(cfg.region.clone()),
            s3_bucket: Some(cfg.bucket.clone()),
            s3_path_style: Some(cfg.path_style),
            s3_base_path: if cfg.base_path.is_empty() {
                None
            } else {
                Some(cfg.base_path.clone())
            },
            ..Default::default()
        }
    }

    async fn init(&self, cfg: ProviderConfig) -> Result<(), ProviderError> {
        let s3cfg = Self::build_config(&cfg)?;

        // HEAD bucket — cheapest probe of auth + bucket existence. Cloudflare
        // R2 sometimes returns 405 (HEAD not supported) for a perfectly valid
        // bucket; fall back to a zero-result ListObjectsV2 in that case. Do
        // NOT fall back on 4xx statuses that mean something specific (401
        // Unauthorized, 403 Forbidden, 404 NoSuchBucket) — those are real.
        let bucket_path = Self::bucket_path(&s3cfg);
        let bucket_url = Self::bucket_url(&s3cfg);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&s3cfg, "HEAD", &bucket_path, "", &[], ts);
        let req = ProviderHttpRequest {
            method: "HEAD".to_string(),
            url: bucket_url.clone(),
            headers: hdrs,
            body: None,
        };
        let resp = self.http.request(req).await?;

        if resp.status == 405 {
            // GET with list-type=2&max-keys=0 probes the same thing via the
            // list endpoint every S3-compatible backend supports. Query params
            // already sorted (l < m) for the SigV4 canonical form.
            let list_query = "list-type=2&max-keys=0";
            let ts = Self::now_secs();
            let hdrs = Self::auth_headers(&s3cfg, "GET", &bucket_path, list_query, &[], ts);
            let url = format!("{bucket_url}?{list_query}");
            let req = ProviderHttpRequest {
                method: "GET".to_string(),
                url,
                headers: hdrs,
                body: None,
            };
            let resp = self.http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }
        } else if let Some(e) = map_http_status(resp.status, &resp.body) {
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
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        // S3 rejects single-PUT objects > 5 GiB. Fail fast with a clear
        // message before we try to hand 6 GB to reqwest. `as u64` widens
        // 32-bit WASM `usize` so the comparison compiles on both targets.
        if (data.len() as u64) > MAX_SINGLE_PUT_BYTES {
            return Err(ProviderError::Provider(format!(
                "file too large for S3 single-PUT ({} bytes > 5 GiB limit). \
                 Use streaming upload or split the file.",
                data.len()
            )));
        }

        let key = format!("{}{name}", cfg.vault_prefix());
        let path = Self::object_path(&cfg, &key);
        let url = Self::object_url(&cfg, &key);

        // If the caller supplied an expected version, compare via HEAD first
        // (see `check_expected_version` for why not `If-Match`).
        if let Some(ev) = &options.expected_version {
            Self::check_expected_version(&self.http, &cfg, &key, ev).await?;
        }

        let ts = Self::now_secs();
        let size = data.len();

        let extra: Vec<(String, String)> = vec![
            (
                "content-type".to_string(),
                options
                    .mime_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            ),
            ("content-length".to_string(), size.to_string()),
        ];

        let mut hdrs = Self::auth_headers(&cfg, "PUT", &path, "", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest {
            method: "PUT".to_string(),
            url,
            headers: hdrs,
            body: Some(data),
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        let etag = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| normalize_etag(v))
            .unwrap_or_default();
        Ok(UploadResult {
            ref_: key,
            version: etag,
        })
    }

    async fn download(&self, ref_: String) -> Result<Vec<u8>, ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "GET", &path, "", &[], ts);

        let req = ProviderHttpRequest {
            method: "GET".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        Ok(resp.body)
    }

    async fn delete(&self, ref_: String) -> Result<(), ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "DELETE", &path, "", &[], ts);

        let req = ProviderHttpRequest {
            method: "DELETE".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
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
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let path = Self::object_path(&cfg, &ref_);
        let url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();
        let hdrs = Self::auth_headers(&cfg, "HEAD", &path, "", &[], ts);

        let req = ProviderHttpRequest {
            method: "HEAD".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }
        let etag = resp
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "etag")
            .map(|(_, v)| normalize_etag(v))
            .ok_or_else(|| ProviderError::Provider("no ETag in HEAD response".into()))?;
        Ok(etag)
    }

    async fn upload_stream_open(
        &self,
        _ref_: Option<String>,
        name: String,
        total_size: u64,
        options: UploadOptions,
    ) -> Result<String, ProviderError> {
        // Fail fast when the file can't fit in the 10 000-part window. When
        // `total_size == 0` (caller doesn't know the size yet), this check
        // skips naturally — the `upload_stream_write` defensive check catches
        // runaway callers.
        if total_size > MAX_MULTIPART_OBJECT_BYTES {
            let max_gib = MAX_MULTIPART_OBJECT_BYTES / (1024 * 1024 * 1024);
            let size_gib = total_size / (1024 * 1024 * 1024);
            return Err(ProviderError::Provider(format!(
                "file too large for S3 multipart upload ({size_gib} GiB > {max_gib} GiB limit from \
                 10 000 × 8 MiB parts). Split the file or use a provider without this cap \
                 (SFTP, OneDrive)."
            )));
        }

        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let key = format!("{}{name}", cfg.vault_prefix());
        let path = Self::object_path(&cfg, &key);
        let url = format!("{}?uploads", Self::object_url(&cfg, &key));
        let ts = Self::now_secs();
        let content_type = options
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let extra = vec![("content-type".to_string(), content_type)];
        let mut hdrs = Self::auth_headers(&cfg, "POST", &path, "uploads", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest {
            method: "POST".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        // Parse UploadId from XML response.
        let upload_id = parse_upload_id(&resp.body)?;
        let stream_id = new_stream_id();

        self.state
            .lock()
            .map_err(|_| lock_err())?
            .upload_sessions
            .insert(
                stream_id.clone(),
                MultipartSession {
                    upload_id,
                    key,
                    parts: vec![],
                    next_part: 1,
                    buffer: vec![],
                    expected_version: options.expected_version,
                },
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
            let cfg = state
                .config
                .clone()
                .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state
                .upload_sessions
                .get_mut(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            session.buffer.extend_from_slice(&chunk);

            if session.buffer.len() < PART_SIZE {
                return Ok(());
            }
            // Defensive: catch callers that opened with `total_size == 0`
            // (skipping the `upload_stream_open` gate) but keep writing past
            // the 10 000-part window. Without this the 10001st UploadPart
            // would 400 from the server with no hint about the cause.
            if session.next_part > MAX_PARTS {
                return Err(ProviderError::Provider(format!(
                    "file exceeds S3 multipart cap ({MAX_PARTS} × {PART_SIZE}-byte parts). \
                     Split the file or use a provider without this cap."
                )));
            }
            let data: Vec<u8> = session.buffer.drain(..PART_SIZE).collect();
            let part_number = session.next_part;
            session.next_part += 1;
            (
                Arc::clone(&self.http),
                cfg,
                session.upload_id.clone(),
                session.key.clone(),
                part_number,
                data,
            )
        };

        let etag =
            Self::upload_part(&http_clone, &cfg, &key, &upload_id, part_number, to_upload).await?;

        let mut state = self.state.lock().map_err(|_| lock_err())?;
        let session = state
            .upload_sessions
            .get_mut(&stream_id)
            .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
        session.parts.push((part_number, etag));
        Ok(())
    }

    async fn upload_stream_close(&self, stream_id: String) -> Result<UploadResult, ProviderError> {
        // Flush any remaining buffer as the final part, then complete.
        let (cfg, upload_id, key, parts, final_buf, part_number, expected_version) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let cfg = state
                .config
                .clone()
                .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state
                .upload_sessions
                .remove(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            let part_number = session.next_part;
            (
                cfg,
                session.upload_id,
                session.key,
                session.parts,
                session.buffer,
                part_number,
                session.expected_version,
            )
        };

        // Optimistic-concurrency gate, if requested. Runs BEFORE
        // CompleteMultipartUpload so a conflict aborts the transaction
        // cheaply instead of replacing the object.
        if let Some(ev) = expected_version.as_deref() {
            match Self::check_expected_version(&self.http, &cfg, &key, ev).await {
                Ok(()) => {}
                Err(e) => {
                    // Abort the in-progress multipart so parts don't linger.
                    let _ = Self::abort_multipart(&self.http, &cfg, &key, &upload_id).await;
                    return Err(e);
                }
            }
        }

        // Upload the final (possibly partial) part if it has data.
        let mut parts_final = parts;
        if !final_buf.is_empty() {
            let etag =
                Self::upload_part(&self.http, &cfg, &key, &upload_id, part_number, final_buf)
                    .await?;
            parts_final.push((part_number, etag));
        }

        if parts_final.is_empty() {
            return Err(ProviderError::Provider(
                "cannot complete multipart upload with zero parts".into(),
            ));
        }

        // Build CompleteMultipartUpload XML.
        // P4: XML-escape ETags before interpolation. Strictly, AWS S3 returns
        // MD5-hex ETags — but S3-compatible endpoints (Wasabi, R2, MinIO,
        // Ceph) have weaker guarantees and a hostile-compatible server could
        // return an ETag containing `"</ETag></Part>…` to inject additional
        // parts into the CompleteMultipartUpload body. Escaping neutralises
        // this; we do not reject since we don't know the endpoint's format.
        let xml_parts: String = parts_final
            .iter()
            .map(|(n, etag)| {
                format!(
                    "<Part><PartNumber>{n}</PartNumber><ETag>\"{}\"</ETag></Part>",
                    xml_escape(etag)
                )
            })
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

        let req = ProviderHttpRequest {
            method: "POST".to_string(),
            url,
            headers: hdrs,
            body: Some(body_bytes),
        };
        let resp = self.http.request(req).await?;
        if let Some(e) = map_http_status(resp.status, &resp.body) {
            return Err(e);
        }

        let etag = parse_xml_text(&resp.body, "ETag")
            .map(|e| normalize_etag(&e))
            .unwrap_or_default();
        Ok(UploadResult {
            ref_: key,
            version: etag,
        })
    }

    async fn upload_stream_abort(&self, stream_id: String) -> Result<(), ProviderError> {
        let (cfg, upload_id, key) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let cfg = state
                .config
                .clone()
                .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
            let session = state
                .upload_sessions
                .remove(&stream_id)
                .ok_or_else(|| ProviderError::Provider("unknown stream_id".into()))?;
            (cfg, session.upload_id, session.key)
        };
        Self::abort_multipart(&self.http, &cfg, &key, &upload_id).await
    }

    async fn download_stream_open(&self, ref_: String) -> Result<String, ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;
        // `ref_` is the key returned by upload/upload_stream_close, which already
        // includes VAULT_ROOT_PREFIX. Do NOT re-prefix — matches `download()`.
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
                let mut hdrs = Self::auth_headers(
                    &cfg,
                    "GET",
                    &path,
                    "",
                    std::slice::from_ref(&range_header),
                    ts,
                );
                hdrs.push(range_header);
                hdrs
            })
        };
        let http_call = make_http_call_fn(Arc::clone(&self.http));
        let buf = RangedDownloadBuffer::new(url, "GET", None, make_headers, http_call);
        let stream_id = new_stream_id();
        self.state
            .lock()
            .map_err(|_| lock_err())?
            .download_buffers
            .insert(stream_id.clone(), buf);
        Ok(stream_id)
    }

    async fn download_stream_read(
        &self,
        stream_id: String,
    ) -> Result<Option<Vec<u8>>, ProviderError> {
        let (req, requested, http_call) = {
            let mut state = self.state.lock().map_err(|_| lock_err())?;
            let buf = state
                .download_buffers
                .get_mut(&stream_id)
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
            Some(buf) => {
                buf.apply_response(resp.status, resp.body, content_range.as_deref(), requested)
            }
        }
    }

    async fn download_stream_close(&self, stream_id: String) -> Result<(), ProviderError> {
        self.state
            .lock()
            .map_err(|_| lock_err())?
            .download_buffers
            .remove(&stream_id);
        Ok(())
    }

    async fn create_public_link(&self, _ref_: String) -> Result<String, ProviderError> {
        Err(ProviderError::Provider(
            "S3 does not support provider-native public links; use presigned URLs (B1) instead"
                .into(),
        ))
    }

    async fn revoke_public_link(&self, _ref_: String) -> Result<(), ProviderError> {
        Ok(()) // no-op
    }

    async fn create_presigned_url(
        &self,
        ref_: String,
        ttl_seconds: u32,
    ) -> Result<String, ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let ttl = ttl_seconds.min(MAX_PRESIGN_TTL);
        let path = Self::object_path(&cfg, &ref_);
        let obj_url = Self::object_url(&cfg, &ref_);
        let ts = Self::now_secs();

        let url = sigv4::presign_url(
            &obj_url,
            &cfg.host,
            &path,
            &cfg.region,
            &cfg.access_key_id,
            &cfg.secret_access_key,
            ts,
            ttl,
        );
        Ok(url)
    }

    async fn list(&self, parent_ref: Option<String>) -> Result<Vec<StorageEntry>, ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let prefix = match &parent_ref {
            Some(p) if !p.is_empty() => {
                if p.ends_with('/') {
                    p.clone()
                } else {
                    format!("{p}/")
                }
            }
            _ => cfg.vault_prefix(),
        };

        let bucket_path = Self::bucket_path(&cfg);
        let bucket_url = Self::bucket_url(&cfg);

        let mut entries: Vec<StorageEntry> = Vec::new();
        let mut continuation: Option<String> = None;
        // Hard cap: protects against a server stuck in a pagination loop.
        // 10_000 pages × up to 1000 objects = 10M objects, well past any
        // sensible vault size.
        let mut pages_fetched: u32 = 0;

        loop {
            // B14: SigV4 requires the canonical query string to be sorted
            // lexicographically by parameter name. Assemble as pairs, sort, then
            // join so adding a future parameter out of order can't silently break
            // the signature.
            let mut params: Vec<(&str, String)> = vec![
                ("delimiter", sigv4::percent_encode("/", true)),
                ("list-type", "2".to_string()),
                ("prefix", sigv4::percent_encode(&prefix, true)),
            ];
            if let Some(ref tok) = continuation {
                params.push(("continuation-token", sigv4::percent_encode(tok, true)));
            }
            params.sort_by(|a, b| a.0.cmp(b.0));
            let query = params
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            let url = format!("{bucket_url}?{query}");
            let ts = Self::now_secs();
            let hdrs = Self::auth_headers(&cfg, "GET", &bucket_path, &query, &[], ts);

            let req = ProviderHttpRequest {
                method: "GET".to_string(),
                url,
                headers: hdrs,
                body: None,
            };
            let resp = self.http.request(req).await?;
            if let Some(e) = map_http_status(resp.status, &resp.body) {
                return Err(e);
            }

            let page = parse_list_response(&resp.body, &prefix)?;
            entries.extend(page.entries);
            pages_fetched += 1;

            match page.next_token {
                Some(tok) if pages_fetched < 10_000 => continuation = Some(tok),
                _ => break,
            }
        }

        Ok(entries)
    }

    async fn create_folder(
        &self,
        name: String,
        parent_ref: Option<String>,
    ) -> Result<String, ProviderError> {
        let cfg = self
            .state
            .lock()
            .map_err(|_| lock_err())?
            .config
            .clone()
            .ok_or_else(|| ProviderError::Provider("S3 not initialised".into()))?;

        let key = match parent_ref {
            Some(p) if !p.is_empty() => {
                let p = if p.ends_with('/') { p } else { format!("{p}/") };
                format!("{p}{name}/")
            }
            _ => format!("{}{name}/", cfg.vault_prefix()),
        };
        let path = Self::object_path(&cfg, &key);
        let url = Self::object_url(&cfg, &key);
        let ts = Self::now_secs();
        let extra = vec![("content-length".to_string(), "0".to_string())];
        let mut hdrs = Self::auth_headers(&cfg, "PUT", &path, "", &extra, ts);
        hdrs.extend(extra);

        let req = ProviderHttpRequest {
            method: "PUT".to_string(),
            url,
            headers: hdrs,
            body: None,
        };
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
    parse_xml_text(xml, "UploadId").ok_or_else(|| {
        ProviderError::Provider("missing UploadId in CreateMultipartUpload response".into())
    })
}

/// One page of a paginated ListObjectsV2 response.
struct ListPage {
    entries: Vec<StorageEntry>,
    /// Token to pass in `continuation-token` on the next request.
    /// `Some` when the server set `<IsTruncated>true</IsTruncated>`.
    next_token: Option<String>,
}

/// Parse a ListObjectsV2 XML response into StorageEntry items + continuation
/// token.
///
/// Uses quick-xml so namespace-prefixed responses (`<s3:Contents>` on some
/// MinIO / Ceph deployments) are handled correctly. The previous substring
/// parser silently returned an empty listing on those servers.
fn parse_list_response(xml: &[u8], prefix: &str) -> Result<ListPage, ProviderError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    #[derive(Clone, Copy, PartialEq)]
    enum Context {
        None,
        Contents,
        CommonPrefixes,
    }
    enum TextTarget {
        None,
        Key,
        Size,
        LastModified,
        Prefix,
        NextContinuationToken,
    }

    let mut entries: Vec<StorageEntry> = Vec::new();
    let mut next_token: Option<String> = None;
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut ctx = Context::None;
    let mut text_target = TextTarget::None;
    let mut cur_key = String::new();
    let mut cur_size: u64 = 0;
    let mut cur_modified: Option<i64> = None;
    let mut cur_prefix = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match name {
                    "Contents" => {
                        ctx = Context::Contents;
                        cur_key.clear();
                        cur_size = 0;
                        cur_modified = None;
                    }
                    "CommonPrefixes" => {
                        ctx = Context::CommonPrefixes;
                        cur_prefix.clear();
                    }
                    "Key" if ctx == Context::Contents => text_target = TextTarget::Key,
                    "Size" if ctx == Context::Contents => text_target = TextTarget::Size,
                    "LastModified" if ctx == Context::Contents => {
                        text_target = TextTarget::LastModified
                    }
                    "Prefix" if ctx == Context::CommonPrefixes => text_target = TextTarget::Prefix,
                    // NextContinuationToken sits at the ListBucketResult root,
                    // not inside Contents/CommonPrefixes.
                    "NextContinuationToken" if ctx == Context::None => {
                        text_target = TextTarget::NextContinuationToken
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .decode()
                    .ok()
                    .and_then(|d| quick_xml::escape::unescape(&d).ok().map(|u| u.into_owned()))
                    .map(std::borrow::Cow::Owned)
                    .unwrap_or(std::borrow::Cow::Borrowed(""));
                match text_target {
                    TextTarget::Key => cur_key = s.to_string(),
                    TextTarget::Size => cur_size = s.trim().parse().unwrap_or(0),
                    TextTarget::LastModified => cur_modified = parse_iso8601_ms(s.trim()),
                    TextTarget::Prefix => cur_prefix = s.to_string(),
                    TextTarget::NextContinuationToken => {
                        let tok = s.trim().to_string();
                        if !tok.is_empty() {
                            next_token = Some(tok);
                        }
                    }
                    TextTarget::None => {}
                }
                text_target = TextTarget::None;
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = std::str::from_utf8(local.as_ref()).unwrap_or("");
                match name {
                    "Contents" => {
                        // Skip the prefix directory marker itself (zero-byte key ending in "/").
                        if !cur_key.is_empty()
                            && cur_key != prefix
                            && !(cur_key.ends_with('/') && cur_size == 0)
                        {
                            let file_name = cur_key
                                .split('/')
                                .next_back()
                                .unwrap_or(&cur_key)
                                .to_string();
                            entries.push(StorageEntry {
                                ref_: cur_key.clone(),
                                name: file_name,
                                size: cur_size,
                                is_folder: false,
                                mime_type: None,
                                modified_at: cur_modified,
                            });
                        }
                        ctx = Context::None;
                    }
                    "CommonPrefixes" => {
                        let pname = cur_prefix
                            .trim_end_matches('/')
                            .split('/')
                            .next_back()
                            .unwrap_or(&cur_prefix)
                            .to_string();
                        if !pname.is_empty() {
                            entries.push(StorageEntry {
                                ref_: cur_prefix.clone(),
                                name: pname,
                                size: 0,
                                is_folder: true,
                                mime_type: None,
                                modified_at: None,
                            });
                        }
                        ctx = Context::None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(ProviderError::InvalidResponse),
            _ => {}
        }
        buf.clear();
    }

    Ok(ListPage {
        entries,
        next_token,
    })
}

/// Parse an S3 ISO 8601 timestamp ("2024-01-15T12:00:00.000Z") to Unix milliseconds.
///
/// Accepts `YYYY-MM-DDTHH:MM:SS[.fff]Z`. Milliseconds are preserved when present;
/// the trailing `Z` is optional. Returns `None` on any malformed field.
fn parse_iso8601_ms(s: &str) -> Option<i64> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;

    // Split fractional seconds from integer seconds: "12:34:56.789" → ("12:34:56", "789")
    let (time_main, fraction) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };

    let mut date_parts = date.split('-');
    let year: u64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;

    let mut tp = time_main.split(':');
    let hour: u64 = tp.next()?.parse().ok()?;
    let min: u64 = tp.next()?.parse().ok()?;
    let sec: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    // First three fraction digits are milliseconds; zero-pad if shorter.
    let millis: u64 = if fraction.is_empty() {
        0
    } else {
        let take = fraction.chars().take(3).collect::<String>();
        let padded = format!("{:0<3}", take);
        padded.parse().unwrap_or(0)
    };

    let days = gregorian_to_unix_days(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    // i64::MAX corresponds to year ~2^31 secs from epoch; cast is fine for any
    // realistic S3 LastModified.
    Some((secs * 1000 + millis) as i64)
}

fn gregorian_to_unix_days(year: u64, month: u64, day: u64) -> Option<u64> {
    if year < 1970 || month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    // Howard Hinnant's `days_from_civil`, Unix-epoch-relative. The previous
    // Zeller-derived formula was off by ~35 days for dates after 2020, so
    // LastModified timestamps on the UI drifted by over a month.
    // Reference: http://howardhinnant.github.io/date_algorithms.html
    let y_adj = if month <= 2 { year - 1 } else { year };
    let era = y_adj / 400;
    let yoe = y_adj - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_from_year0 = era * 146097 + doe;
    // 1970-01-01 is day 719468 in Hinnant's scheme.
    days_from_year0.checked_sub(719468)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]
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
                    responses
                        .into_iter()
                        .map(|(s, b)| (s, b.as_bytes().to_vec(), vec![]))
                        .collect(),
                ),
                requests: Mutex::new(vec![]),
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
                requests: Mutex::new(vec![]),
            }
        }

        fn last_request(&self) -> Option<(String, String)> {
            self.requests
                .lock()
                .ok()?
                .last()
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
            self.requests.lock().unwrap().push((
                req.method.clone(),
                req.url.clone(),
                req.body.clone().unwrap_or_default(),
            ));
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

    // ── Base-path unit tests ─────────────────────────────────────────────────

    #[test]
    fn base_path_normalises_to_canonical_form() {
        assert_eq!(normalize_s3_base_path(""), "");
        assert_eq!(normalize_s3_base_path("   "), "");
        assert_eq!(normalize_s3_base_path("/"), "");
        assert_eq!(normalize_s3_base_path("///"), "");
        assert_eq!(normalize_s3_base_path("MyFolder"), "MyFolder/");
        assert_eq!(normalize_s3_base_path("/MyFolder"), "MyFolder/");
        assert_eq!(normalize_s3_base_path("MyFolder/"), "MyFolder/");
        assert_eq!(normalize_s3_base_path("/MyFolder/"), "MyFolder/");
        assert_eq!(normalize_s3_base_path("  /MyFolder/  "), "MyFolder/");
        assert_eq!(normalize_s3_base_path("nested/sub"), "nested/sub/");
    }

    // `S3Provider::build_config` is an associated fn (no `self`), so we
    // monomorphise it with any concrete `H` that satisfies the trait bound.
    // `MockHttp` (defined below in the integration-style tests) is the one
    // already in scope — reuse it rather than introduce another stub.
    #[test]
    fn vault_prefix_empty_base_path_matches_legacy_constant() {
        // Existing vaults (no s3_base_path set) must keep resolving to keys
        // under `WattcloudVault/` — the prefix refactor is backwards-compatible.
        let cfg = S3Provider::<MockHttp>::build_config(&s3_cfg(false)).unwrap();
        assert_eq!(cfg.vault_prefix(), "WattcloudVault/");
    }

    #[test]
    fn vault_prefix_with_base_path_is_nested() {
        let mut raw = s3_cfg(false);
        raw.s3_base_path = Some("MyFolder".to_string());
        let cfg = S3Provider::<MockHttp>::build_config(&raw).unwrap();
        assert_eq!(cfg.base_path, "MyFolder/");
        assert_eq!(cfg.vault_prefix(), "MyFolder/WattcloudVault/");
    }

    #[test]
    fn build_config_normalises_base_path_from_user_input() {
        // Users may paste "/MyFolder/" or similar; S3 keys don't have leading
        // slashes, so we strip them before storing.
        let mut raw = s3_cfg(false);
        raw.s3_base_path = Some("/MyFolder/".to_string());
        let cfg = S3Provider::<MockHttp>::build_config(&raw).unwrap();
        assert_eq!(cfg.base_path, "MyFolder/");
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
            "GET",
            "/my-bucket/WattcloudVault/file.v7",
            "",
            "s3.example.com",
            &[],
            "UNSIGNED-PAYLOAD",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            1705319696,
        );
        let auth2 = sigv4::authorization(
            "GET",
            "/my-bucket/WattcloudVault/file.v7",
            "",
            "s3.example.com",
            &[],
            "UNSIGNED-PAYLOAD",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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
            "https://s3.example.com/my-bucket/WattcloudVault/file.v7",
            "s3.example.com",
            "/my-bucket/WattcloudVault/file.v7",
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
            "GET",
            "/",
            "",
            VEC_HOST,
            &[],
            "UNSIGNED-PAYLOAD",
            VEC_REGION,
            VEC_ACCESS,
            VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(
            vec_sig(&auth),
            "f8815cdb11f23ac0476d526ba474c2f76561dcc4405465cd093a230e86a592d6"
        );
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn sigv4_vector_get_vanilla_query() {
        let auth = sigv4::authorization(
            "GET",
            "/",
            "Param1=value1&Param2=value2",
            VEC_HOST,
            &[],
            "UNSIGNED-PAYLOAD",
            VEC_REGION,
            VEC_ACCESS,
            VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(
            vec_sig(&auth),
            "599617b2e955f7f516469582df558e5752fd5e59153cc8a0a53bbbe08b345659"
        );
    }

    #[test]
    fn sigv4_vector_post_vanilla_query() {
        let auth = sigv4::authorization(
            "POST",
            "/",
            "Param1=value1&Param2=value2",
            VEC_HOST,
            &[],
            "UNSIGNED-PAYLOAD",
            VEC_REGION,
            VEC_ACCESS,
            VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(
            vec_sig(&auth),
            "4ec8141c5a9b7ec9287ac6c560764f09b5cfcf3141b6c775dc5718ca1a088709"
        );
    }

    #[test]
    fn sigv4_vector_get_utf8() {
        // Already percent-encoded path — implementation must not double-encode
        let auth = sigv4::authorization(
            "GET",
            "/%E1%88%B4",
            "",
            VEC_HOST,
            &[],
            "UNSIGNED-PAYLOAD",
            VEC_REGION,
            VEC_ACCESS,
            VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(
            vec_sig(&auth),
            "bec65300a6ac49a96bd3ede872abd38da64a4a3f7614af90c3b40d8e172ec4b3"
        );
    }

    #[test]
    fn sigv4_vector_header_duplicate_merge_order() {
        // Duplicate headers must be merged in original-request order (value2 first, then value1).
        // The canonical form must be "my-header1:value2,value1", not reversed.
        let auth = sigv4::authorization(
            "GET",
            "/",
            "",
            VEC_HOST,
            &[
                ("My-Header1".to_string(), "value2".to_string()),
                ("My-Header1".to_string(), "value1".to_string()),
            ],
            "UNSIGNED-PAYLOAD",
            VEC_REGION,
            VEC_ACCESS,
            VEC_SECRET,
            VEC_TS,
        );
        assert_eq!(
            vec_sig(&auth),
            "13edcc510734a17cdf8354e9d67d4f839adec8efb1474a3f58103d2fc8e8930c"
        );
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
            (200, "", vec![]),                       // HEAD bucket (init)
            (200, "", vec![("ETag", "\"abc123\"")]), // PUT object
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let result = p
            .upload(
                None,
                "vault.db".to_string(),
                b"hello".to_vec(),
                UploadOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.version, "abc123");
        assert_eq!(result.ref_, "WattcloudVault/vault.db");
        // Exactly 2 HTTP calls (init + PUT)
        assert_eq!(p.http.request_count(), 2);
    }

    #[test]
    fn gregorian_to_unix_days_matches_known_dates() {
        // 1970-01-01 is day 0.
        assert_eq!(gregorian_to_unix_days(1970, 1, 1), Some(0));
        // 1970-01-02 is day 1.
        assert_eq!(gregorian_to_unix_days(1970, 1, 2), Some(1));
        // 1972-02-29 (leap day) must be handled.
        assert_eq!(gregorian_to_unix_days(1972, 2, 29), Some(789));
        // 2000-01-01 (end of 30 years).
        assert_eq!(gregorian_to_unix_days(2000, 1, 1), Some(10957));
        // 2024-01-01 — regression: the old Zeller formula produced 19688.
        assert_eq!(gregorian_to_unix_days(2024, 1, 1), Some(19723));
        // Pre-epoch / malformed → None.
        assert_eq!(gregorian_to_unix_days(1969, 12, 31), None);
        assert_eq!(gregorian_to_unix_days(2024, 0, 1), None);
        assert_eq!(gregorian_to_unix_days(2024, 13, 1), None);
        assert_eq!(gregorian_to_unix_days(2024, 1, 0), None);
    }

    #[test]
    fn parse_iso8601_ms_recent_timestamp_is_close_to_wall_clock() {
        // 2024-01-15T12:34:56.000Z → 1705322096000 ms.
        let ms = parse_iso8601_ms("2024-01-15T12:34:56.000Z").unwrap();
        assert_eq!(ms, 1_705_322_096_000);
    }

    #[tokio::test]
    async fn init_falls_back_to_list_on_405() {
        // R2-style quirk: HEAD on bucket root returns 405 Method Not Allowed
        // even though the bucket is fine. We fall back to ListObjectsV2
        // max-keys=0 and succeed if that works.
        let http = MockHttp::with_headers(vec![
            (405, "", vec![]),                                      // HEAD
            (200, "<ListBucketResult></ListBucketResult>", vec![]), // GET list
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        assert!(p.is_ready());
        assert_eq!(p.http.request_count(), 2);
    }

    #[tokio::test]
    async fn init_does_not_fall_back_on_403() {
        // 403 is a real auth failure; must not be masked by a fallback GET.
        let http = MockHttp::with_headers(vec![(403, "", vec![])]);
        let p = S3Provider::new(http);
        let err = p.init(s3_cfg(true)).await.unwrap_err();
        assert!(matches!(err, ProviderError::Forbidden));
        assert_eq!(p.http.request_count(), 1);
    }

    #[tokio::test]
    async fn upload_stream_open_rejects_files_over_multipart_cap() {
        // Just-over-cap file size → fail fast before CreateMultipartUpload
        // is even issued. Only the init HEAD is consumed.
        let http = MockHttp::with_headers(vec![(200, "", vec![])]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();

        let oversized = MAX_MULTIPART_OBJECT_BYTES + 1;
        let err = p
            .upload_stream_open(
                None,
                "huge.bin".to_string(),
                oversized,
                UploadOptions::default(),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too large"), "got {msg}");
        assert!(msg.contains("multipart"), "got {msg}");
        // Only the init HEAD ran — no POST to CreateMultipartUpload.
        assert_eq!(p.http.request_count(), 1);
    }

    #[tokio::test]
    async fn upload_stream_open_accepts_exact_cap() {
        // Boundary: exactly MAX_PARTS * PART_SIZE must pass.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),
            (
                200,
                "<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>",
                vec![],
            ),
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        p.upload_stream_open(
            None,
            "limit.bin".to_string(),
            MAX_MULTIPART_OBJECT_BYTES,
            UploadOptions::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn upload_stream_open_allows_zero_total_size() {
        // total_size == 0 (caller doesn't know yet) must skip the upfront
        // gate; the runtime check in upload_stream_write catches runaway
        // callers via MAX_PARTS.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),
            (
                200,
                "<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>",
                vec![],
            ),
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        p.upload_stream_open(None, "unknown.bin".to_string(), 0, UploadOptions::default())
            .await
            .unwrap();
    }

    #[test]
    fn single_put_cap_is_5_gib() {
        // Sanity-check the constant. Allocating a 5 GiB buffer to exercise
        // the actual code path would OOM the test runner — this asserts the
        // value instead. The production gate at s3.rs `upload()` rejects
        // `data.len() as u64 > MAX_SINGLE_PUT_BYTES` with a clear message.
        assert_eq!(MAX_SINGLE_PUT_BYTES, 5u64 * 1024 * 1024 * 1024);
    }

    #[tokio::test]
    async fn upload_expected_version_match_proceeds() {
        // HEAD returns matching ETag → PUT runs as usual.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),                       // init HEAD bucket
            (200, "", vec![("ETag", "\"v1\"")]),     // HEAD object (current version)
            (200, "", vec![("ETag", "\"v2-new\"")]), // PUT object
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let result = p
            .upload(
                None,
                "vault.db".to_string(),
                b"updated".to_vec(),
                UploadOptions {
                    expected_version: Some("v1".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(result.version, "v2-new");
        assert_eq!(p.http.request_count(), 3);
    }

    #[tokio::test]
    async fn upload_expected_version_mismatch_returns_conflict() {
        // HEAD returns different ETag → Conflict, no PUT issued.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),                           // init
            (200, "", vec![("ETag", "\"v1-current\"")]), // HEAD shows different
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let err = p
            .upload(
                None,
                "vault.db".to_string(),
                b"updated".to_vec(),
                UploadOptions {
                    expected_version: Some("v1-stale".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Conflict { ref current_version } if current_version == "v1-current"
        ));
        // Only init + HEAD — PUT was skipped.
        assert_eq!(p.http.request_count(), 2);
    }

    #[tokio::test]
    async fn upload_expected_version_handles_multipart_etag() {
        // The stored version is the hyphenated multipart ETag; with HEAD-compare
        // it round-trips correctly even though a single-PUT re-upload would
        // otherwise 412 with If-Match.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]), // init
            (
                200,
                "",
                vec![("ETag", "\"d8e8fca2dc0f896fd7cb4cb0031ba249-3\"")],
            ), // HEAD: multipart ETag
            (200, "", vec![("ETag", "\"fresh-md5\"")]), // PUT: single-PUT replaces it
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let result = p
            .upload(
                None,
                "vault.db".to_string(),
                b"small".to_vec(),
                UploadOptions {
                    expected_version: Some("d8e8fca2dc0f896fd7cb4cb0031ba249-3".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(result.version, "fresh-md5");
    }

    #[tokio::test]
    async fn multipart_close_expected_version_mismatch_aborts() {
        // Expected version doesn't match current → HEAD diff → abort the upload,
        // return Conflict instead of calling CompleteMultipartUpload.
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]), // init
            (
                200,
                "<InitiateMultipartUploadResult><UploadId>up123</UploadId></InitiateMultipartUploadResult>",
                vec![],
            ),
            (200, "", vec![("ETag", "\"part1etag\"")]), // UploadPart
            (200, "", vec![("ETag", "\"current\"")]),   // HEAD at close time
            (204, "", vec![]),                          // AbortMultipartUpload
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();

        let sid = p
            .upload_stream_open(
                None,
                "big.v7".to_string(),
                10_000_000,
                UploadOptions {
                    expected_version: Some("stale".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), vec![0u8; PART_SIZE])
            .await
            .unwrap();
        let err = p.upload_stream_close(sid).await.unwrap_err();
        assert!(matches!(
            err,
            ProviderError::Conflict { ref current_version } if current_version == "current"
        ));
        // init + CreateMultipart + UploadPart + HEAD + Abort = 5
        assert_eq!(p.http.request_count(), 5);
    }

    #[tokio::test]
    async fn get_version_returns_etag() {
        let http = MockHttp::with_headers(vec![
            (200, "", vec![]),                         // init
            (200, "", vec![("ETag", "\"deadbeef\"")]), // HEAD object
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let version = p
            .get_version("WattcloudVault/file.v7".to_string())
            .await
            .unwrap();
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

        let sid = p
            .upload_stream_open(
                None,
                "big.v7".to_string(),
                20_000_000,
                UploadOptions::default(),
            )
            .await
            .unwrap();
        // Two parts: each PART_SIZE (8 MiB)
        p.upload_stream_write(sid.clone(), vec![0u8; PART_SIZE])
            .await
            .unwrap();
        p.upload_stream_write(sid.clone(), vec![1u8; PART_SIZE])
            .await
            .unwrap();
        let result = p.upload_stream_close(sid).await.unwrap();

        assert_eq!(result.ref_, "WattcloudVault/big.v7");
        assert_eq!(p.http.request_count(), 5);
    }

    #[tokio::test]
    async fn list_objects_v2_parsed_correctly() {
        let xml = r#"<ListBucketResult>
  <CommonPrefixes><Prefix>WattcloudVault/docs/</Prefix></CommonPrefixes>
  <Contents><Key>WattcloudVault/vault.db</Key><Size>4096</Size><LastModified>2024-01-15T12:34:56.000Z</LastModified></Contents>
  <Contents><Key>WattcloudVault/</Key><Size>0</Size><LastModified>2024-01-10T00:00:00.000Z</LastModified></Contents>
</ListBucketResult>"#;
        let http = MockHttp::new(vec![
            (200, ""),  // init
            (200, xml), // list
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
    async fn list_objects_v2_paginates_via_continuation_token() {
        let page1 = r#"<ListBucketResult>
  <Contents><Key>WattcloudVault/a.v7</Key><Size>10</Size></Contents>
  <Contents><Key>WattcloudVault/b.v7</Key><Size>20</Size></Contents>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>page2-token-xyz</NextContinuationToken>
</ListBucketResult>"#;
        let page2 = r#"<ListBucketResult>
  <Contents><Key>WattcloudVault/c.v7</Key><Size>30</Size></Contents>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;
        let http = MockHttp::new(vec![
            (200, ""),    // init HEAD
            (200, page1), // first list
            (200, page2), // second list, no more pages
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let entries = p.list(None).await.unwrap();

        // Should collect entries from both pages.
        assert_eq!(entries.len(), 3);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.v7"), "got {names:?}");
        assert!(names.contains(&"b.v7"), "got {names:?}");
        assert!(names.contains(&"c.v7"), "got {names:?}");
    }

    #[tokio::test]
    async fn list_objects_v2_parses_namespace_prefixed_xml() {
        // MinIO / Ceph occasionally emit ListObjectsV2 with an explicit
        // xmlns prefix. The substring-based parser returned an empty list on
        // these responses; the quick-xml parser should strip the prefix via
        // local_name() and produce the same entries as the unprefixed form.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<s3:ListBucketResult xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/">
  <s3:CommonPrefixes><s3:Prefix>WattcloudVault/docs/</s3:Prefix></s3:CommonPrefixes>
  <s3:Contents>
    <s3:Key>WattcloudVault/vault.db</s3:Key>
    <s3:Size>4096</s3:Size>
    <s3:LastModified>2024-01-15T12:34:56.000Z</s3:LastModified>
  </s3:Contents>
</s3:ListBucketResult>"#;
        let http = MockHttp::new(vec![(200, ""), (200, xml)]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let entries = p.list(None).await.unwrap();

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.is_folder && e.name == "docs"));
        assert!(entries
            .iter()
            .any(|e| !e.is_folder && e.name == "vault.db" && e.size == 4096));
    }

    #[tokio::test]
    async fn presigned_url_ttl_capped_at_max() {
        let http = MockHttp::with_headers(vec![(200, "", vec![])]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();

        // Request 7 days (604800s) — must be capped at 86400s (24 hours).
        let url = p
            .create_presigned_url("WattcloudVault/file.v7".to_string(), 604_800)
            .await
            .unwrap();
        assert!(url.contains("X-Amz-Expires=86400"));
    }

    #[tokio::test]
    async fn create_folder_puts_slash_object() {
        let http =
            MockHttp::with_headers(vec![(200, "", vec![]), (200, "", vec![("ETag", "\"ef\"")])]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        let ref_ = p.create_folder("docs".to_string(), None).await.unwrap();
        assert_eq!(ref_, "WattcloudVault/docs/");
        let (method, url) = p.http.last_request().unwrap();
        assert_eq!(method, "PUT");
        assert!(url.contains("WattcloudVault/docs/"));
    }

    #[tokio::test]
    async fn delete_returns_ok_on_404() {
        let http = MockHttp::new(vec![
            (200, ""), // init
            (404, ""), // DELETE (already deleted)
        ]);
        let p = S3Provider::new(http);
        p.init(s3_cfg(true)).await.unwrap();
        // 404 on DELETE = already deleted = OK
        p.delete("WattcloudVault/gone.v7".to_string())
            .await
            .unwrap();
    }

    #[test]
    fn parse_xml_text_helper() {
        let xml = b"<UploadId>my-upload-id-123</UploadId>";
        assert_eq!(
            parse_xml_text(xml, "UploadId"),
            Some("my-upload-id-123".to_string())
        );
        assert_eq!(parse_xml_text(xml, "MissingTag"), None);
    }
}
