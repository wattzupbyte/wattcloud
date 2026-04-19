// WASM bindings for the Rust-native BYO storage provider orchestrators.
//
// These replace the TS provider HTTP implementations (GDriveProvider.ts, etc.)
// with direct calls to the Rust providers backed by reqwest wasm fetch.
//
// API conventions:
//   - config_json: JSON string of ProviderConfig (sdk-core byo::provider)
//   - plaintext: Uint8Array (raw bytes, not base64)
//   - return value of download: Uint8Array
//   - ref_: provider file reference (opaque string)
//   - pub_keys_json / sec_keys_json: JSON with mlkem / x25519 keys as base64
//
// Token refresh functions return a new config_json string with updated tokens.
// Callers must persist the updated config before retrying.

use wasm_bindgen::prelude::*;

use sdk_core::byo::provider::{ProviderConfig, ProviderError, StorageProvider, UploadOptions, UploadResult};

use crate::provider_http::ReqwestProviderHttpClient;
use crate::util::{b64_decode, b64_encode};


// ─── Token refresh helper ─────────────────────────────────────────────────────

async fn do_refresh_token(mut config: ProviderConfig, token_url: &str) -> Result<String, JsValue> {
    use sdk_core::api::{ProviderHttpClient, ProviderHttpRequest};
    use sdk_core::byo::oauth::{build_refresh_form, parse_token_response};

    let refresh_token = config
        .refresh_token
        .clone()
        .ok_or_else(|| JsValue::from_str("refresh_token missing from config"))?;
    let client_id = config
        .client_id
        .clone()
        .ok_or_else(|| JsValue::from_str("client_id missing from config"))?;

    let form = build_refresh_form(&refresh_token, &client_id);
    let http = ReqwestProviderHttpClient::new();
    let req = ProviderHttpRequest::post(token_url.to_string())
        .header(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()))
        .body(form.into_bytes());

    let resp = http
        .request(req)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    if resp.status < 200 || resp.status >= 300 {
        return Err(JsValue::from_str(&format!(
            "token refresh failed: HTTP {} {}",
            resp.status,
            String::from_utf8_lossy(&resp.body).chars().take(200).collect::<String>()
        )));
    }

    let tok = parse_token_response(&resp.body).map_err(|e| JsValue::from_str(&e.to_string()))?;
    config.access_token = Some(tok.access_token);
    if let Some(new_rt) = tok.refresh_token {
        config.refresh_token = Some(new_rt);
    }
    if let Some(expires_in) = tok.expires_in {
        // Use js_sys::Date for wasm timestamp
        let now_ms = js_sys::Date::now() as i64;
        config.token_expiry = Some(now_ms + (expires_in as i64) * 1000);
    }

    serde_json::to_string(&config).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Generic provider dispatcher (P8) ────────────────────────────────────────
//
// Single entry point covering all StorageProvider operations for every provider.
// Binary data (upload data, download result) is base64-encoded inside the JSON
// args/result — acceptable overhead since messages already cross a worker boundary.
//
// Operations: upload, download, list, delete, getVersion, createFolder,
//   deleteFolder, createPublicLink, revokePublicLink, createPresignedUrl
//
// args_json always contains a "config" field (ProviderConfig JSON).
// Result is always a JSON string (null literal, string, or object/array).

async fn dispatch_op<P: StorageProvider>(
    provider: &P,
    op: &str,
    args: &serde_json::Value,
) -> Result<String, JsValue> {
    // Helper: extract a required string field.
    let str_field = |key: &str| {
        args[key]
            .as_str()
            .ok_or_else(|| JsValue::from_str(&format!("missing required field: {key}")))
    };

    match op {
        "upload" => {
            let ref_ = args["ref"].as_str().map(String::from);
            let name = str_field("name")?.to_string();
            let data = b64_decode(str_field("datab64")?)?;
            let expected_version = args["expectedVersion"].as_str().map(String::from);
            let parent_ref = args["parentRef"].as_str().map(String::from);
            let options = UploadOptions { expected_version, parent_ref, ..Default::default() };
            let result = provider.upload(ref_, name, data, options).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "download" => {
            let ref_ = str_field("ref")?.to_string();
            let data = provider.download(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let encoded = b64_encode(&data);
            serde_json::to_string(&serde_json::json!({ "datab64": encoded }))
                .map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "list" => {
            let parent_ref = args["parentRef"].as_str().map(String::from);
            let entries = provider.list(parent_ref).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&entries).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "delete" => {
            let ref_ = str_field("ref")?.to_string();
            provider.delete(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok("null".to_string())
        }
        "getVersion" => {
            let ref_ = str_field("ref")?.to_string();
            let version = provider.get_version(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&version).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "createFolder" => {
            let name = str_field("name")?.to_string();
            let parent_ref = args["parentRef"].as_str().map(String::from);
            let ref_ = provider.create_folder(name, parent_ref).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&serde_json::json!({ "ref": ref_ }))
                .map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "deleteFolder" => {
            let ref_ = str_field("ref")?.to_string();
            provider.delete_folder(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok("null".to_string())
        }
        "createPublicLink" => {
            let ref_ = str_field("ref")?.to_string();
            let url = provider.create_public_link(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&url).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        "revokePublicLink" => {
            let ref_ = str_field("ref")?.to_string();
            provider.revoke_public_link(ref_).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok("null".to_string())
        }
        "createPresignedUrl" => {
            let ref_ = str_field("ref")?.to_string();
            let ttl = args["ttlSeconds"].as_u64().unwrap_or(3600) as u32;
            let url = provider.create_presigned_url(ref_, ttl).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            serde_json::to_string(&url).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        _ => Err(JsValue::from_str(&format!("byoProviderCall: unknown op: {op}"))),
    }
}

/// Generic BYO provider dispatcher. Covers all StorageProvider raw operations
/// (upload/download/list/delete/getVersion/createFolder/deleteFolder/
///  createPublicLink/revokePublicLink/createPresignedUrl) for every provider type.
///
/// args_json: JSON object with "config" (ProviderConfig) + op-specific fields.
/// Returns a JSON string whose shape depends on op (see dispatch_op above).
///
/// D1: streaming operations (`upload_stream_*` / `download_stream_*`) are NOT
/// routed through this dispatcher because each call here instantiates a fresh
/// provider — the per-provider in-memory session maps (S3 multipart, Box
/// upload buffers, GDrive resumable session URI) would be discarded between
/// calls. Streaming uses `byo_streaming::byo_stream_*` instead, which owns a
/// long-lived provider instance inside a thread_local session map.
#[wasm_bindgen(js_name = byoProviderCall)]
pub async fn byo_provider_call(
    provider_type: &str,
    op: &str,
    args_json: &str,
) -> Result<String, JsValue> {
    let args: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let config: ProviderConfig = serde_json::from_value(
        args.get("config").cloned().ok_or_else(|| JsValue::from_str("missing 'config' in args"))?
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    macro_rules! with_provider {
        ($p:expr) => {{
            $p.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            dispatch_op(&$p, op, &args).await
        }};
    }

    match provider_type {
        "gdrive"  => with_provider!(sdk_core::byo::GdriveProvider::new(ReqwestProviderHttpClient::new())),
        "dropbox" => with_provider!(sdk_core::byo::DropboxProvider::new(ReqwestProviderHttpClient::new())),
        "onedrive" => with_provider!(sdk_core::byo::OneDriveProvider::new(ReqwestProviderHttpClient::new())),
        "webdav"  => with_provider!(sdk_core::byo::WebDAVProvider::new(ReqwestProviderHttpClient::new())),
        "box"     => with_provider!(sdk_core::byo::BoxProvider::new(ReqwestProviderHttpClient::new())),
        "pcloud"  => with_provider!(sdk_core::byo::PCloudProvider::new(ReqwestProviderHttpClient::new())),
        "s3"      => with_provider!(sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new())),
        _ => Err(JsValue::from_str(&format!("byoProviderCall: unknown provider_type: {provider_type}"))),
    }
}

// ─── GDrive ──────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = byoGdriveRefreshToken)]
pub async fn byo_gdrive_refresh_token(config_json: &str) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    do_refresh_token(config, "https://oauth2.googleapis.com/token").await
}

// ─── Dropbox ──────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = byoDropboxRefreshToken)]
pub async fn byo_dropbox_refresh_token(config_json: &str) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    do_refresh_token(config, "https://api.dropbox.com/oauth2/token").await
}

// ─── OneDrive ─────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = byoOnedriveRefreshToken)]
pub async fn byo_onedrive_refresh_token(config_json: &str) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    do_refresh_token(
        config,
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    )
    .await
}

// ─── WebDAV ───────────────────────────────────────────────────────────────────
// WebDAV has no token refresh (static Basic auth credentials)

// ─── Box ──────────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = byoBoxRefreshToken)]
pub async fn byo_box_refresh_token(config_json: &str) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    do_refresh_token(config, "https://api.box.com/oauth2/token").await
}

// ─── pCloud ───────────────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = byoPcloudRefreshToken)]
pub async fn byo_pcloud_refresh_token(config_json: &str) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    // pCloud has two regional token endpoints; pick based on pcloud_region in config.
    let token_url = if config.pcloud_region.as_deref() == Some("eu") {
        "https://eapi.pcloud.com/oauth2_token"
    } else {
        "https://api.pcloud.com/oauth2_token"
    };
    do_refresh_token(config, token_url).await
}

// ─── S3-family (S3 / R2 / B2 / Wasabi / MinIO) ───────────────────────────────
//
// S3 provider is WASM-only (no TS class). Utility operations for vault management
// and direct raw access are below; generic file I/O goes through byoProviderCall.

/// List files/folders at `prefix`. Returns JSON array of StorageEntry.
#[wasm_bindgen(js_name = byoS3List)]
pub async fn byo_s3_list(
    config_json: &str,
    parent_ref: Option<String>,
) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    let entries = provider.list(parent_ref).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&entries).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Delete a file by ref. Idempotent (404 = OK).
#[wasm_bindgen(js_name = byoS3Delete)]
pub async fn byo_s3_delete(config_json: &str, ref_: String) -> Result<(), JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider.delete(ref_).await.map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Return the ETag (version) for an object.
#[wasm_bindgen(js_name = byoS3GetVersion)]
pub async fn byo_s3_get_version(config_json: &str, ref_: String) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider.get_version(ref_).await.map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Create a presigned GET URL (capped at 24 hours). Used for share link variant B1.
#[wasm_bindgen(js_name = byoS3CreatePresignedUrl)]
pub async fn byo_s3_create_presigned_url(
    config_json: &str,
    ref_: String,
    ttl_seconds: u32,
) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider.create_presigned_url(ref_, ttl_seconds).await.map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Raw upload of pre-encrypted bytes (e.g. vault file saves). Returns JSON UploadResult.
#[wasm_bindgen(js_name = byoS3UploadRaw)]
pub async fn byo_s3_upload_raw(
    config_json: &str,
    ref_: Option<String>,
    name: String,
    data: Vec<u8>,
    expected_version: Option<String>,
) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    let options = UploadOptions { expected_version, ..Default::default() };
    let result = provider.upload(ref_, name, data, options).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Raw download returning V7 ciphertext bytes.
#[wasm_bindgen(js_name = byoS3DownloadRaw)]
pub async fn byo_s3_download_raw(config_json: &str, ref_: String) -> Result<Vec<u8>, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    let data = provider.download(ref_).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(data)
}

/// Create a folder (zero-byte object with trailing "/").
#[wasm_bindgen(js_name = byoS3CreateFolder)]
pub async fn byo_s3_create_folder(
    config_json: &str,
    name: String,
    parent_ref: Option<String>,
) -> Result<String, JsValue> {
    let config: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let provider = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
    provider.init(config).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider.create_folder(name, parent_ref).await.map_err(|e| JsValue::from_str(&e.to_string()))
}

// ─── Cross-provider streaming pipe (Phase 3c) ─────────────────────────────────
//
// V7 ciphertext is piped verbatim from source to destination entirely inside
// WASM. No bytes cross the JS boundary during the transfer.
//
// ZK invariants:
//   ZK-5: bytes are already V7-encrypted; they travel src provider → dst provider
//         without decryption or re-encryption.
//   ZK-6: dst_name MUST be an opaque blob path (data/{uuid}), never a plaintext
//         filename. Callers are responsible for supplying the correct name.

/// Stream-copy a V7 ciphertext blob from one provider to another.
///
/// Both providers are instantiated and managed entirely inside WASM;
/// no ciphertext bytes cross the WASM/JS boundary.
///
/// Returns `{ ref, version }` JSON matching UploadResult on success.
#[wasm_bindgen(js_name = byoCrossProviderStreamCopy)]
pub async fn byo_cross_provider_stream_copy(
    src_type: &str,
    src_config_json: &str,
    dst_type: &str,
    dst_config_json: &str,
    src_ref: String,
    // Opaque blob name — MUST be data/{uuid}, never a plaintext filename (ZK-6).
    dst_name: String,
    total_size: u64,
) -> Result<JsValue, JsValue> {
    let src_cfg: ProviderConfig = serde_json::from_str(src_config_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let dst_cfg: ProviderConfig = serde_json::from_str(dst_config_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Macro: instantiate the destination provider and run the pipe.
    // Expanded inside each src_type arm; src_ref/dst_name/total_size are
    // consumed by exactly one arm at runtime (Rust knows match arms are exclusive).
    macro_rules! with_dst {
        ($src:expr) => {
            match dst_type {
                "gdrive" => {
                    let dst = sdk_core::byo::GdriveProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "dropbox" => {
                    let dst = sdk_core::byo::DropboxProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "onedrive" => {
                    let dst = sdk_core::byo::OneDriveProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "webdav" => {
                    let dst = sdk_core::byo::WebDAVProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "box" => {
                    let dst = sdk_core::byo::BoxProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "pcloud" => {
                    let dst = sdk_core::byo::PCloudProvider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                "s3" => {
                    let dst = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
                    dst.init(dst_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
                    pipe_between_providers(&$src, &dst, src_ref, dst_name, total_size).await
                }
                other => Err(ProviderError::Provider(format!("unknown dst provider: {other}"))),
            }
            .map_err(|e| JsValue::from_str(&e.to_string()))
        };
    }

    let upload_result: Result<UploadResult, JsValue> = match src_type {
        "gdrive" => {
            let src = sdk_core::byo::GdriveProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "dropbox" => {
            let src = sdk_core::byo::DropboxProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "onedrive" => {
            let src = sdk_core::byo::OneDriveProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "webdav" => {
            let src = sdk_core::byo::WebDAVProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "box" => {
            let src = sdk_core::byo::BoxProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "pcloud" => {
            let src = sdk_core::byo::PCloudProvider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        "s3" => {
            let src = sdk_core::byo::S3Provider::new(ReqwestProviderHttpClient::new());
            src.init(src_cfg).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            with_dst!(src)
        }
        other => Err(JsValue::from_str(&format!("unknown src provider: {other}"))),
    };

    let result = upload_result?;
    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Inner pipe — generic over provider types so it is monomorphized by the compiler.
/// Runs entirely in WASM; no data crosses the JS boundary.
async fn pipe_between_providers<S: StorageProvider, D: StorageProvider>(
    src: &S,
    dst: &D,
    src_ref: String,
    dst_name: String,
    total_size: u64,
) -> Result<UploadResult, ProviderError> {
    let dl_id = src.download_stream_open(src_ref).await?;
    let ul_id = match dst
        .upload_stream_open(None, dst_name, total_size, UploadOptions::default())
        .await
    {
        Ok(id) => id,
        Err(e) => {
            let _ = src.download_stream_close(dl_id).await;
            return Err(e);
        }
    };

    let outcome: Result<UploadResult, ProviderError> = async {
        while let Some(chunk) = src.download_stream_read(dl_id.clone()).await? {
            dst.upload_stream_write(ul_id.clone(), chunk).await?;
        }
        dst.upload_stream_close(ul_id.clone()).await
    }
    .await;

    // Always close the download stream regardless of upload outcome.
    let _ = src.download_stream_close(dl_id).await;
    match outcome {
        Ok(r) => Ok(r),
        Err(e) => {
            let _ = dst.upload_stream_abort(ul_id).await;
            Err(e)
        }
    }
}
