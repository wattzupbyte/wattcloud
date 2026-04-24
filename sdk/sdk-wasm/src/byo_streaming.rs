// Phase 3d: provider-integrated upload/download streaming sessions.
//
// Each session keeps a long-lived concrete provider instance (via Rc<dyn Fn>
// closures) so that stateful providers (S3 multipart, Box, WebDAV chunking)
// maintain their internal session maps across multiple push/pull calls.
//
// # Why Rc<dyn Fn> closures instead of Box<dyn StorageProvider>
//
// StorageProvider uses RPITIT (`impl Future`) which is not object-safe — it
// cannot be used as `dyn StorageProvider`. Instead each session stores
// Rc-wrapped closures that capture a concrete Rc<P>. Cloning the Rc from
// inside a RefCell borrow before the async call avoids holding the borrow
// across an await point, satisfying both the borrow checker and RefCell's
// single-borrow rule.
//
// # ZK invariants
//
// ZK-5: ciphertext is passed directly to provider.upload_stream_write; it is
//       never returned to JS. Plaintext crosses WASM/JS at push() / pull()
//       only, bounded by V7_ENCRYPT_CHUNK_SIZE = 512 KiB.
// ZK-6: dst `name` (upload) must be data/{uuid} — enforced at the JS call site.
// Key material: V7StreamEncryptor / V7StreamDecryptor own the content key and
//   HMAC state. They are dropped (and thus ZeroizeOnDrop-ed) when the session
//   struct is removed from the thread_local map on finalize / abort / error.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use wasm_bindgen::prelude::*;

use sdk_core::byo::provider::{
    ProviderConfig, ProviderError, StorageProvider, UploadOptions, UploadResult,
};
use sdk_core::byo::streaming::constants::V7_ENCRYPT_CHUNK_SIZE;
use sdk_core::byo::streaming::{ByoDownloadFlow, ByoUploadFlow};

use crate::provider_http::ReqwestProviderHttpClient;
use crate::util::{parse_public_keys, parse_secret_keys};

// ── Boxed future alias (no Send — WASM is single-threaded) ────────────────────

type BoxFut<T> = Pin<Box<dyn Future<Output = T>>>;
type RcFn<A, T> = Rc<dyn Fn(A) -> BoxFut<Result<T, ProviderError>>>;
type RcFn0<T> = Rc<dyn Fn() -> BoxFut<Result<T, ProviderError>>>;

// ── Upload session ─────────────────────────────────────────────────────────────

struct UploadSession {
    flow: Option<ByoUploadFlow>,
    write: RcFn<Vec<u8>, ()>,
    close: RcFn0<UploadResult>,
    abort: RcFn0<()>,
}

thread_local! {
    static UPLOADS: RefCell<HashMap<String, UploadSession>> = RefCell::new(HashMap::new());
    static DOWNLOADS: RefCell<HashMap<String, DownloadSession>> = RefCell::new(HashMap::new());
}

/// Generate an unpredictable session ID using the CSPRNG.
///
/// Session IDs are map keys — not auth tokens — but `Math.random()` is a
/// non-cryptographic PRNG and using it here violates the crate's "only approved
/// entropy source is `crypto.getRandomValues`" rule (see `sdk/SECURITY.md` §4).
/// With a predictable PRNG, any code sharing the worker context could predict
/// the next session ID and call `byoStreamDownloadClose` on a victim session,
/// evicting it from the map and silently aborting the HMAC verification.
///
/// `getrandom::getrandom` maps to `crypto.getRandomValues` on wasm32 via the
/// `js` feature that's already enabled in the workspace.
fn session_id() -> String {
    let mut bytes = [0u8; 16];
    // If the CSPRNG is unavailable we have nothing useful to fall back to —
    // returning a known-bad ID ("00000000…") would only delay failure until
    // the first collision. Prefer loud failure: the next caller observing the
    // format mismatch can report the degradation.
    if getrandom::getrandom(&mut bytes).is_err() {
        // Extremely unlikely: a browser without `crypto.getRandomValues` is
        // not a supported target. Make the failure mode observable.
        return "csprng-unavailable".to_string();
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn make_upload_session<P: StorageProvider + 'static>(
    flow: ByoUploadFlow,
    provider: P,
    stream_id: String,
) -> UploadSession {
    let p = Rc::new(provider);

    let (p1, sid1) = (p.clone(), stream_id.clone());
    let write: RcFn<Vec<u8>, ()> = Rc::new(move |chunk: Vec<u8>| {
        let (p, sid) = (p1.clone(), sid1.clone());
        Box::pin(async move { p.upload_stream_write(sid, chunk).await }) as BoxFut<_>
    });

    let (p2, sid2) = (p.clone(), stream_id.clone());
    let close: RcFn0<UploadResult> = Rc::new(move || {
        let (p, sid) = (p2.clone(), sid2.clone());
        Box::pin(async move { p.upload_stream_close(sid).await }) as BoxFut<_>
    });

    let (p3, sid3) = (p.clone(), stream_id.clone());
    let abort: RcFn0<()> = Rc::new(move || {
        let (p, sid) = (p3.clone(), sid3.clone());
        Box::pin(async move { p.upload_stream_abort(sid).await.map(|_| ()) }) as BoxFut<_>
    });

    UploadSession {
        flow: Some(flow),
        write,
        close,
        abort,
    }
}

/// Open a provider upload stream and initialise a V7 streaming upload session.
///
/// Returns `{ sessionId, chunkSize }`. Non-final push calls must supply exactly
/// `chunkSize` bytes of plaintext.
#[wasm_bindgen(js_name = byoStreamUploadInit)]
pub async fn byo_stream_upload_init(
    pub_keys_json: &str,
    provider_type: &str,
    config_json: &str,
    name: String,
    parent_ref: Option<String>,
    plaintext_len: f64,
) -> Result<JsValue, JsValue> {
    let cfg: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (mlkem_pub, x25519_pub) = parse_public_keys(pub_keys_json)?;
    let (flow, header, total_size) =
        ByoUploadFlow::new(&mlkem_pub, &x25519_pub, plaintext_len as u64)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let opts = UploadOptions {
        parent_ref,
        ..Default::default()
    };

    macro_rules! init_provider {
        ($ty:ty) => {{
            let p = <$ty>::new(ReqwestProviderHttpClient::new());
            p.init(cfg)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let stream_id = p
                .upload_stream_open(None, name, total_size, opts)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            // Write V7 header as the first bytes of the upload.
            p.upload_stream_write(stream_id.clone(), header)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let sid = session_id();
            UPLOADS.with(|m| {
                m.borrow_mut()
                    .insert(sid.clone(), make_upload_session(flow, p, stream_id))
            });
            Ok::<String, JsValue>(sid)
        }};
    }

    let session_id = match provider_type {
        "gdrive" => init_provider!(sdk_core::byo::GdriveProvider<ReqwestProviderHttpClient>),
        "dropbox" => init_provider!(sdk_core::byo::DropboxProvider<ReqwestProviderHttpClient>),
        "onedrive" => init_provider!(sdk_core::byo::OneDriveProvider<ReqwestProviderHttpClient>),
        "webdav" => init_provider!(sdk_core::byo::WebDAVProvider<ReqwestProviderHttpClient>),
        "box" => init_provider!(sdk_core::byo::BoxProvider<ReqwestProviderHttpClient>),
        "pcloud" => init_provider!(sdk_core::byo::PCloudProvider<ReqwestProviderHttpClient>),
        "s3" => init_provider!(sdk_core::byo::S3Provider<ReqwestProviderHttpClient>),
        other => return Err(JsValue::from_str(&format!("unknown provider: {other}"))),
    }?;

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("sessionId"),
        &JsValue::from_str(&session_id),
    )
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("chunkSize"),
        &JsValue::from_f64(V7_ENCRYPT_CHUNK_SIZE as f64),
    )
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Encrypt one plaintext chunk and write the cipher frame to the provider.
///
/// Nothing is returned to JS — ciphertext stays inside WASM (ZK-5).
/// Non-final chunks must be exactly V7_ENCRYPT_CHUNK_SIZE (512 KiB).
#[wasm_bindgen(js_name = byoStreamUploadPush)]
pub async fn byo_stream_upload_push(
    session_id: &str,
    plaintext: Vec<u8>,
    is_last: bool,
) -> Result<(), JsValue> {
    // Borrow, encrypt, clone Rc — all before any await.
    let (frame, write) = UPLOADS.with(|m| {
        let mut map = m.borrow_mut();
        let s = map
            .get_mut(session_id)
            .ok_or_else(|| JsValue::from_str("byoStreamUploadPush: session not found"))?;
        let flow = s
            .flow
            .as_mut()
            .ok_or_else(|| JsValue::from_str("byoStreamUploadPush: already finalised"))?;
        let frame = flow
            .push_chunk(&plaintext, is_last)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok::<_, JsValue>((frame, Rc::clone(&s.write)))
    })?;

    write(frame)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Write the HMAC footer, close the provider stream, return `{ ref, version }` JSON.
///
/// Drops the session — encryptor's content_key is zeroized.
#[wasm_bindgen(js_name = byoStreamUploadFinalize)]
pub async fn byo_stream_upload_finalize(session_id: &str) -> Result<JsValue, JsValue> {
    // C6: evict the session from the thread_local map BEFORE any .await. If
    // `write(footer)` or `close()` fails, we must still drop the encryptor so
    // content_key is zeroized — previously the `?` propagation below left the
    // session in the map, leaking key material until the sweeper ran (if ever).
    let mut session = UPLOADS
        .with(|m| m.borrow_mut().remove(session_id))
        .ok_or_else(|| JsValue::from_str("byoStreamUploadFinalize: session not found"))?;

    let flow_owned = session
        .flow
        .take()
        .ok_or_else(|| JsValue::from_str("byoStreamUploadFinalize: already finalised"))?;
    let write = Rc::clone(&session.write);
    let close = Rc::clone(&session.close);
    let footer = flow_owned
        .finalize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .to_vec();

    write(footer)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = close()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_json::to_string(&result)
        .map(|s| JsValue::from_str(&s))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Abort an in-progress upload. Drops the encryptor (zeroizes content_key).
#[wasm_bindgen(js_name = byoStreamUploadAbort)]
pub async fn byo_stream_upload_abort(session_id: &str) -> Result<(), JsValue> {
    let abort = UPLOADS.with(|m| {
        m.borrow_mut().remove(session_id).map(|s| s.abort)
        // ByoUploadFlow dropped here → ZeroizeOnDrop on content_key
    });
    if let Some(abort) = abort {
        let _ = abort().await; // best-effort; don't surface abort error to caller
    }
    Ok(())
}

// ── Download session ───────────────────────────────────────────────────────────

struct DownloadSession {
    flow: ByoDownloadFlow,
    read: RcFn0<Option<Vec<u8>>>,
    close: RcFn0<()>,
    /// Milliseconds since a reference epoch (Date.now()), set on create and
    /// refreshed by every pull. Used by `byoStreamSweepStale` (S11) to evict
    /// sessions whose caller abandoned the HMAC-verify close step and that
    /// would otherwise pin `content_key` + HMAC state in the worker heap.
    last_touch_ms: f64,
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

fn make_download_session<P: StorageProvider + 'static>(
    flow: ByoDownloadFlow,
    provider: P,
    stream_id: String,
) -> DownloadSession {
    let p = Rc::new(provider);

    let (p1, sid1) = (p.clone(), stream_id.clone());
    let read: RcFn0<Option<Vec<u8>>> = Rc::new(move || {
        let (p, sid) = (p1.clone(), sid1.clone());
        Box::pin(async move { p.download_stream_read(sid).await }) as BoxFut<_>
    });

    let (p2, sid2) = (p.clone(), stream_id.clone());
    let close: RcFn0<()> = Rc::new(move || {
        let (p, sid) = (p2.clone(), sid2.clone());
        Box::pin(async move { p.download_stream_close(sid).await }) as BoxFut<_>
    });

    DownloadSession {
        flow,
        read,
        close,
        last_touch_ms: now_ms(),
    }
}

/// Open a provider download stream and initialise a V7 streaming download session.
///
/// Returns the session ID. Pull plaintext chunks via `byoStreamDownloadPull`
/// until it returns `null`, then call `byoStreamDownloadClose`.
#[wasm_bindgen(js_name = byoStreamDownloadInit)]
pub async fn byo_stream_download_init(
    sec_keys_json: &str,
    provider_type: &str,
    config_json: &str,
    ref_: String,
) -> Result<String, JsValue> {
    let cfg: ProviderConfig =
        serde_json::from_str(config_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (mlkem_sec, x25519_sec) = parse_secret_keys(sec_keys_json)?;
    let flow = ByoDownloadFlow::new(mlkem_sec, x25519_sec);

    macro_rules! init_provider {
        ($ty:ty) => {{
            let p = <$ty>::new(ReqwestProviderHttpClient::new());
            p.init(cfg)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let stream_id = p
                .download_stream_open(ref_)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let sid = session_id();
            DOWNLOADS.with(|m| {
                m.borrow_mut()
                    .insert(sid.clone(), make_download_session(flow, p, stream_id))
            });
            Ok::<String, JsValue>(sid)
        }};
    }

    match provider_type {
        "gdrive" => init_provider!(sdk_core::byo::GdriveProvider<ReqwestProviderHttpClient>),
        "dropbox" => init_provider!(sdk_core::byo::DropboxProvider<ReqwestProviderHttpClient>),
        "onedrive" => init_provider!(sdk_core::byo::OneDriveProvider<ReqwestProviderHttpClient>),
        "webdav" => init_provider!(sdk_core::byo::WebDAVProvider<ReqwestProviderHttpClient>),
        "box" => init_provider!(sdk_core::byo::BoxProvider<ReqwestProviderHttpClient>),
        "pcloud" => init_provider!(sdk_core::byo::PCloudProvider<ReqwestProviderHttpClient>),
        "s3" => init_provider!(sdk_core::byo::S3Provider<ReqwestProviderHttpClient>),
        other => Err(JsValue::from_str(&format!("unknown provider: {other}"))),
    }
}

/// Pull the next plaintext chunk. Returns `null` at EOF (then call Close).
///
/// Returns a `Uint8Array` (may be empty during the 1709-byte header accumulation phase).
#[wasm_bindgen(js_name = byoStreamDownloadPull)]
pub async fn byo_stream_download_pull(session_id: &str) -> Result<JsValue, JsValue> {
    // Clone the read Rc before awaiting.
    let read = DOWNLOADS.with(|m| {
        m.borrow()
            .get(session_id)
            .map(|s| Rc::clone(&s.read))
            .ok_or_else(|| JsValue::from_str("byoStreamDownloadPull: session not found"))
    })?;

    let maybe_chunk = read()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    match maybe_chunk {
        None => Ok(JsValue::null()),
        Some(raw_cipher) => {
            let plaintext = DOWNLOADS.with(|m| {
                let mut map = m.borrow_mut();
                let s = map.get_mut(session_id).ok_or_else(|| {
                    JsValue::from_str("byoStreamDownloadPull: session disappeared")
                })?;
                // S11: refresh the last-touch timestamp so the sweeper
                // doesn't evict an active session between chunks.
                s.last_touch_ms = now_ms();
                s.flow
                    .push(&raw_cipher)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            })?;
            Ok(js_sys::Uint8Array::from(plaintext.as_slice()).into())
        }
    }
}

/// Evict download sessions that have not been touched (pull/close) for at
/// least `max_age_ms` milliseconds (S11).
///
/// Hosts call this on an idle tick (or on `visibilitychange → hidden`) to
/// release `content_key` + HMAC state held by `ByoDownloadFlow` sessions
/// whose callers abandoned the pipeline after EOF (`pull → null`) without
/// a subsequent `byoStreamDownloadClose`. Also evicts sessions abandoned
/// mid-stream by a crashed caller. HMAC verification is NOT run on evict —
/// any plaintext already yielded to the host must be discarded by the host;
/// the eviction just reclaims WASM heap.
#[wasm_bindgen(js_name = byoStreamSweepStale)]
pub fn byo_stream_sweep_stale(max_age_ms: f64) -> u32 {
    let now = now_ms();
    DOWNLOADS.with(|m| {
        let mut map = m.borrow_mut();
        let before = map.len();
        map.retain(|_, s| now - s.last_touch_ms < max_age_ms);
        (before - map.len()) as u32
    })
}

/// Verify the trailing HMAC footer and close the provider stream.
///
/// SECURITY: callers MUST ensure this returns `Ok` before trusting any
/// previously yielded plaintext. Drops the decryptor (ZeroizeOnDrop).
#[wasm_bindgen(js_name = byoStreamDownloadClose)]
pub async fn byo_stream_download_close(session_id: &str) -> Result<(), JsValue> {
    let (flow, close) = DOWNLOADS.with(|m| {
        m.borrow_mut()
            .remove(session_id)
            .map(|s| (s.flow, s.close))
            .ok_or_else(|| JsValue::from_str("byoStreamDownloadClose: session not found"))
    })?;

    // Verify HMAC before closing the provider stream.
    flow.finalize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Close the provider download stream (best-effort — HMAC already verified).
    let _ = close().await;
    Ok(())
}
