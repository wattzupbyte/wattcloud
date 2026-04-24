// BYO usage-statistics WASM bridge.
//
// Exposes a minimal set of #[wasm_bindgen] entry points so the TypeScript
// stats client can queue events and flush them to POST /relay/stats.
//
// Architecture
// ─────────────
// A single static OnceLock<Mutex<StatsState>> holds the ring-buffer sink,
// device_id, and relay base URL.  Initialised once by `statsInit`.
//
// Thread safety: WASM is single-threaded; Mutex is here for the Send + Sync
// bounds required by InMemoryStatsSink, not for real concurrency.
//
// Cookie handling
// ───────────────
// The relay_auth cookie is HttpOnly + SameSite=Strict.  For same-origin
// browser requests reqwest's WASM fetch backend inherits the browser's
// cookie jar automatically (credentials: 'same-origin' is the default).
// The caller (TS StatsClient) acquires a fresh relay cookie (purpose="stats")
// before calling statsFlush; we do NOT consume JTI server-side for stats
// (intentional design — stats is a counter-only endpoint, replay is harmless).
//
// Relay bandwidth
// ───────────────
// SFTP bandwidth is accumulated in SftpRelayClient (per-session Arc<AtomicU64>)
// and exposed via SftpSessionWasm.relayBandwidthAndReset() in byo_sftp.rs.
// Share-relay bandwidth is measured directly in TypeScript (TS owns the fetch).
// Therefore no global bandwidth accumulator lives here.

use std::sync::{Mutex, OnceLock};

use wasm_bindgen::prelude::*;

use crate::provider_http::ReqwestProviderHttpClient;
use sdk_core::byo::stats::{InMemoryStatsSink, StatsEvent, StatsSink, StatsUploader};

// ─── State ───────────────────────────────────────────────────────────────────

/// Capacity of the in-memory event ring buffer.
/// Matches STATS_BATCH_MAX_EVENTS × 4 for comfortable buffering between flushes.
const SINK_CAP: usize = 800;

struct StatsState {
    sink: InMemoryStatsSink,
    device_id: String,
    base_url: String,
}

static STATE: OnceLock<Mutex<StatsState>> = OnceLock::new();

fn with_state<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut StatsState) -> R,
{
    STATE.get()?.lock().ok().map(|mut s| f(&mut s))
}

// ─── WASM bindings ────────────────────────────────────────────────────────────

/// Initialise the stats subsystem.
///
/// Must be called once from the BYO worker after the device UUID is confirmed.
/// Calling again after initialisation is a no-op (OnceLock guarantees
/// one-time initialisation).
///
/// `base_url`  — relay root, e.g. `"https://byo.example.com"`.
/// `device_id` — permanent lowercase UUIDv4 (never rotated per design decision).
#[wasm_bindgen(js_name = statsInit)]
pub fn stats_init(base_url: &str, device_id: &str) {
    let _ = STATE.get_or_init(|| {
        Mutex::new(StatsState {
            sink: InMemoryStatsSink::new(SINK_CAP),
            device_id: device_id.to_owned(),
            base_url: base_url.to_owned(),
        })
    });
}

/// Queue a single event.
///
/// `event_json` must be a JSON object matching the `StatsEvent` wire format
/// (i.e. it must have a `"kind"` field).  Unknown kinds are silently dropped
/// (forward-compatibility: new clients on old WASM builds).
///
/// This is synchronous and fire-and-forget — it never blocks.
#[wasm_bindgen(js_name = statsRecord)]
pub fn stats_record(event_json: &str) {
    let ev: StatsEvent = match serde_json::from_str(event_json) {
        Ok(e) => e,
        Err(_) => return, // unknown kind or malformed — drop silently
    };
    with_state(|s| s.sink.record(ev));
}

/// Return the current queue depth (number of pending events).
///
/// The TypeScript client uses this for early-flush decisions
/// (flush when depth ≥ FLUSH_EVENT_THRESHOLD).
#[wasm_bindgen(js_name = statsDrain)]
pub fn stats_drain() -> u32 {
    with_state(|s| s.sink.len() as u32).unwrap_or(0)
}

/// Drain the queue and POST up to 200 events to `/relay/stats`.
///
/// Returns a `Promise<void>`.  The caller (TS StatsClient) must:
///   1. Call `acquireRelayCookie("stats")` to ensure a valid relay auth cookie.
///   2. Call `statsFlush()`.
///
/// Errors are ignored at the JS boundary (stats are best-effort).
/// The relay auth cookie is automatically attached by the browser (same-origin
/// HttpOnly cookie); no explicit Cookie header is set.
#[wasm_bindgen(js_name = statsFlush)]
pub async fn stats_flush() -> Result<(), JsValue> {
    let (device_id, base_url, events) = match STATE.get() {
        None => return Ok(()), // not initialised
        Some(lock) => {
            let Ok(s) = lock.lock() else { return Ok(()) };
            let events = s.sink.drain(200);
            if events.is_empty() {
                return Ok(());
            }
            (s.device_id.clone(), s.base_url.clone(), events)
        }
    };

    let uploader = StatsUploader::new(ReqwestProviderHttpClient::new(), base_url);
    // Pass "" for relay_cookie: same-origin browser fetch auto-attaches the
    // HttpOnly relay_auth cookie.
    if let Err(_e) = uploader.flush_batch(&device_id, events, "").await {
        // Discard errors — stats are best-effort, never propagate to caller.
    }
    Ok(())
}
