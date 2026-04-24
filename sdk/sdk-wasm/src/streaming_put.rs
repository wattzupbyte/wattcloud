// StreamingPutClient implementation for WASM.
//
// Uses the browser Streams API to feed chunks into `fetch()` as a
// `ReadableStream` body with `duplex: 'half'`. Avoids materialising the
// ciphertext in the WASM heap — each chunk crosses the WASM/JS boundary
// and lands straight in the ReadableStream queue.
//
// State model mirrors the SFTP session pattern used elsewhere in the SDK:
// a `thread_local` map keyed by string handle, one entry per in-flight PUT.
//
// Browser support is feature-detected once per process via the same recipe
// `shareUploadStreaming.ts` uses (probe `duplex` getter + Content-Type
// inference). Caching is mandatory — every capability probe allocates a
// ReadableStream, and we don't want to leak one per `supports_streaming_put`
// call.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use js_sys::{Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    AbortController, Headers, ReadableStream, ReadableStreamDefaultController, Request,
    RequestInit, Response,
};

use sdk_core::api::{ProviderHttpResponse, StreamingPutClient};
use sdk_core::byo::ProviderError;

use crate::provider_http::ReqwestProviderHttpClient;

// ─── Session state ────────────────────────────────────────────────────────────

struct StreamSession {
    controller: ReadableStreamDefaultController,
    response_promise: Promise,
    abort_controller: AbortController,
    // Keep the start closure alive for the lifetime of the stream — dropping
    // it would null out the callback reference on the JS side.
    _start_closure: Closure<dyn FnMut(ReadableStreamDefaultController)>,
}

thread_local! {
    static SESSIONS: RefCell<HashMap<String, StreamSession>> = RefCell::new(HashMap::new());
    static SUPPORT_CACHE: RefCell<Option<bool>> = const { RefCell::new(None) };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn js_err(prefix: &str, e: JsValue) -> ProviderError {
    let msg = e
        .as_string()
        .or_else(|| {
            // Try .toString() for Error objects.
            js_sys::Reflect::get(&e, &JsValue::from_str("message"))
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| format!("{e:?}"));
    ProviderError::Network(format!("{prefix}: {msg}"))
}

fn session_id() -> String {
    // Same construction as byo_streaming: 16 bytes of CSPRNG → 32-char hex.
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "csprng-unavailable".to_string();
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Feature-test for `fetch(..., { body: ReadableStream, duplex: 'half' })`.
/// Equivalent to the JS `supportsRequestStreams()` helper in
/// `frontend/src/lib/byo/shareUploadStreaming.ts`.
fn detect_streaming_support() -> bool {
    // Spec-compliant browsers READ the `duplex` getter when streaming is on;
    // older browsers also auto-infer a Content-Type from the body, which we
    // use as a negative signal.
    let Ok(stream) = ReadableStream::new() else {
        return false;
    };

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&stream);

    let duplex_accessed = Rc::new(RefCell::new(false));
    let duplex_accessed_clone = Rc::clone(&duplex_accessed);
    let getter = Closure::wrap(Box::new(move || {
        *duplex_accessed_clone.borrow_mut() = true;
        JsValue::from_str("half")
    }) as Box<dyn FnMut() -> JsValue>);
    let desc = Object::new();
    if Reflect::set(
        &desc,
        &JsValue::from_str("get"),
        getter.as_ref().unchecked_ref(),
    )
    .is_err()
    {
        return false;
    }
    if Reflect::set(&desc, &JsValue::from_str("enumerable"), &JsValue::TRUE).is_err() {
        return false;
    }
    if Object::define_property(&init, &JsValue::from_str("duplex"), &desc).is_undefined() {
        // defineProperty returned undefined (shouldn't happen per spec).
    }

    let Ok(req) = Request::new_with_str_and_init("https://example.invalid/", &init) else {
        return false;
    };
    let headers = req.headers();
    let has_content_type = headers
        .has("Content-Type")
        .or_else(|_| headers.has("content-type"))
        .unwrap_or(false);
    *duplex_accessed.borrow() && !has_content_type
}

// ─── StreamingPutClient impl ──────────────────────────────────────────────────

impl StreamingPutClient for ReqwestProviderHttpClient {
    fn supports_streaming_put(&self) -> bool {
        SUPPORT_CACHE.with(|cache| {
            if let Some(v) = *cache.borrow() {
                return v;
            }
            let supported = detect_streaming_support();
            *cache.borrow_mut() = Some(supported);
            supported
        })
    }

    async fn put_stream_open(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        content_length: Option<u64>,
    ) -> Result<String, ProviderError> {
        // 1. Build ReadableStream that captures its controller.
        let captured: Rc<RefCell<Option<ReadableStreamDefaultController>>> =
            Rc::new(RefCell::new(None));
        let captured_clone = Rc::clone(&captured);
        let start_closure = Closure::wrap(Box::new(move |c: ReadableStreamDefaultController| {
            *captured_clone.borrow_mut() = Some(c);
        })
            as Box<dyn FnMut(ReadableStreamDefaultController)>);
        let source = Object::new();
        Reflect::set(
            &source,
            &JsValue::from_str("start"),
            start_closure.as_ref().unchecked_ref(),
        )
        .map_err(|e| js_err("source.start", e))?;

        let stream = ReadableStream::new_with_underlying_source(&source)
            .map_err(|e| js_err("ReadableStream::new", e))?;

        let controller = captured
            .borrow_mut()
            .take()
            .ok_or_else(|| ProviderError::Network("ReadableStream start() never ran".into()))?;

        // 2. Build the fetch request: PUT url, body=stream, duplex=half.
        let headers_obj = Headers::new().map_err(|e| js_err("Headers::new", e))?;
        for (k, v) in &headers {
            headers_obj
                .append(k, v)
                .map_err(|e| js_err("headers.append", e))?;
        }
        if let Some(cl) = content_length {
            // Append rather than set so the caller can override via headers
            // (unlikely, but keeps the API predictable).
            let _ = headers_obj.append("Content-Length", &cl.to_string());
        }
        let init = RequestInit::new();
        init.set_method("PUT");
        init.set_headers(&headers_obj);
        init.set_body(&stream);
        // `duplex: 'half'` is a newer RequestInit field not in every
        // web-sys version; set via Reflect so we're not tied to the
        // shipped type.
        Reflect::set(
            &init,
            &JsValue::from_str("duplex"),
            &JsValue::from_str("half"),
        )
        .map_err(|e| js_err("init.duplex", e))?;

        let abort_controller =
            AbortController::new().map_err(|e| js_err("AbortController::new", e))?;
        init.set_signal(Some(&abort_controller.signal()));

        let window = web_sys::window().ok_or_else(|| ProviderError::Network("no window".into()))?;
        let request =
            Request::new_with_str_and_init(&url, &init).map_err(|e| js_err("Request::new", e))?;
        let response_promise = window.fetch_with_request(&request);

        // 3. Store session.
        let handle = session_id();
        SESSIONS.with(|m| {
            m.borrow_mut().insert(
                handle.clone(),
                StreamSession {
                    controller,
                    response_promise,
                    abort_controller,
                    _start_closure: start_closure,
                },
            );
        });
        Ok(handle)
    }

    async fn put_stream_write(&self, handle: String, chunk: Vec<u8>) -> Result<(), ProviderError> {
        // Copy into a Uint8Array — needs to live on the JS heap.
        let view = Uint8Array::new_with_length(chunk.len() as u32);
        view.copy_from(&chunk);
        SESSIONS.with(|m| {
            let map = m.borrow();
            let s = map.get(&handle).ok_or_else(|| {
                ProviderError::Provider(format!("unknown stream handle: {handle}"))
            })?;
            s.controller
                .enqueue_with_chunk(&view)
                .map_err(|e| js_err("controller.enqueue", e))
        })
    }

    async fn put_stream_close(
        &self,
        handle: String,
    ) -> Result<ProviderHttpResponse, ProviderError> {
        // Evict the session upfront so the controller/promise can be
        // dropped on any error path.
        let session = SESSIONS
            .with(|m| m.borrow_mut().remove(&handle))
            .ok_or_else(|| ProviderError::Provider(format!("unknown stream handle: {handle}")))?;

        session
            .controller
            .close()
            .map_err(|e| js_err("controller.close", e))?;

        let resp_js = JsFuture::from(session.response_promise)
            .await
            .map_err(|e| js_err("fetch", e))?;
        let response: Response = resp_js
            .dyn_into()
            .map_err(|_| ProviderError::Network("fetch returned non-Response".into()))?;

        let status = response.status();
        let headers = collect_headers(&response);

        let body_buf_promise = response
            .array_buffer()
            .map_err(|e| js_err("Response::array_buffer", e))?;
        let buf_js = JsFuture::from(body_buf_promise)
            .await
            .map_err(|e| js_err("response body", e))?;
        let buf: js_sys::ArrayBuffer = buf_js
            .dyn_into()
            .map_err(|_| ProviderError::Network("body is not ArrayBuffer".into()))?;
        let view = Uint8Array::new(&buf);
        let body = view.to_vec();

        Ok(ProviderHttpResponse {
            status,
            headers,
            body,
        })
    }

    async fn put_stream_abort(&self, handle: String) -> Result<(), ProviderError> {
        let session = SESSIONS.with(|m| m.borrow_mut().remove(&handle));
        if let Some(s) = session {
            s.abort_controller.abort();
            // Best-effort close on the controller too — the AbortController
            // tears down the fetch; the ReadableStream controller reports
            // that the consumer (the fetch body) has cancelled.
            let _ = s.controller.close();
        }
        Ok(())
    }
}

fn collect_headers(response: &Response) -> Vec<(String, String)> {
    let headers = response.headers();
    let mut out: Vec<(String, String)> = Vec::new();
    // The Headers iterator is a JS iterator of [name, value] pairs. Use
    // js_sys::try_iter to walk it; a pattern match extracts the pair.
    let iter = match js_sys::try_iter(&headers) {
        Ok(Some(it)) => it,
        _ => return out,
    };
    for entry in iter.flatten() {
        let arr: js_sys::Array = match entry.dyn_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let k = arr.get(0).as_string().unwrap_or_default();
        let v = arr.get(1).as_string().unwrap_or_default();
        if !k.is_empty() {
            out.push((k, v));
        }
    }
    out
}
