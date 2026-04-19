// WASM bindings for the SFTP relay protocol (P7).
//
// Architecture
// ────────────
// `WasmRelayTransport` bridges the browser WebSocket (managed in TypeScript) to
// the Rust `SftpRelayClient` state machine.
//
// TS → Rust (receive path):
//   TS calls `session.on_recv_text(text)` or `session.on_recv_binary(data)` when
//   the WebSocket fires `onmessage`.  These push frames into an internal buffer
//   and wake any pending `recv()` future.
//
// Rust → TS (send path):
//   `send_text` / `send_text_then_binary` call JS callback functions stored at
//   construction time.
//
// SAFETY
// ──────
// WASM is single-threaded; `Rc<RefCell<...>>` is safe without Send + Sync.
// `unsafe impl Send + Sync` is added on inner types so they can be stored inside
// `Arc<...>` (required by SftpRelayClient).  Correct because WASM never uses
// multiple threads.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::{Zeroize, Zeroizing};

use sdk_core::byo::provider::ProviderError;
use sdk_core::byo::sftp::client::SftpRelayClient;
use sdk_core::byo::sftp::transport::{RelayFrame, RelayTransport};

// ─── SFTP credential registry (WASM-heap storage) ──────────────────────────
//
// Holds SFTP passwords / private keys inside WASM memory. Callers store a
// credential and receive an opaque u32 handle; `auth_with_handle` consumes
// the handle to drive SSH auth without ever handing the credential back to
// JS. This replaces the older worker-postMessage pattern that routed raw
// credentials back to the main thread on every session.init().

enum SftpCred {
    Password(Zeroizing<String>),
    PublicKey {
        private_key: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

impl Drop for SftpCred {
    fn drop(&mut self) {
        // Every variant zeroizes its secrets. `Zeroizing<String>` does this
        // automatically on drop, so these explicit calls are defence-in-depth
        // for the day someone swaps the wrapper. C10: the `PublicKey` arm was
        // missing from the previous impl — if the field types ever change to
        // plain `String`, the gap would reappear silently.
        match self {
            SftpCred::Password(p) => p.zeroize(),
            SftpCred::PublicKey {
                private_key,
                passphrase,
            } => {
                private_key.zeroize();
                if let Some(pp) = passphrase {
                    pp.zeroize();
                }
            }
        }
    }
}

thread_local! {
    static SFTP_CREDS: RefCell<HashMap<u32, SftpCred>> = RefCell::new(HashMap::new());
    static SFTP_CRED_COUNTER: RefCell<u32> = const { RefCell::new(1) };
}

fn next_cred_handle() -> u32 {
    SFTP_CRED_COUNTER.with(|c| {
        let mut v = c.borrow_mut();
        let handle = *v;
        *v = v.wrapping_add(1).max(1); // wrap around 0
        handle
    })
}

/// Store an SFTP password inside WASM memory and return an opaque handle.
/// The plaintext password is zeroized on drop when the handle is cleared or
/// when `sftp_clear_all_credentials()` is called.
#[wasm_bindgen]
pub fn sftp_store_credential_password(password: String) -> u32 {
    let handle = next_cred_handle();
    SFTP_CREDS.with(|m| {
        m.borrow_mut()
            .insert(handle, SftpCred::Password(Zeroizing::new(password)));
    });
    handle
}

/// Store an SFTP SSH private key (optionally with a passphrase) inside WASM
/// memory. The PEM text and passphrase are zeroized on drop.
#[wasm_bindgen]
pub fn sftp_store_credential_publickey(
    private_key: String,
    passphrase: Option<String>,
) -> u32 {
    let handle = next_cred_handle();
    SFTP_CREDS.with(|m| {
        m.borrow_mut().insert(
            handle,
            SftpCred::PublicKey {
                private_key: Zeroizing::new(private_key),
                passphrase: passphrase.map(Zeroizing::new),
            },
        );
    });
    handle
}

/// Remove a specific credential from the registry.
#[wasm_bindgen]
pub fn sftp_clear_credential(handle: u32) {
    SFTP_CREDS.with(|m| {
        m.borrow_mut().remove(&handle);
    });
}

/// Remove every credential from the registry (e.g. on vault lock).
#[wasm_bindgen]
pub fn sftp_clear_all_credentials() {
    SFTP_CREDS.with(|m| m.borrow_mut().clear());
}

/// Owned copy of a stored credential, lifted out of the registry so the
/// caller can await async SSH auth without holding the `RefCell` borrow.
enum ExtractedCred {
    Password(Zeroizing<String>),
    PublicKey {
        private_key: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

fn lookup_sftp_cred(handle: u32) -> Result<ExtractedCred, &'static str> {
    SFTP_CREDS.with(|m| {
        let m = m.borrow();
        match m.get(&handle) {
            Some(SftpCred::Password(p)) => {
                Ok(ExtractedCred::Password(Zeroizing::new((**p).clone())))
            }
            Some(SftpCred::PublicKey { private_key, passphrase }) => {
                Ok(ExtractedCred::PublicKey {
                    private_key: Zeroizing::new((**private_key).clone()),
                    passphrase: passphrase
                        .as_ref()
                        .map(|p| Zeroizing::new((**p).clone())),
                })
            }
            None => Err("unknown SFTP credential handle"),
        }
    })
}

// ─── WasmRelayTransport internals ────────────────────────────────────────────

struct WasmTransportState {
    recv_queue: VecDeque<RelayFrame>,
    waker: Option<Waker>,
    closed: bool,
}

/// WASM-side relay transport.
///
/// `state` is shared via `Rc<RefCell<>>` between the transport and any pending
/// `RecvFuture`s, ensuring the state buffer outlives futures even if the
/// transport is dropped while a recv is in progress.
pub struct WasmRelayTransport {
    state: Rc<RefCell<WasmTransportState>>,
    send_text_fn: Function,
    send_text_binary_fn: Function,
    close_fn: Function,
}

// SAFETY: WASM is single-threaded. Rc<RefCell<>> is not Send/Sync by itself,
// but no real concurrency exists in WASM so this is sound.
unsafe impl Send for WasmRelayTransport {}
unsafe impl Sync for WasmRelayTransport {}

impl WasmRelayTransport {
    fn new(
        send_text_fn: Function,
        send_text_binary_fn: Function,
        close_fn: Function,
    ) -> Self {
        Self {
            state: Rc::new(RefCell::new(WasmTransportState {
                recv_queue: VecDeque::new(),
                waker: None,
                closed: false,
            })),
            send_text_fn,
            send_text_binary_fn,
            close_fn,
        }
    }

    pub fn push_text_frame(&self, text: String) {
        let mut s = self.state.borrow_mut();
        s.recv_queue.push_back(RelayFrame::Text(text));
        if let Some(w) = s.waker.take() { w.wake(); }
    }

    pub fn push_binary_frame(&self, data: Vec<u8>) {
        let mut s = self.state.borrow_mut();
        s.recv_queue.push_back(RelayFrame::Binary(data));
        if let Some(w) = s.waker.take() { w.wake(); }
    }

    pub fn push_close_signal(&self) {
        let mut s = self.state.borrow_mut();
        s.closed = true;
        if let Some(w) = s.waker.take() { w.wake(); }
    }
}

// ── RecvFuture ────────────────────────────────────────────────────────────────

struct RecvFuture {
    /// Rc clone keeps the state buffer alive for the lifetime of the future,
    /// even if the WasmRelayTransport is dropped before the future resolves.
    state: Rc<RefCell<WasmTransportState>>,
}

// SAFETY: WASM is single-threaded; no actual concurrent access occurs.
unsafe impl Send for RecvFuture {}
unsafe impl Sync for RecvFuture {}

impl Future for RecvFuture {
    type Output = Result<RelayFrame, ProviderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.state.borrow_mut();
        if let Some(frame) = s.recv_queue.pop_front() {
            Poll::Ready(Ok(frame))
        } else if s.closed {
            Poll::Ready(Ok(RelayFrame::Closed))
        } else {
            s.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// ── RelayTransport impl ───────────────────────────────────────────────────────

impl RelayTransport for WasmRelayTransport {
    fn send_text(&self, s: &str) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let r = self.send_text_fn.call1(&JsValue::NULL, &JsValue::from_str(s));
        async move { r.map_err(|e| ProviderError::SftpRelay(format!("{e:?}"))).map(|_| ()) }
    }

    fn send_text_then_binary(
        &self,
        text_hdr: &str,
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let arr = Uint8Array::from(body);
        let r = self.send_text_binary_fn.call2(&JsValue::NULL, &JsValue::from_str(text_hdr), &arr);
        async move { r.map_err(|e| ProviderError::SftpRelay(format!("{e:?}"))).map(|_| ()) }
    }

    fn recv(&self) -> impl std::future::Future<Output = Result<RelayFrame, ProviderError>> {
        RecvFuture { state: Rc::clone(&self.state) }
    }

    fn close(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        let r = self.close_fn.call0(&JsValue::NULL);
        async move { r.map_err(|e| ProviderError::SftpRelay(format!("{e:?}"))).map(|_| ()) }
    }
}

// ─── SftpSessionWasm ─────────────────────────────────────────────────────────

/// WASM-exposed SFTP session.
///
/// TypeScript usage:
/// ```ts
/// const session = new SftpSessionWasm(
///   (text: string) => ws.send(text),
///   (text: string, bin: Uint8Array) => { ws.send(text); ws.send(bin); },
///   () => ws.close(),
/// );
/// ws.onmessage = (e) => {
///   if (typeof e.data === 'string') session.on_recv_text(e.data);
///   else session.on_recv_binary(new Uint8Array(e.data));
/// };
/// ws.onclose = () => session.on_close();
///
/// await session.handshake(fp => confirm(`Trust ${fp}?`));
/// await session.auth_password('user', 'pass');
/// ```
#[wasm_bindgen]
pub struct SftpSessionWasm {
    transport: Rc<WasmRelayTransport>,
    // Rc so we can clone into async blocks without lifetime issues.
    client: Rc<SftpRelayClient<WasmRelayTransportRef>>,
}

/// Newtype around `*const WasmRelayTransport` so we can implement `RelayTransport`
/// and store it inside `SftpRelayClient` (which wraps T in Arc<T>).
///
/// The pointer is valid for the entire lifetime of `SftpSessionWasm` because
/// `transport` (Rc<WasmRelayTransport>) keeps the transport alive.
struct WasmRelayTransportRef(*const WasmRelayTransport);

// SAFETY: WASM single-threaded; pointer is valid for session lifetime.
unsafe impl Send for WasmRelayTransportRef {}
unsafe impl Sync for WasmRelayTransportRef {}

impl RelayTransport for WasmRelayTransportRef {
    fn send_text(&self, s: &str) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        unsafe { &*self.0 }.send_text(s)
    }

    fn send_text_then_binary(
        &self,
        text_hdr: &str,
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        unsafe { &*self.0 }.send_text_then_binary(text_hdr, body)
    }

    fn recv(&self) -> impl std::future::Future<Output = Result<RelayFrame, ProviderError>> {
        unsafe { &*self.0 }.recv()
    }

    fn close(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
        unsafe { &*self.0 }.close()
    }
}

#[wasm_bindgen]
impl SftpSessionWasm {
    /// Construct a new session.
    ///
    /// - `send_text_fn`: `(text: string) => void`
    /// - `send_text_binary_fn`: `(text: string, binary: Uint8Array) => void`
    /// - `close_fn`: `() => void`
    #[wasm_bindgen(constructor)]
    pub fn new(
        send_text_fn: Function,
        send_text_binary_fn: Function,
        close_fn: Function,
    ) -> SftpSessionWasm {
        let transport = Rc::new(WasmRelayTransport::new(
            send_text_fn,
            send_text_binary_fn,
            close_fn,
        ));
        let transport_ref = WasmRelayTransportRef(Rc::as_ptr(&transport));
        let client = Rc::new(SftpRelayClient::new(transport_ref));
        SftpSessionWasm { transport, client }
    }

    /// Called from TS WebSocket.onmessage when a text frame arrives.
    pub fn on_recv_text(&self, text: String) {
        self.transport.push_text_frame(text);
    }

    /// Called from TS WebSocket.onmessage when a binary frame arrives.
    pub fn on_recv_binary(&self, data: Uint8Array) {
        self.transport.push_binary_frame(data.to_vec());
    }

    /// Called from TS WebSocket.onclose.
    pub fn on_close(&self) {
        self.transport.push_close_signal();
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    /// Perform the relay handshake (reads host_key frame, verifies TOFU, sends accepted).
    ///
    /// `on_first_host_key_fn`: `(fingerprint: string) => Promise<boolean>`
    ///   Return `true` to trust, `false` to reject.  Not called on known fingerprints.
    ///
    /// Resolves with the relay protocol version (1 or 2+).
    pub fn handshake(&self, on_first_host_key_fn: Function) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let version = client
                .handshake(|fp| {
                    let cb = on_first_host_key_fn.clone();
                    async move {
                        let result = cb.call1(&JsValue::NULL, &JsValue::from_str(&fp))
                            .unwrap_or(JsValue::FALSE);
                        let promise = js_sys::Promise::from(result);
                        match wasm_bindgen_futures::JsFuture::from(promise).await {
                            Ok(v) => v.as_bool().unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                })
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_f64(version as f64))
        })
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    pub fn auth_password(&self, username: String, password: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.auth_password(&username, &password).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn auth_publickey(
        &self,
        username: String,
        private_key: String,
        passphrase: Option<String>,
    ) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.auth_publickey(&username, &private_key, passphrase.as_deref()).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Authenticate using a credential previously stored via
    /// [`sftp_store_credential_password`] or
    /// [`sftp_store_credential_publickey`].
    ///
    /// The credential never leaves the WASM heap; only the opaque `handle`
    /// crosses the JS boundary. On success the stored credential is left in
    /// place so auto-reconnect can reuse it; call [`sftp_clear_credential`]
    /// explicitly when the caller no longer needs it.
    pub fn auth_with_handle(&self, username: String, handle: u32) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        let extracted = lookup_sftp_cred(handle);
        future_to_promise(async move {
            let cred = match extracted {
                Ok(c) => c,
                Err(e) => return Err(JsValue::from_str(e)),
            };
            match cred {
                ExtractedCred::Password(password) => {
                    client
                        .auth_password(&username, &password)
                        .await
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                }
                ExtractedCred::PublicKey { private_key, passphrase } => {
                    client
                        .auth_publickey(
                            &username,
                            &private_key,
                            passphrase.as_ref().map(|p| p.as_str()),
                        )
                        .await
                        .map_err(|e| JsValue::from_str(&e.to_string()))?;
                }
            }
            Ok(JsValue::UNDEFINED)
        })
    }

    // ── Filesystem verbs ──────────────────────────────────────────────────────

    /// Returns JSON: `{ "mtime": number, "size": number, "isDir": boolean }`
    pub fn stat(&self, path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let (mtime, size, is_dir) = client.stat(&path).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&serde_json::json!({"mtime":mtime,"size":size,"isDir":is_dir}).to_string()))
        })
    }

    /// Returns JSON array of `StorageEntry`.
    pub fn list(&self, path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let entries = client.list(&path).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&serde_json::to_string(&entries)
                .map_err(|e| JsValue::from_str(&e.to_string()))?))
        })
    }

    pub fn mkdir(&self, path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.mkdir(&path).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn delete_file(&self, path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.delete_file(&path).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    pub fn rename_path(&self, old_path: String, new_path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.rename(&old_path, &new_path).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Read a file; resolves with `Uint8Array`.
    pub fn read_file(&self, path: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let data = client.read(&path).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(Uint8Array::from(data.as_slice()).into())
        })
    }

    /// Single-shot write (v1 `write` verb, two-frame protocol).
    pub fn write_file(&self, path: String, data: Uint8Array) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        let data = data.to_vec();
        future_to_promise(async move {
            client.write(&path, &data).await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    // ── Streaming upload ──────────────────────────────────────────────────────

    /// Open a streaming upload. Returns opaque `stream_id` string.
    pub fn upload_open(&self, name: String, total_size: f64) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let id = client.upload_open(&name, total_size as u64).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&id))
        })
    }

    /// Write a chunk for a v2 streaming upload.
    pub fn upload_write_chunk(&self, stream_id: String, chunk: Uint8Array) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        let chunk = chunk.to_vec();
        future_to_promise(async move {
            client.upload_write_chunk(&stream_id, &chunk).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Close a v2 streaming upload. Returns JSON `{ ref: string, version: string }`.
    pub fn upload_close_v2(&self, stream_id: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            let r = client.upload_close_v2(&stream_id).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&serde_json::to_string(&r).map_err(|e| JsValue::from_str(&e.to_string()))?))
        })
    }

    /// Close a v1 upload (provide full buffered data). Returns JSON `{ ref, version }`.
    pub fn upload_close_v1(&self, stream_id: String, data: Uint8Array) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        let data = data.to_vec();
        future_to_promise(async move {
            let r = client.upload_close_v1(&stream_id, &data).await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::from_str(&serde_json::to_string(&r).map_err(|e| JsValue::from_str(&e.to_string()))?))
        })
    }

    /// Abort a v2 streaming upload (best-effort).
    pub fn upload_abort_v2(&self, stream_id: String) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.upload_abort_v2(&stream_id).await;
            Ok(JsValue::UNDEFINED)
        })
    }

    // ── Lifecycle helpers ─────────────────────────────────────────────────────

    pub fn ensure_root_folders(&self) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.ensure_root_folders().await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Stored TOFU fingerprint (empty string if not yet connected).
    pub fn stored_fingerprint(&self) -> String {
        self.client.stored_fingerprint().unwrap_or_default()
    }

    /// Relay protocol version (set after handshake; 0 before).
    pub fn relay_version(&self) -> u32 {
        self.client.relay_version()
    }

    pub fn disconnect(&self) -> js_sys::Promise {
        let client = Rc::clone(&self.client);
        future_to_promise(async move {
            client.disconnect().await.map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Read and atomically reset the SFTP relay bandwidth counters for this session.
    ///
    /// Returns `{ sent: number, recv: number }` where both values are
    /// cumulative ciphertext bytes since the last call (or since session start).
    ///
    /// Call this after each upload / download to emit a `relay_bandwidth_sftp`
    /// stats event from the TypeScript stats client.
    pub fn relay_bandwidth_and_reset(&self) -> JsValue {
        let (sent, recv) = self.client.relay_bandwidth_and_reset();
        let obj = js_sys::Object::new();
        // Use f64 to avoid u64 precision loss in JS; values will never exceed 2^53.
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("sent"), &JsValue::from_f64(sent as f64));
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("recv"), &JsValue::from_f64(recv as f64));
        obj.into()
    }
}
