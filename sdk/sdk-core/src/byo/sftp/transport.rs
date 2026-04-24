// RelayFrame + RelayTransport trait.
//
// RelayTransport abstracts the WebSocket connection to the SFTP relay so that
// the entire protocol state machine (SftpRelayClient) can live in sdk-core and
// be shared by the browser (WasmRelayTransport in sdk-wasm) and Android
// (OkHttpRelayTransport via UniFFI callback interface).
//
// SEND+SYNC NOTES
// ───────────────
// The trait requires Send + Sync so that SftpProvider<T: RelayTransport> can
// implement StorageProvider (which is Send + Sync).  Browser implementations
// use `Rc<RefCell<...>>` internally (WASM is single-threaded) and declare
// `unsafe impl Send + Sync` — safe because WASM has no concurrency.
// Android implementations naturally satisfy the bounds via OkHttp's thread safety.

use crate::byo::ProviderError;

/// A frame received from the relay WebSocket.
#[derive(Debug)]
pub enum RelayFrame {
    /// UTF-8 text frame (JSON-encoded control messages).
    Text(String),
    /// Raw binary frame (file data following a two-frame read response).
    Binary(Vec<u8>),
    /// The connection was closed cleanly.
    Closed,
}

/// Abstraction over a relay WebSocket connection.
///
/// Implementations:
///   - Tests   : `MockRelayTransport` in `sdk-core/src/byo/sftp/client.rs`
///   - Browser : `WasmRelayTransport` in `sdk-wasm/src/byo_sftp.rs`
///   - Android : Kotlin `OkHttpRelayTransport` (UniFFI callback interface, P8+)
///
/// The relay protocol uses two-frame binary writes:
///   Text frame 1: JSON `{ id, method, params }` header
///   Binary frame: raw payload (ciphertext)
/// and two-frame binary reads:
///   Relay sends JSON `{ id, result: { size } }` then a binary frame.
pub trait RelayTransport: Send + Sync {
    /// Send a single UTF-8 text frame (JSON control message).
    fn send_text(&self, s: &str) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    /// Send the two-frame binary write protocol:
    ///   Frame 1: `text_hdr` as a UTF-8 text frame (JSON `{ id, method, params }`)
    ///   Frame 2: `body` as a raw binary frame
    ///
    /// Implementations MUST send both frames before returning.  The relay
    /// reads them atomically — a partial send would corrupt the session.
    fn send_text_then_binary(
        &self,
        text_hdr: &str,
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    /// Receive the next frame. Blocks until a frame (Text, Binary, or Closed) arrives.
    ///
    /// `Closed` is returned once on a clean close; subsequent calls may return
    /// `ProviderError::SftpRelay("connection closed")`.
    fn recv(&self) -> impl std::future::Future<Output = Result<RelayFrame, ProviderError>>;

    /// Close the connection gracefully.
    fn close(&self) -> impl std::future::Future<Output = Result<(), ProviderError>>;
}
