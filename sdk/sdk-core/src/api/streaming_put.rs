// Streaming HTTP PUT client contract.
//
// This trait complements `ProviderHttpClient` for the one use-case that
// buffering can't serve: sending a multi-gigabyte WebDAV PUT without
// materialising the whole body in the WASM heap first.
//
// The shape mirrors the SFTP session pattern already used elsewhere in the
// SDK: an open/write/close/abort protocol keyed by a string handle. Each
// chunk crossing the WASM/JS boundary is the plaintext encryption output
// (V7_ENCRYPT_CHUNK_SIZE = 512 KiB) — small enough that call overhead is
// negligible, large enough that we don't chatter.
//
// Concrete implementations:
//   sdk-wasm (wasm32): web_sys ReadableStream + fetch({ duplex: 'half' })
//   sdk-ffi  (native): reqwest::Body::wrap_stream + mpsc channel
//
// sdk-core provides the trait only — all I/O belongs elsewhere.

use crate::api::ProviderHttpResponse;
use crate::byo::ProviderError;

/// Async streaming PUT contract.
///
/// Unlike `ProviderHttpClient::request`, the body is not materialised up
/// front: each `put_stream_write` appends to an in-flight request body.
/// `put_stream_close` awaits the full response and returns it verbatim;
/// callers (providers) extract ETag / status themselves.
///
/// `Send`-ness of the returned futures matches `ProviderHttpClient`: required
/// on native so UniFFI can await from a `Send` runtime, not required on WASM
/// (reqwest/fetch futures wrap JS promises and are `!Send`).
#[cfg(not(target_arch = "wasm32"))]
pub trait StreamingPutClient: Send + Sync {
    /// True when the runtime can actually perform a streaming PUT. Browsers
    /// that predate request-stream support (Safari < 17, etc.) return false
    /// and the caller falls back to buffer-and-forward.
    fn supports_streaming_put(&self) -> bool;

    /// Begin a PUT whose body will be streamed. `content_length`, when `Some`,
    /// is sent as a `Content-Length` header so the receiver can skip chunked
    /// transfer encoding (several WebDAV servers prefer this). The returned
    /// handle identifies the in-flight request for subsequent calls.
    fn put_stream_open(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        content_length: Option<u64>,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>> + Send;

    /// Append `chunk` to the in-flight request body. Non-blocking on the
    /// network layer — the chunk is enqueued into the body stream and
    /// backpressure is controlled by the caller's call cadence.
    fn put_stream_write(
        &self,
        handle: String,
        chunk: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> + Send;

    /// Close the body stream, await the full response, return it. On success
    /// the handle is invalidated.
    fn put_stream_close(
        &self,
        handle: String,
    ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send;

    /// Abort the in-flight request. Best-effort; the handle is invalidated
    /// even if the underlying abort call fails (caller is almost always on
    /// an error path already).
    fn put_stream_abort(
        &self,
        handle: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait StreamingPutClient: Send + Sync {
    fn supports_streaming_put(&self) -> bool;

    fn put_stream_open(
        &self,
        url: String,
        headers: Vec<(String, String)>,
        content_length: Option<u64>,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    fn put_stream_write(
        &self,
        handle: String,
        chunk: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn put_stream_close(
        &self,
        handle: String,
    ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>>;

    fn put_stream_abort(
        &self,
        handle: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;
}
