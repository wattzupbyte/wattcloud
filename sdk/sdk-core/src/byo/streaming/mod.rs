// BYO streaming module: V7 upload/download state machines + chunk buffering.
//
// All types are platform-agnostic: pure algorithms over `&[u8]`, no I/O.
// Platform layers (WASM WritableStream, Android OutputStream) drive these
// state machines and own all network/disk operations.

pub mod chunk_writer;
pub mod constants;
pub mod download_flow;
pub mod upload_flow;

pub use chunk_writer::ChunkWriter;
pub use download_flow::ByoDownloadFlow;
pub use upload_flow::ByoUploadFlow;
