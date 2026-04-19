// BYO SFTP relay protocol — sdk-core implementation.
//
// This module contains the entire SFTP relay protocol state machine so that
// Android (sdk-ffi/UniFFI) and browser (sdk-wasm) share identical logic.
//
// Platform responsibilities:
//   - WebSocket lifecycle (open/onmessage/send/close): stays in each platform.
//   - Cookie acquisition: thin TS/Kotlin wrapper around relay_auth.rs.
//   - `onFirstHostKey` UI callback: platform-specific (browser dialog / Android dialog).
//
// Module layout:
//   transport  — RelayFrame + RelayTransport trait (platform contract).
//   client     — SftpRelayClient<T: RelayTransport> (complete protocol).

pub mod client;
pub mod transport;

pub use client::{SftpProvider, SftpRelayClient, UPLOAD_CHUNK_SIZE};
pub use transport::{RelayFrame, RelayTransport};
