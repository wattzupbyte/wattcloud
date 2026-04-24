// SftpRelayClient — complete SFTP relay protocol state machine.
//
// Implements all verbs (auth / stat / list / mkdir / delete / rename / read /
// write / write_open / write_chunk / write_close / write_abort) plus the
// host_key handshake, TOFU fingerprint verification, relay_version negotiation,
// and the v2 streaming upload / download state machine.
//
// CONCURRENCY MODEL
// ─────────────────
// The client is *sequential*: only one request is in-flight at a time.
// Application-level callers (StorageProvider impl, tests) must not call
// multiple methods concurrently on the same SftpRelayClient instance.
// This is enforced by wrapping mutable state in Mutex and holding it only
// briefly around counter increments — actual await points hold no lock.
//
// DESIGN NOTE: the TS SftpProvider used a map of pending requests, giving the
// illusion of concurrency.  In practice all uploads/downloads are sequential;
// removing the concurrency complexity simplifies the state machine considerably.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::byo::provider::{ProviderError, StorageEntry, UploadResult};
use crate::byo::sftp::transport::{RelayFrame, RelayTransport};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Folder name used for the vault root on the SFTP server (relative to the
/// optional per-session `base_path`).  Combined with `base_path` in
/// [`SftpRelayClient::vault_root_path`] to form the full root like
/// `/wattcloud/WattcloudVault`.
const VAULT_ROOT_NAME: &str = "/WattcloudVault";
/// Chunk size for v2 streaming uploads. Must be ≤ relay server's 16 MB WS frame
/// limit and ≤ its 200 MiB per-session buffer.
///
/// B3: SPEC-BYO §Relay Protocol v2 + CLAUDE.md specify 8 MiB chunks. The prior
/// 4 MiB value doubled the number of write_chunk round-trips per upload for no
/// protocol benefit.
pub const UPLOAD_CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

// ─── Wire types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest<P: Serialize> {
    id: u32,
    method: &'static str,
    params: P,
}

#[derive(Deserialize)]
struct RpcResponse {
    id: u32,
    result: Option<Value>,
    error: Option<String>,
}

// ─── Internal state ───────────────────────────────────────────────────────────

#[derive(Default)]
struct SftpState {
    /// Monotonically increasing request ID counter.
    request_counter: u32,
    /// Relay protocol version extracted from the `host_key` handshake frame.
    /// v1 = legacy single-shot `write`; v2+ = streaming write_open/chunk/close.
    relay_version: u32,
    /// TOFU host key fingerprint persisted per provider.
    /// `None` = first connection (user must confirm).
    /// `Some(fp)` = subsequent connections (auto-verified).
    stored_fingerprint: Option<String>,
    /// mtime:size strings keyed by remote path — used for conflict detection.
    file_versions: HashMap<String, String>,
    /// Whether the handshake + auth has completed.
    ready: bool,
}

// ─── SftpRelayClient ─────────────────────────────────────────────────────────

/// Protocol state machine for the SFTP relay WebSocket connection.
///
/// Generic over any `RelayTransport` implementation (browser WS, Android OkHttp,
/// or `MockRelayTransport` in tests).
pub struct SftpRelayClient<T: RelayTransport> {
    transport: Arc<T>,
    state: Arc<Mutex<SftpState>>,
    /// Optional base directory prepended to the vault root.  Empty for the
    /// default (vault lives at the SFTP session root), otherwise something
    /// like `"/wattcloud"` — combined with [`VAULT_ROOT_NAME`] to get the
    /// full root path.  Immutable after construction.
    base_path: String,
    /// Cumulative ciphertext bytes sent to the relay (upload bandwidth).
    pub bytes_sent: Arc<AtomicU64>,
    /// Cumulative ciphertext bytes received from the relay (download bandwidth).
    pub bytes_recv: Arc<AtomicU64>,
}

impl<T: RelayTransport> SftpRelayClient<T> {
    /// Create a new client wrapping the given transport.
    /// The transport MUST already be connected (WS open) before calling this.
    ///
    /// `base_path` is a server-absolute prefix applied to the vault root so
    /// the vault can live in a subdirectory (e.g. `"/wattcloud"` → vault at
    /// `/wattcloud/WattcloudVault`).  Pass `""` for no prefix.  Leading
    /// slash is normalized; trailing slashes stripped.
    pub fn new(transport: T, base_path: String) -> Self {
        Self {
            transport: Arc::new(transport),
            state: Arc::new(Mutex::new(SftpState::default())),
            base_path: normalize_base_path(&base_path),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Full absolute path to the vault root on the SFTP server.  Equals
    /// `{base_path}{VAULT_ROOT_NAME}` — e.g. `/WattcloudVault` when no base
    /// path is configured, or `/wattcloud/WattcloudVault` when it is.
    fn vault_root_path(&self) -> String {
        format!("{}{VAULT_ROOT_NAME}", self.base_path)
    }

    /// Read and atomically reset the relay bandwidth counters.
    ///
    /// Returns `(bytes_sent, bytes_recv)`.  Both counters are reset to 0 after
    /// the read so the next call returns only the delta since this call.
    /// Called by the WASM layer at vault-lock time to emit `relay_bandwidth_sftp`.
    pub fn relay_bandwidth_and_reset(&self) -> (u64, u64) {
        let sent = self.bytes_sent.swap(0, Ordering::AcqRel);
        let recv = self.bytes_recv.swap(0, Ordering::AcqRel);
        (sent, recv)
    }

    /// Return a clone of the stored TOFU fingerprint (if any).
    pub fn stored_fingerprint(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.stored_fingerprint.clone())
    }

    /// Inject a previously-persisted TOFU fingerprint so the next
    /// [`handshake`] skips the first-connection callback and instead verifies
    /// the server's live fingerprint against it. Callers pass the value they
    /// previously read out of [`stored_fingerprint`] (round-tripped through
    /// the persisted `ProviderConfig.sftp_host_key_fingerprint`).
    pub fn set_stored_fingerprint(&self, fingerprint: String) -> Result<(), ProviderError> {
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .stored_fingerprint = Some(fingerprint);
        Ok(())
    }

    /// Return the relay protocol version (set after handshake).
    pub fn relay_version(&self) -> u32 {
        self.state.lock().ok().map(|s| s.relay_version).unwrap_or(1)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn next_id(&self) -> Result<u32, ProviderError> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?;
        s.request_counter = s.request_counter.wrapping_add(1);
        Ok(s.request_counter)
    }

    /// Read text frames until we get one whose `id` matches `expected_id`.
    /// Returns the `result` field of the matching frame.
    async fn recv_response(&self, expected_id: u32) -> Result<Value, ProviderError> {
        loop {
            match self.transport.recv().await? {
                RelayFrame::Text(text) => {
                    let resp: RpcResponse = serde_json::from_str(&text).map_err(|_| {
                        ProviderError::Provider(format!(
                            "malformed JSON: {}",
                            &text[..text.len().min(100)]
                        ))
                    })?;
                    if resp.id != expected_id {
                        // Out-of-order response from a previous timed-out request; skip.
                        continue;
                    }
                    if let Some(err) = resp.error {
                        return Err(ProviderError::SftpRelay(err));
                    }
                    return Ok(resp.result.unwrap_or(Value::Null));
                }
                RelayFrame::Binary(_) => {
                    // Unexpected binary frame while expecting a JSON response — skip.
                    continue;
                }
                RelayFrame::Closed => {
                    return Err(ProviderError::SftpRelay("connection closed".into()));
                }
            }
        }
    }

    /// Like `recv_response`, but additionally reads the following binary frame.
    /// Used for the `read` verb's two-frame response.
    async fn recv_response_then_binary(&self, expected_id: u32) -> Result<Vec<u8>, ProviderError> {
        // Phase 1: consume text frames until we get the matching JSON header.
        loop {
            match self.transport.recv().await? {
                RelayFrame::Text(text) => {
                    let resp: RpcResponse = serde_json::from_str(&text)
                        .map_err(|_| ProviderError::Provider("malformed JSON".into()))?;
                    if resp.id != expected_id {
                        continue;
                    }
                    if let Some(err) = resp.error {
                        return Err(ProviderError::SftpRelay(err));
                    }
                    // JSON header received; fall through to binary read.
                    break;
                }
                RelayFrame::Binary(_) => continue, // stale binary frame; skip
                RelayFrame::Closed => {
                    return Err(ProviderError::SftpRelay("connection closed".into()));
                }
            }
        }
        // Phase 2: read the binary data frame.
        loop {
            match self.transport.recv().await? {
                RelayFrame::Binary(data) => {
                    // Accumulate ciphertext bytes received (download bandwidth).
                    self.bytes_recv
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    return Ok(data);
                }
                RelayFrame::Text(_) => continue, // spurious text after binary header; skip
                RelayFrame::Closed => {
                    return Err(ProviderError::SftpRelay(
                        "connection closed during binary read".into(),
                    ));
                }
            }
        }
    }

    /// Send a JSON-only request and await the JSON response.
    async fn call<P: Serialize>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Value, ProviderError> {
        let id = self.next_id()?;
        let req = RpcRequest { id, method, params };
        let text = serde_json::to_string(&req)
            .map_err(|_| ProviderError::Provider("serialization failed".into()))?;
        self.transport.send_text(&text).await?;
        self.recv_response(id).await
    }

    /// Send a two-frame write request (JSON header + binary body) and await the JSON response.
    async fn call_binary_write<P: Serialize>(
        &self,
        method: &'static str,
        params: P,
        body: &[u8],
    ) -> Result<Value, ProviderError> {
        let id = self.next_id()?;
        let req = RpcRequest { id, method, params };
        let text = serde_json::to_string(&req)
            .map_err(|_| ProviderError::Provider("serialization failed".into()))?;
        self.transport.send_text_then_binary(&text, body).await?;
        // Accumulate ciphertext bytes sent (upload bandwidth).
        self.bytes_sent
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        self.recv_response(id).await
    }

    /// Send a standard JSON request and await a two-frame response (JSON then binary).
    async fn call_binary_read<P: Serialize>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Vec<u8>, ProviderError> {
        let id = self.next_id()?;
        let req = RpcRequest { id, method, params };
        let text = serde_json::to_string(&req)
            .map_err(|_| ProviderError::Provider("serialization failed".into()))?;
        self.transport.send_text(&text).await?;
        self.recv_response_then_binary(id).await
    }

    // ── Handshake ────────────────────────────────────────────────────────────

    /// Perform the host-key handshake.
    ///
    /// Reads the first frame from the relay (MUST be a `host_key` message),
    /// verifies the TOFU fingerprint, and sends `host_key_accepted`.
    ///
    /// Returns the relay protocol version (1 or 2+).
    ///
    /// On first connection (`stored_fingerprint` is `None`), calls
    /// `on_first_host_key` with the fingerprint.  If the callback returns
    /// `false`, the connection is rejected and the transport is closed.
    pub async fn handshake<F, Fut>(&self, on_first_host_key: F) -> Result<u32, ProviderError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let frame = self.transport.recv().await?;
        let text = match frame {
            RelayFrame::Text(t) => t,
            RelayFrame::Binary(_) => {
                return Err(ProviderError::SftpRelay(
                    "expected host_key text frame".into(),
                ))
            }
            RelayFrame::Closed => {
                return Err(ProviderError::SftpRelay(
                    "connection closed during handshake".into(),
                ))
            }
        };

        let msg: Value = serde_json::from_str(&text)
            .map_err(|_| ProviderError::Provider("malformed host_key frame".into()))?;

        if msg.get("type").and_then(|t| t.as_str()) != Some("host_key") {
            return Err(ProviderError::SftpRelay(format!(
                "expected host_key, got: {}",
                msg.get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown")
            )));
        }

        let fingerprint = msg
            .get("fingerprint")
            .and_then(|f| f.as_str())
            .ok_or_else(|| ProviderError::SftpRelay("host_key missing fingerprint".into()))?
            .to_string();

        let relay_version = match msg.get("relay_version").and_then(|v| v.as_u64()) {
            Some(v @ 1..=2) => v as u32,
            Some(v) => {
                return Err(ProviderError::SftpRelay(format!(
                    "unsupported relay_version: {v}; expected 1 or 2"
                )));
            }
            // Relay did not send relay_version — legacy v1 deployment.
            None => 1,
        };

        // TOFU verification.
        let stored = {
            self.state
                .lock()
                .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                .stored_fingerprint
                .clone()
        };

        match stored {
            Some(known) if known == fingerprint => {
                // Fingerprint matches — no user confirmation needed.
            }
            Some(known) => {
                // Mismatch — possible MITM or server key rotation.
                let _ = self.transport.close().await;
                return Err(ProviderError::SftpRelay(format!(
                    "host key changed: expected {known}, got {fingerprint}"
                )));
            }
            None => {
                // First connection — call user confirmation callback.
                let accepted = on_first_host_key(fingerprint.clone()).await;
                if !accepted {
                    let _ = self.transport.close().await;
                    return Err(ProviderError::SftpRelay("host key rejected by user".into()));
                }
                self.state
                    .lock()
                    .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
                    .stored_fingerprint = Some(fingerprint);
            }
        }

        // Accept and record relay version.
        self.transport
            .send_text(r#"{"type":"host_key_accepted"}"#)
            .await?;

        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .relay_version = relay_version;

        Ok(relay_version)
    }

    // ── Auth ─────────────────────────────────────────────────────────────────

    /// Authenticate with the SFTP server using password credentials.
    pub async fn auth_password(&self, username: &str, password: &str) -> Result<(), ProviderError> {
        self.call(
            "auth",
            serde_json::json!({
                "type": "password",
                "username": username,
                "password": password,
            }),
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .ready = true;
        Ok(())
    }

    /// Authenticate using a PEM private key.
    pub async fn auth_publickey(
        &self,
        username: &str,
        private_key: &str,
        passphrase: Option<&str>,
    ) -> Result<(), ProviderError> {
        self.call(
            "auth",
            serde_json::json!({
                "type": "publickey",
                "username": username,
                "privateKey": private_key,
                "passphrase": passphrase,
            }),
        )
        .await?;
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .ready = true;
        Ok(())
    }

    // ── Filesystem verbs ─────────────────────────────────────────────────────

    /// Query the remote file system's free space via the relay's
    /// `statvfs@openssh.com` shim. Returns `Some(free_bytes)` when the SFTP
    /// server supports the extension, `None` otherwise (non-OpenSSH servers,
    /// transient wire errors — caller should skip the gate rather than
    /// treat this as a hard failure).
    pub async fn fs_info(&self, path: &str) -> Result<Option<u64>, ProviderError> {
        let result = self
            .call("fs_info", serde_json::json!({ "path": path }))
            .await?;
        if !result["supported"].as_bool().unwrap_or(false) {
            return Ok(None);
        }
        Ok(result["freeBytes"].as_u64())
    }

    /// Stat a remote path. Returns `(mtime_ms, size, is_dir)`.
    pub async fn stat(&self, path: &str) -> Result<(i64, u64, bool), ProviderError> {
        let result = self
            .call("stat", serde_json::json!({ "path": path }))
            .await?;
        let mtime = result["mtime"].as_i64().unwrap_or(0);
        let size = result["size"].as_u64().unwrap_or(0);
        let is_dir = result["isDir"].as_bool().unwrap_or(false);
        Ok((mtime, size, is_dir))
    }

    /// List directory contents.
    pub async fn list(&self, path: &str) -> Result<Vec<StorageEntry>, ProviderError> {
        let result = self
            .call("list", serde_json::json!({ "path": path }))
            .await?;
        let entries = result["entries"]
            .as_array()
            .ok_or(ProviderError::InvalidResponse)?;
        entries
            .iter()
            .map(|e| {
                let path = e["path"]
                    .as_str()
                    .ok_or(ProviderError::InvalidResponse)?
                    .to_string();
                let name = e["name"]
                    .as_str()
                    .ok_or(ProviderError::InvalidResponse)?
                    .to_string();
                let size = e["size"].as_u64().unwrap_or(0);
                let is_folder = e["isDir"].as_bool().unwrap_or(false);
                // Relay sends mtime in Unix seconds; StorageEntry stores milliseconds.
                let mtime = e["mtime"].as_i64().map(|s| s * 1000);
                Ok(StorageEntry {
                    ref_: path,
                    name,
                    size,
                    is_folder,
                    mime_type: None,
                    modified_at: mtime,
                })
            })
            .collect()
    }

    /// Create a remote directory.  Ignores "already exists" errors only.
    pub async fn mkdir(&self, path: &str) -> Result<(), ProviderError> {
        match self
            .call("mkdir", serde_json::json!({ "path": path }))
            .await
        {
            Ok(_) => Ok(()),
            Err(ProviderError::SftpRelay(msg))
                if msg.contains("already exists")
                    || msg.contains("EEXIST")
                    || msg.contains("SSH_FX_FILE_ALREADY_EXISTS") =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Delete a remote file.
    pub async fn delete_file(&self, path: &str) -> Result<(), ProviderError> {
        self.call("delete", serde_json::json!({ "path": path }))
            .await?;
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .file_versions
            .remove(path);
        Ok(())
    }

    /// Rename (atomic move) a remote path.
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), ProviderError> {
        // D3: SPEC-BYO §BYO Relay Server names the rename params `from`/`to`;
        // the byo-relay relay accepts both spellings for upgrade safety.
        self.call(
            "rename",
            serde_json::json!({ "from": old_path, "to": new_path }),
        )
        .await?;
        Ok(())
    }

    /// Read a remote file entirely (single-shot, no streaming).
    pub async fn read(&self, path: &str) -> Result<Vec<u8>, ProviderError> {
        self.call_binary_read("read", serde_json::json!({ "path": path }))
            .await
    }

    /// Write a remote file entirely (single-shot v1 protocol).
    pub async fn write(&self, path: &str, data: &[u8]) -> Result<(), ProviderError> {
        self.call_binary_write(
            "write",
            serde_json::json!({ "path": path, "size": data.len() }),
            data,
        )
        .await?;
        Ok(())
    }

    // ── Version / conflict helpers ────────────────────────────────────────────

    /// Store the `mtime:size` version string for a path.
    pub async fn set_version(
        &self,
        path: &str,
        mtime: i64,
        size: u64,
    ) -> Result<(), ProviderError> {
        let version = format!("{mtime}:{size}");
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .file_versions
            .insert(path.to_string(), version);
        Ok(())
    }

    /// Get the cached `mtime:size` version string for a path (if any).
    pub fn cached_version(&self, path: &str) -> Option<String> {
        self.state.lock().ok()?.file_versions.get(path).cloned()
    }

    // ── Streaming upload ──────────────────────────────────────────────────────

    /// Open a streaming upload session against the relay's v2 write verbs.
    ///
    /// The v1 single-shot fallback was retired once the relay bumped to
    /// protocol version 2 at launch — every deployed relay now speaks v2+.
    /// Clients talking to an ancient pre-v2 relay will get a clear
    /// `write_open` error; reinstate `upload_close_v1` if that ever becomes
    /// a supported scenario again.
    ///
    /// Returns an opaque `stream_id` string that encodes the session state
    /// for subsequent `upload_write`, `upload_close`, and `upload_abort` calls.
    pub async fn upload_open(&self, name: &str, _total_size: u64) -> Result<String, ProviderError> {
        // Atomic temp path using a pseudo-random suffix derived from the counter.
        let counter = self.next_id()?;
        let root = self.vault_root_path();
        let temp_path = format!("{root}/data/{name}.tmp.{counter}");
        let final_path = format!("{root}/data/{name}");

        let result = self
            .call("write_open", serde_json::json!({ "path": &temp_path }))
            .await
            .map_err(|e| wrap_sftp_err(&format!("write_open {temp_path}"), e))?;
        let handle = result["handle"]
            .as_str()
            .ok_or(ProviderError::InvalidResponse)?
            .to_string();
        // Encode session state into the stream_id so the client is stateless
        // across open/write/close calls.  Format: "v2:<handle>:<temp_path>:<final_path>"
        Ok(format!("v2:{handle}:{temp_path}:{final_path}"))
    }

    /// Send one chunk for a v2 streaming upload.  `stream_id` must come from `upload_open`.
    pub async fn upload_write_chunk(
        &self,
        stream_id: &str,
        chunk: &[u8],
    ) -> Result<(), ProviderError> {
        let handle = parse_stream_id_v2_handle(stream_id)?;
        self.call_binary_write(
            "write_chunk",
            serde_json::json!({ "handle": handle }),
            chunk,
        )
        .await
        .map_err(|e| wrap_sftp_err(&format!("write_chunk handle={handle}"), e))?;
        Ok(())
    }

    /// Finalize a v2 streaming upload (write_close + rename).
    pub async fn upload_close_v2(&self, stream_id: &str) -> Result<UploadResult, ProviderError> {
        let (handle, temp_path, final_path) = parse_stream_id_v2(stream_id)?;
        // write_close finalizes the server-side temp file.
        self.call("write_close", serde_json::json!({ "handle": handle }))
            .await
            .map_err(|e| wrap_sftp_err(&format!("write_close handle={handle}"), e))?;
        // Atomic rename temp → final.
        self.rename(&temp_path, &final_path)
            .await
            .map_err(|e| wrap_sftp_err(&format!("rename {temp_path} -> {final_path}"), e))?;
        // Stat the final file to get the version.
        let (mtime, size, _) = self
            .stat(&final_path)
            .await
            .map_err(|e| wrap_sftp_err(&format!("stat {final_path}"), e))?;
        self.set_version(&final_path, mtime, size).await?;
        Ok(UploadResult {
            ref_: final_path,
            version: format!("{mtime}:{size}"),
        })
    }

    /// Abort a v2 streaming upload (best-effort write_abort).
    pub async fn upload_abort_v2(&self, stream_id: &str) {
        if let Ok(handle) = parse_stream_id_v2_handle(stream_id) {
            let _ = self
                .call("write_abort", serde_json::json!({ "handle": handle }))
                .await;
        }
    }

    // ── Streaming download ───────────────────────────────────────────────────

    /// Open a streaming read session for `path`.
    ///
    /// Mirrors the v2 write session pattern: relay opens an SFTP file handle
    /// and returns an opaque `read_handle`. Subsequent `read_chunk` calls pull
    /// bytes until EOF; caller must invoke `read_close` to release the handle.
    pub async fn read_open(&self, path: &str) -> Result<String, ProviderError> {
        let result = self
            .call("read_open", serde_json::json!({ "path": path }))
            .await
            .map_err(|e| wrap_sftp_err(&format!("read_open {path}"), e))?;
        let handle = result["handle"]
            .as_str()
            .ok_or(ProviderError::InvalidResponse)?
            .to_string();
        Ok(handle)
    }

    /// Pull the next chunk from a streaming read session.
    ///
    /// Returns `None` at EOF (signaled by an empty binary frame from the
    /// relay). After EOF the caller should still invoke `read_close` so the
    /// relay drops the session immediately rather than waiting for GC.
    pub async fn read_chunk(&self, handle: &str) -> Result<Option<Vec<u8>>, ProviderError> {
        let data = self
            .call_binary_read("read_chunk", serde_json::json!({ "handle": handle }))
            .await
            .map_err(|e| wrap_sftp_err(&format!("read_chunk handle={handle}"), e))?;
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }

    /// Close a streaming read session. Idempotent on the client side — the
    /// relay is responsible for dropping stale sessions on disconnect.
    pub async fn read_close(&self, handle: &str) -> Result<(), ProviderError> {
        let _ = self
            .call("read_close", serde_json::json!({ "handle": handle }))
            .await
            .map_err(|e| wrap_sftp_err(&format!("read_close handle={handle}"), e))?;
        Ok(())
    }

    // ── Root folder ───────────────────────────────────────────────────────────

    /// Ensure the vault root and its `/data` subdirectory exist on the SFTP
    /// server.  With a `base_path` of `""` these are `/WattcloudVault` and
    /// `/WattcloudVault/data`; with `"/wattcloud"` they are
    /// `/wattcloud/WattcloudVault` and `/wattcloud/WattcloudVault/data`.
    /// If the user-supplied `base_path` doesn't exist yet (e.g. a Hetzner
    /// sub-account that chroots to the parent directory), we mkdir -p each
    /// component so the caller doesn't have to pre-create it by hand.
    pub async fn ensure_root_folders(&self) -> Result<(), ProviderError> {
        self.ensure_dir_recursive(&self.base_path)
            .await
            .map_err(|e| wrap_sftp_err("ensure base path", e))?;
        let root = self.vault_root_path();
        self.ensure_dir(&root)
            .await
            .map_err(|e| wrap_sftp_err("ensure vault root", e))?;
        let data_path = format!("{root}/data");
        self.ensure_dir(&data_path)
            .await
            .map_err(|e| wrap_sftp_err("ensure vault data dir", e))?;
        Ok(())
    }

    /// Stat `path`; if it doesn't exist, mkdir it.  Leaves other errors
    /// (permission denied, etc.) to the caller.  On any failure we wrap the
    /// underlying error with the path so the diagnostic in the toast tells
    /// the user *which* step broke instead of a bare `No such file`.
    async fn ensure_dir(&self, path: &str) -> Result<(), ProviderError> {
        if path.is_empty() {
            return Ok(());
        }
        match self.stat(path).await {
            Ok(_) => Ok(()),
            Err(ProviderError::SftpRelay(_)) => self.mkdir(path).await.map_err(|e| match e {
                ProviderError::SftpRelay(msg) => {
                    ProviderError::SftpRelay(format!("mkdir {path}: {msg}"))
                }
                other => other,
            }),
            Err(e) => Err(match e {
                ProviderError::SftpRelay(msg) => {
                    ProviderError::SftpRelay(format!("stat {path}: {msg}"))
                }
                other => other,
            }),
        }
    }

    /// mkdir -p semantics: walk `/a/b/c`, calling [`Self::ensure_dir`] for
    /// each prefix (`/a`, `/a/b`, `/a/b/c`).  An empty or `/` path is a no-op.
    async fn ensure_dir_recursive(&self, path: &str) -> Result<(), ProviderError> {
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Ok(());
        }
        let components: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        let mut accumulator = String::new();
        for part in components {
            accumulator.push('/');
            accumulator.push_str(part);
            self.ensure_dir(&accumulator).await?;
        }
        Ok(())
    }

    /// Disconnect the underlying transport.
    pub async fn disconnect(&self) -> Result<(), ProviderError> {
        self.state
            .lock()
            .map_err(|_| ProviderError::Provider("lock poisoned".into()))?
            .ready = false;
        self.transport.close().await
    }
}

/// Prepend an operation label to any `ProviderError::SftpRelay` error so a
/// toast shows `ensure base path: <detail>` instead of a bare `No such file`.
/// Other error variants pass through untouched.
fn wrap_sftp_err(op: &str, err: ProviderError) -> ProviderError {
    match err {
        ProviderError::SftpRelay(msg) => ProviderError::SftpRelay(format!("{op}: {msg}")),
        other => other,
    }
}

// ─── Stream ID helpers ────────────────────────────────────────────────────────

fn parse_stream_id_v2(stream_id: &str) -> Result<(String, String, String), ProviderError> {
    // Format: "v2:<handle>:<temp_path>:<final_path>"
    let rest = stream_id
        .strip_prefix("v2:")
        .ok_or(ProviderError::Provider("invalid v2 stream_id".into()))?;
    // handle may not contain ':', but paths do — so split from left (3 parts).
    let mut parts = rest.splitn(3, ':');
    let handle = parts
        .next()
        .ok_or(ProviderError::Provider("stream_id missing handle".into()))?
        .to_string();
    let temp_path = parts
        .next()
        .ok_or(ProviderError::Provider(
            "stream_id missing temp_path".into(),
        ))?
        .to_string();
    let final_path = parts
        .next()
        .ok_or(ProviderError::Provider(
            "stream_id missing final_path".into(),
        ))?
        .to_string();
    Ok((handle, temp_path, final_path))
}

fn parse_stream_id_v2_handle(stream_id: &str) -> Result<String, ProviderError> {
    Ok(parse_stream_id_v2(stream_id)?.0)
}

/// Normalize a user-supplied SFTP base path.
///
/// - empty / whitespace → `""` (no prefix)
/// - trims whitespace
/// - strips trailing slashes
/// - prepends a single `/` if the caller forgot it
///
/// The returned string is either `""` or `"/foo"` / `"/foo/bar"` — never
/// ends in `/`, never contains repeated slashes at the seam.
fn normalize_base_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_trailing = trimmed.trim_end_matches('/');
    if without_trailing.is_empty() {
        return String::new();
    }
    if without_trailing.starts_with('/') {
        without_trailing.to_string()
    } else {
        format!("/{without_trailing}")
    }
}

// ─── SftpProvider (thin wrapper implementing StorageProvider) ─────────────────
//
// Not yet a full impl — needs the streaming I/O contract finalized in P8.
// Providing basic metadata/lifecycle impl so sdk-ffi can already bind it.

pub struct SftpProvider<T: RelayTransport> {
    client: Arc<SftpRelayClient<T>>,
    #[allow(dead_code)]
    config: Arc<Mutex<crate::byo::provider::ProviderConfig>>,
}

impl<T: RelayTransport + 'static> SftpProvider<T> {
    pub fn new(transport: T, base_path: String) -> Self {
        Self {
            client: Arc::new(SftpRelayClient::new(transport, base_path)),
            config: Arc::new(Mutex::new(Default::default())),
        }
    }

    pub fn client(&self) -> &SftpRelayClient<T> {
        &self.client
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod mock {
    use super::*;
    use std::collections::VecDeque;

    /// Frame queued by the client for sending.
    #[derive(Debug, PartialEq)]
    pub enum SentFrame {
        Text(String),
        TextThenBinary(String, Vec<u8>),
    }

    /// A simple mock transport that plays back a pre-scripted sequence of
    /// relay frames and records all frames the client sends.
    pub struct MockRelayTransport {
        /// Frames the relay "sends" to the client (pre-loaded at construction).
        recv_queue: Mutex<VecDeque<RelayFrame>>,
        /// Frames the client sent to the relay (inspected in tests).
        sent: Mutex<Vec<SentFrame>>,
        closed: Mutex<bool>,
    }

    impl MockRelayTransport {
        pub fn new(recv_frames: Vec<RelayFrame>) -> Self {
            Self {
                recv_queue: Mutex::new(recv_frames.into()),
                sent: Mutex::new(Vec::new()),
                closed: Mutex::new(false),
            }
        }

        /// Drain the recorded sent frames for assertion.
        pub fn drain_sent(&self) -> Vec<SentFrame> {
            self.sent.lock().unwrap().drain(..).collect()
        }
    }

    // SAFETY: tests are single-threaded (tokio::test uses a current-thread runtime).
    unsafe impl Send for MockRelayTransport {}
    unsafe impl Sync for MockRelayTransport {}

    impl RelayTransport for MockRelayTransport {
        fn send_text(
            &self,
            s: &str,
        ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
            self.sent
                .lock()
                .unwrap()
                .push(SentFrame::Text(s.to_string()));
            async { Ok(()) }
        }

        fn send_text_then_binary(
            &self,
            text_hdr: &str,
            body: &[u8],
        ) -> impl std::future::Future<Output = Result<(), ProviderError>> {
            self.sent.lock().unwrap().push(SentFrame::TextThenBinary(
                text_hdr.to_string(),
                body.to_vec(),
            ));
            async { Ok(()) }
        }

        fn recv(&self) -> impl std::future::Future<Output = Result<RelayFrame, ProviderError>> {
            let frame = self
                .recv_queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RelayFrame::Closed);
            async move { Ok(frame) }
        }

        fn close(&self) -> impl std::future::Future<Output = Result<(), ProviderError>> {
            *self.closed.lock().unwrap() = true;
            async { Ok(()) }
        }
    }

    // ── Helper builders ───────────────────────────────────────────────────────

    /// Build the standard relay frames for a v2 handshake (host_key + accepted).
    pub fn v2_handshake_frames(fingerprint: &str) -> Vec<RelayFrame> {
        vec![RelayFrame::Text(format!(
            r#"{{"type":"host_key","fingerprint":"{fingerprint}","relay_version":2}}"#
        ))]
        // host_key_accepted is sent by the CLIENT; relay doesn't send a response.
    }

    /// Build a successful JSON response frame.
    pub fn ok_response(id: u32, result: Value) -> RelayFrame {
        RelayFrame::Text(format!(r#"{{"id":{id},"result":{result}}}"#))
    }

    /// Build an error JSON response frame.
    pub fn err_response(id: u32, error: &str) -> RelayFrame {
        RelayFrame::Text(format!(r#"{{"id":{id},"error":"{error}"}}"#))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::mock::*;
    use super::*;
    use serde_json::json;

    fn make_client(recv: Vec<RelayFrame>) -> SftpRelayClient<MockRelayTransport> {
        // Tests default to an empty base_path so the vault root is
        // `/WattcloudVault` — matches the hard-coded expectations in the
        // assertions below.
        SftpRelayClient::new(MockRelayTransport::new(recv), String::new())
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn handshake_first_connection_accepted() {
        let client = make_client(v2_handshake_frames("SHA256:abc123"));
        let version = client
            .handshake(|fp| async move {
                assert_eq!(fp, "SHA256:abc123");
                true // user accepts
            })
            .await
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(
            client.stored_fingerprint(),
            Some("SHA256:abc123".to_string())
        );
    }

    #[tokio::test]
    async fn handshake_first_connection_rejected() {
        let client = make_client(v2_handshake_frames("SHA256:abc123"));
        let result = client.handshake(|_fp| async { false }).await;
        assert!(matches!(result, Err(ProviderError::SftpRelay(_))));
    }

    #[tokio::test]
    async fn handshake_known_fingerprint_matches() {
        let frames = v2_handshake_frames("SHA256:known");
        let client = make_client(frames);
        // Pre-set the stored fingerprint.
        client.state.lock().unwrap().stored_fingerprint = Some("SHA256:known".to_string());
        let version = client
            .handshake(|_| async { panic!("should not call callback") })
            .await
            .unwrap();
        assert_eq!(version, 2);
    }

    #[tokio::test]
    async fn handshake_fingerprint_mismatch_rejects() {
        let frames = v2_handshake_frames("SHA256:new");
        let client = make_client(frames);
        client.state.lock().unwrap().stored_fingerprint = Some("SHA256:old".to_string());
        let result = client
            .handshake(|_| async { panic!("should not call callback") })
            .await;
        assert!(matches!(result, Err(ProviderError::SftpRelay(_))));
    }

    #[tokio::test]
    async fn set_stored_fingerprint_makes_handshake_skip_callback() {
        // Regression: the WASM SftpSessionWasm binding had no set_stored_fingerprint
        // method, so SftpProvider.ts could never inject the persisted TOFU fp and
        // every reconnect ran the `on_first_host_key` callback (which the hydrate
        // path unconditionally accepts). Verify the setter now drives the same
        // "known fingerprint matches" path as pre-setting the state directly.
        let frames = v2_handshake_frames("SHA256:injected");
        let client = make_client(frames);
        client
            .set_stored_fingerprint("SHA256:injected".to_string())
            .unwrap();
        let version = client
            .handshake(|_| async { panic!("callback must not run for known fingerprint") })
            .await
            .unwrap();
        assert_eq!(version, 2);
    }

    #[tokio::test]
    async fn set_stored_fingerprint_then_mismatch_rejects() {
        // A stored fingerprint injected via the setter must be compared against
        // the live one — a swapped host key (MITM/compromised relay) must reject.
        let frames = v2_handshake_frames("SHA256:evil");
        let client = make_client(frames);
        client
            .set_stored_fingerprint("SHA256:trusted".to_string())
            .unwrap();
        let result = client
            .handshake(|_| async { panic!("callback must not run for known fingerprint") })
            .await;
        assert!(matches!(result, Err(ProviderError::SftpRelay(_))));
    }

    #[tokio::test]
    async fn handshake_sends_host_key_accepted() {
        let client = make_client(v2_handshake_frames("SHA256:x"));
        client.handshake(|_| async { true }).await.unwrap();
        let sent = client.transport.drain_sent();
        assert!(sent
            .iter()
            .any(|f| matches!(f, SentFrame::Text(t) if t.contains("host_key_accepted"))));
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn auth_password_sends_correct_request() {
        let client = make_client(vec![ok_response(1, json!({}))]);
        client.auth_password("alice", "s3cr3t").await.unwrap();
        let sent = client.transport.drain_sent();
        assert_eq!(sent.len(), 1);
        if let SentFrame::Text(text) = &sent[0] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["method"], "auth");
            assert_eq!(v["params"]["type"], "password");
            assert_eq!(v["params"]["username"], "alice");
            assert_eq!(v["params"]["password"], "s3cr3t");
        } else {
            panic!("expected Text frame");
        }
    }

    #[tokio::test]
    async fn auth_publickey_sends_correct_request() {
        let client = make_client(vec![ok_response(1, json!({}))]);
        client
            .auth_publickey("bob", "-----BEGIN RSA PRIVATE KEY-----...", Some("pass"))
            .await
            .unwrap();
        let sent = client.transport.drain_sent();
        if let SentFrame::Text(text) = &sent[0] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["params"]["type"], "publickey");
            assert_eq!(v["params"]["passphrase"], "pass");
        } else {
            panic!("expected Text");
        }
    }

    // ── Filesystem verbs ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn stat_returns_parsed_values() {
        let client = make_client(vec![ok_response(
            1,
            json!({"mtime":1700000000,"size":4096,"isDir":true}),
        )]);
        let (mtime, size, is_dir) = client.stat("/WattcloudVault").await.unwrap();
        assert_eq!(mtime, 1700000000);
        assert_eq!(size, 4096);
        assert!(is_dir);
    }

    #[tokio::test]
    async fn list_parses_entries() {
        let client = make_client(vec![ok_response(
            1,
            json!({
                "entries": [
                    {"path":"/WattcloudVault/vault.sc","name":"vault.sc","size":1024,"isDir":false,"mtime":1700000000},
                    {"path":"/WattcloudVault/data","name":"data","size":0,"isDir":true,"mtime":1700000001},
                ]
            }),
        )]);
        let entries = client.list("/WattcloudVault").await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "vault.sc");
        assert!(!entries[0].is_folder);
        assert!(entries[1].is_folder);
    }

    #[tokio::test]
    async fn rename_sends_correct_params() {
        let client = make_client(vec![ok_response(1, json!({}))]);
        client
            .rename("/tmp/file", "/WattcloudVault/data/file.sc")
            .await
            .unwrap();
        let sent = client.transport.drain_sent();
        if let SentFrame::Text(text) = &sent[0] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["method"], "rename");
            assert_eq!(v["params"]["from"], "/tmp/file");
            assert_eq!(v["params"]["to"], "/WattcloudVault/data/file.sc");
        }
    }

    #[tokio::test]
    async fn read_binary_two_frame_response() {
        let data = b"hello world".to_vec();
        let client = make_client(vec![
            ok_response(1, json!({"size": 11})),
            RelayFrame::Binary(data.clone()),
        ]);
        let result = client.read("/WattcloudVault/vault.sc").await.unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn write_sends_two_frames() {
        let client = make_client(vec![ok_response(1, json!({}))]);
        let data = b"ciphertext".to_vec();
        client.write("/WattcloudVault/vault.sc", &data).await.unwrap();
        let sent = client.transport.drain_sent();
        if let SentFrame::TextThenBinary(text, body) = &sent[0] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["method"], "write");
            assert_eq!(v["params"]["path"], "/WattcloudVault/vault.sc");
            assert_eq!(v["params"]["size"], 10);
            assert_eq!(*body, data);
        } else {
            panic!("expected TextThenBinary");
        }
    }

    // ── V2 upload state machine ───────────────────────────────────────────────

    #[tokio::test]
    async fn upload_v2_happy_path() {
        // Responses for: write_open → handle, write_chunk → ok, write_close → ok, rename → ok, stat → version
        let client = make_client(vec![
            // upload_open sends write_open (id=2, since we called next_id once for temp suffix)
            ok_response(2, json!({"handle": "h1"})),
            // upload_write_chunk
            ok_response(3, json!({})),
            // upload_close_v2: write_close
            ok_response(4, json!({})),
            // rename
            ok_response(5, json!({})),
            // stat for version
            ok_response(6, json!({"mtime": 1700000000, "size": 8, "isDir": false})),
        ]);
        client.state.lock().unwrap().relay_version = 2;

        let stream_id = client.upload_open("test.sc", 8).await.unwrap();
        assert!(stream_id.starts_with("v2:"));

        client
            .upload_write_chunk(&stream_id, b"aaaabbbb")
            .await
            .unwrap();
        let result = client.upload_close_v2(&stream_id).await.unwrap();

        assert!(result.ref_.ends_with("test.sc"));
        assert_eq!(result.version, "1700000000:8");
    }

    #[tokio::test]
    async fn relay_error_response_propagates() {
        let client = make_client(vec![err_response(1, "permission denied")]);
        let result = client.stat("/forbidden").await;
        assert!(
            matches!(result, Err(ProviderError::SftpRelay(msg)) if msg.contains("permission denied"))
        );
    }

    // ── Streaming read (v2) ──────────────────────────────────────────────────

    #[tokio::test]
    async fn read_streaming_happy_path() {
        // read_open → handle, read_chunk × 2 (data then EOF), read_close → ok
        let chunk1 = b"first-chunk-".to_vec();
        let chunk2 = b"second-chunk".to_vec();
        let client = make_client(vec![
            // read_open (id=1) → { handle }
            ok_response(1, json!({ "handle": "rh-abc" })),
            // read_chunk (id=2) → { size: N } + binary
            ok_response(2, json!({ "size": chunk1.len() })),
            RelayFrame::Binary(chunk1.clone()),
            // read_chunk (id=3) → { size: N } + binary
            ok_response(3, json!({ "size": chunk2.len() })),
            RelayFrame::Binary(chunk2.clone()),
            // read_chunk (id=4) → { size: 0 } + empty binary (EOF)
            ok_response(4, json!({ "size": 0 })),
            RelayFrame::Binary(vec![]),
            // read_close (id=5) → ok
            ok_response(5, json!({})),
        ]);

        let handle = client.read_open("/WattcloudVault/data/f.sc").await.unwrap();
        assert_eq!(handle, "rh-abc");

        let first = client.read_chunk(&handle).await.unwrap();
        assert_eq!(first, Some(chunk1));

        let second = client.read_chunk(&handle).await.unwrap();
        assert_eq!(second, Some(chunk2));

        let eof = client.read_chunk(&handle).await.unwrap();
        assert!(eof.is_none(), "empty binary frame must map to None");

        client.read_close(&handle).await.unwrap();

        let sent = client.transport.drain_sent();
        assert_eq!(sent.len(), 5);
        if let SentFrame::Text(text) = &sent[0] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["method"], "read_open");
            assert_eq!(v["params"]["path"], "/WattcloudVault/data/f.sc");
        } else {
            panic!("expected Text frame for read_open");
        }
        if let SentFrame::Text(text) = &sent[4] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert_eq!(v["method"], "read_close");
            assert_eq!(v["params"]["handle"], "rh-abc");
        } else {
            panic!("expected Text frame for read_close");
        }
    }

    #[tokio::test]
    async fn read_chunk_propagates_relay_error() {
        let client = make_client(vec![err_response(1, "unknown read handle")]);
        let err = client.read_chunk("rh-missing").await.unwrap_err();
        assert!(
            matches!(&err, ProviderError::SftpRelay(msg) if msg.contains("unknown read handle")),
            "expected SftpRelay error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn stream_id_parse_roundtrip_v2() {
        let stream_id = "v2:myhandle:/WattcloudVault/data/file.sc.tmp.42:/WattcloudVault/data/file.sc";
        let (handle, temp, fin) = parse_stream_id_v2(stream_id).unwrap();
        assert_eq!(handle, "myhandle");
        assert_eq!(temp, "/WattcloudVault/data/file.sc.tmp.42");
        assert_eq!(fin, "/WattcloudVault/data/file.sc");
    }

}
