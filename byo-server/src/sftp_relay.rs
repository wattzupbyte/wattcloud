//! SFTP relay gateway: translates JSON-RPC commands from the browser into SSH/SFTP operations.
//!
//! The client-side SftpProvider.ts sends JSON-RPC over WebSocket. This handler:
//!   1. Validates relay_auth cookie and SSRF-checks the target host (done by caller).
//!   2. Accepts `auth` (SSH credentials), connects to the pinned IP via russh.
//!   3. Dispatches subsequent commands (stat, list, read, write, mkdir, delete, rename).
//!   4. Returns JSON responses; file data uses a two-frame protocol:
//!      - Read:  JSON {id, result: {size}} + binary frame with file bytes
//!      - Write: JSON {id, method, params: {path, size}} + binary frame → JSON {id, result: {}}
//!
//! SECURITY NOTE: SSH host key verification is blind-accepted.
//! Rationale: the relay is stateless (cannot persist known_hosts). Users are expected
//! to connect to their own servers. TOFU or explicit fingerprint verification
//! should be added in Phase 5+ (ByoSettings). Documented in byo/SECURITY.md.

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use russh::client::{self, Config as SshConfig, Handle};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use tokio::net::TcpStream;
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use crate::errors::SftpRelayError;
use crate::rate_limit::SftpAuthFailureTracker;

/// Idle timeout: 30 minutes of no WebSocket activity closes the SSH session. R4.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum size of a single binary data frame (16 MiB). Applies to both the
/// legacy single-shot `write` verb and each `write_chunk` frame.
const MAX_BINARY_FRAME: usize = 16 * 1024 * 1024;
/// Maximum accumulated size for a streaming write session (200 MiB).
/// Guards against relay OOM if a client streams without closing.
const MAX_STREAM_BUFFER: usize = 200 * 1024 * 1024;
/// Protocol version advertised in the `host_key` frame.
/// Clients use this to decide whether to use the streaming write verbs.
///
/// Version history:
///   1 — initial (write = single-shot two-frame)
///   2 — adds write_open / write_chunk / write_close / write_abort
const RELAY_PROTOCOL_VERSION: u32 = 2;

/// Returns true iff `buf` begins with a valid SSH protocol version banner.
/// SSH-2.0 is current; SSH-1.99 indicates a server that also speaks SSHv1.
fn is_ssh_banner(buf: &[u8]) -> bool {
    buf.starts_with(b"SSH-2.0") || buf.starts_with(b"SSH-1.99")
}

// ── JSON-RPC wire types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WsRequest {
    id: u32,
    method: String,
    params: Value,
}

#[derive(Debug, Serialize)]
struct WsResponse<T: Serialize> {
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok_json<T: Serialize>(id: u32, result: T) -> String {
    serde_json::to_string(&WsResponse {
        id,
        result: Some(result),
        error: None,
    })
    .unwrap_or_else(|_| err_json_str(id, "serialization error"))
}

fn err_json(id: u32, msg: impl std::fmt::Display) -> String {
    err_json_str(id, &msg.to_string())
}

fn err_json_str(id: u32, msg: &str) -> String {
    serde_json::to_string(&WsResponse::<()> {
        id,
        result: None,
        error: Some(msg.to_string()),
    })
    .unwrap_or_else(|_| format!(r#"{{"id":{id},"error":"internal"}}"#))
}

fn param_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

// ── russh client handler with host-key capture ────────────────────────────────

/// Handler that captures the server's host-key fingerprint during the SSH handshake.
/// All keys are accepted at the SSH level; the relay forwards the fingerprint to the
/// browser client which makes the trust decision (TOFU check against vault-stored value).
struct CapturingKeyHandler {
    fingerprint: Arc<std::sync::Mutex<Option<String>>>,
}

impl client::Handler for CapturingKeyHandler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        if let Ok(mut guard) = self.fingerprint.lock() {
            *guard = Some(fp);
        }
        Ok(true) // Accept at SSH level; client performs the TOFU check
    }
}

// ── Public entry point ─────────────────────────────────────────────────────────

/// Handle an SFTP relay WebSocket session.
/// `pinned_ips` must already be validated by `dns::resolve_and_validate`.
/// `client_ip` and `remote_host` are used for rate-limit tracking and logging.
pub async fn handle_sftp_session(
    ws: WebSocket,
    pinned_ips: Vec<IpAddr>,
    port: u16,
    client_ip: IpAddr,
    remote_host: String,
    auth_tracker: Arc<SftpAuthFailureTracker>,
) {
    // Record host access for spray detection before connecting.
    // This happens even before auth so we can detect fast-iteration probing.
    if auth_tracker.record_host(client_ip, &remote_host) {
        // Spray detected — the tracker has already applied the block; close immediately.
        let _ = ws.close().await;
        return;
    }

    tracing::info!(

        remote_host = %remote_host,
        port,
        "sftp relay session started"
    );

    match run_session(ws, pinned_ips, port, client_ip, &remote_host, &auth_tracker).await {
        Ok(stats) => {
            tracing::info!(
        
                remote_host = %remote_host,
                bytes_up = stats.bytes_up,
                bytes_down = stats.bytes_down,
                close_reason = %stats.close_reason,
                "sftp relay session ended"
            );
        }
        Err(e) => {
            tracing::info!(
        
                remote_host = %remote_host,
                close_reason = %e,
                "sftp relay session ended with error"
            );
        }
    }
}

struct SessionStats {
    bytes_up: usize,
    bytes_down: usize,
    close_reason: &'static str,
}

async fn run_session(
    ws: WebSocket,
    pinned_ips: Vec<IpAddr>,
    port: u16,
    client_ip: IpAddr,
    _remote_host: &str,
    auth_tracker: &SftpAuthFailureTracker,
) -> Result<SessionStats, SftpRelayError> {
    let (mut sink, mut stream) = ws.split();

    // Step 1: TCP connect + SSH banner verification.
    // We use peek() so the banner bytes remain in the socket buffer for russh to consume.
    // This lets us validate the server speaks SSH before spending handshake resources
    // and before exposing the relay as a general TCP-connect primitive.
    let tcp = timeout(
        Duration::from_secs(10),
        TcpStream::connect((pinned_ips[0], port)),
    )
    .await
    .map_err(|_| SftpRelayError::SshConnect("connect timeout".into()))?
    .map_err(|e| SftpRelayError::SshConnect(e.to_string()))?;

    // D11: TCP `peek` can return as few as 1 byte on packet splits. Loop
    // until we have the full `"SSH-2.0-"` prefix (8 bytes) or time out,
    // otherwise a slow/split SSH banner is misclassified as NotSshServer.
    let mut banner_buf = [0u8; 255];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let n = match tokio::time::timeout_at(deadline, tcp.peek(&mut banner_buf)).await {
            Ok(Ok(n)) => n,
            _ => return Err(SftpRelayError::NotSshServer),
        };
        if n >= 8 {
            let banner = &banner_buf[..n];
            if !is_ssh_banner(banner) {
                return Err(SftpRelayError::NotSshServer);
            }
            break;
        }
        // Yield briefly so the remote can flush more of the banner; peek is
        // edge-like on TCP — without a small sleep we can busy-loop in the
        // rare case where only 1–7 bytes have landed.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Step 1b: Complete SSH handshake over the verified stream, capturing host-key fingerprint.
    // We connect before reading auth so we can send the fingerprint for TOFU verification
    // BEFORE the client sends credentials — no credentials are transmitted to the relay
    // until the client confirms the host key.
    let captured_fp: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let config = Arc::new(SshConfig::default());
    let mut ssh = client::connect_stream(
        config,
        tcp,
        CapturingKeyHandler {
            fingerprint: Arc::clone(&captured_fp),
        },
    )
    .await
    .map_err(|e| SftpRelayError::SshConnect(e.to_string()))?;

    // Step 2: Send host-key fingerprint to client for TOFU verification.
    // The client must respond with {"type":"host_key_accepted"} before sending credentials.
    let fingerprint = captured_fp
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default();

    let host_key_frame = serde_json::json!({
        "type": "host_key",
        "fingerprint": fingerprint,
        "relay_version": RELAY_PROTOCOL_VERSION,
    });
    sink.send(Message::Text(
        serde_json::to_string(&host_key_frame).unwrap_or_default(),
    ))
    .await
    .map_err(|_| SftpRelayError::UnexpectedMessage)?;

    // Step 3: Wait for host_key_accepted (30 s). Credentials must not arrive first.
    let ack = timeout(Duration::from_secs(30), stream.next())
        .await
        .map_err(|_| SftpRelayError::Timeout)?
        .ok_or(SftpRelayError::HostKeyRejected)?  // WS closed = client rejected
        .map_err(|_| SftpRelayError::UnexpectedMessage)?;

    match ack {
        Message::Text(t) => {
            let v: serde_json::Value =
                serde_json::from_str(&t).map_err(|_| SftpRelayError::UnexpectedMessage)?;
            if v.get("type").and_then(|t| t.as_str()) != Some("host_key_accepted") {
                return Err(SftpRelayError::HostKeyRejected);
            }
        }
        Message::Close(_) => return Err(SftpRelayError::HostKeyRejected),
        _ => return Err(SftpRelayError::UnexpectedMessage),
    }

    // Step 4: Read auth message (credentials only arrive after TOFU is confirmed).
    let auth_msg = timeout(Duration::from_secs(30), stream.next())
        .await
        .map_err(|_| SftpRelayError::Timeout)?
        .ok_or(SftpRelayError::UnexpectedMessage)?
        .map_err(|_| SftpRelayError::UnexpectedMessage)?;

    let AuthParams {
        id: auth_id,
        username,
        credential,
    } = parse_auth(auth_msg)?;

    // Step 5: authenticate.
    // Record a tentative failure BEFORE the handshake. If auth succeeds we refund it.
    // This closes the parallel-guess window: without pre-recording, an attacker can send
    // N parallel connections that all start their handshakes before any failure is
    // counted, effectively multiplying their guess budget by N.
    auth_tracker.record_failure(client_ip);

    let ok = match credential {
        Credential::Password(pw) => ssh
            .authenticate_password(&username, pw)
            .await
            .map_err(|e| SftpRelayError::SshConnect(e.to_string()))?
            .success(),
        Credential::PrivateKey { pem, passphrase } => {
            auth_pubkey(&mut ssh, &username, &pem, passphrase.as_deref()).await?
        }
    };

    if !ok {
        // Failure already counted pre-handshake — do not double-count.
        let _ = sink
            .send(Message::Text(err_json(auth_id, "authentication failed")))
            .await;
        return Err(SftpRelayError::SshAuth);
    }

    // Auth succeeded — refund the tentative failure.
    auth_tracker.refund_failure(client_ip);

    // Step 4: open SFTP subsystem
    let channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| SftpRelayError::SftpInit(e.to_string()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| SftpRelayError::SftpInit(e.to_string()))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| SftpRelayError::SftpInit(e.to_string()))?;

    let _ = sink
        .send(Message::Text(ok_json(auth_id, serde_json::json!({}))))
        .await;

    // Step 5: command loop
    dispatch_loop(&mut sink, &mut stream, &sftp).await
}

/// In-progress streaming write session (v2 protocol).
/// Accumulates chunks until `write_close` flushes the buffer via SFTP.
struct WriteSession {
    path: String,
    buffer: Vec<u8>,
}

/// What the next binary frame should be delivered to.
enum PendingBinary {
    /// Legacy single-shot write: (request_id, file_path)
    Write { req_id: u32, path: String },
    /// Streaming chunk: (request_id, session_handle)
    WriteChunk { req_id: u32, handle: String },
    /// SR2: the previous JSON command (`write` or `write_chunk`) returned an
    /// error but the protocol still requires the client to deliver a binary
    /// frame next. Drain and drop it with an error reply so the client
    /// doesn't hang waiting for an ack.
    Drain { req_id: u32, reason: &'static str },
}

async fn dispatch_loop(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    sftp: &SftpSession,
) -> Result<SessionStats, SftpRelayError> {
    let mut pending_binary: Option<PendingBinary> = None;
    let mut write_sessions: std::collections::HashMap<String, WriteSession> = std::collections::HashMap::new();
    // Aggregate buffered bytes across ALL open write sessions in this connection.
    // SPEC-BYO: single 200 MiB cap, not per-session — otherwise N concurrent
    // write_open handles multiply the server's buffer commitment.
    let mut total_buffered: usize = 0;
    let mut bytes_up: usize = 0;
    // D5: make the down-counter mutable and actually increment it whenever
    // we send bytes back to the client (binary read responses, JSON frames).
    // Previously this stayed at 0 forever so SFTP download bandwidth metrics
    // reported nothing — capacity planning off by a full direction.
    let mut bytes_down: usize = 0;

    loop {
        let msg = match timeout(IDLE_TIMEOUT, stream.next()).await {
            Err(_) => {
                return Err(SftpRelayError::Timeout);
            }
            Ok(None) | Ok(Some(Err(_))) => {
                return Ok(SessionStats {
                    bytes_up,
                    bytes_down,
                    close_reason: "client_closed",
                });
            }
            Ok(Some(Ok(m))) => m,
        };

        match msg {
            Message::Text(text) => {
                bytes_up = bytes_up.saturating_add(text.len());
                let req: WsRequest = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                handle_text_command(
                    sink,
                    sftp,
                    req,
                    &mut pending_binary,
                    &mut write_sessions,
                    &mut total_buffered,
                    &mut bytes_down,
                )
                .await;
            }

            Message::Binary(data) => {
                if data.len() > MAX_BINARY_FRAME {
                    // D12: a stray/oversized binary frame without a pending
                    // write used to be silently dropped — the client then kept
                    // waiting for a response that never came, eventually
                    // hitting idle timeout. Return an error to the last-seen
                    // request id (if any), then close the connection since
                    // the protocol state is now ambiguous.
                    if let Some(pb) = pending_binary.take() {
                        let req_id = match &pb {
                            PendingBinary::Write { req_id, .. }
                            | PendingBinary::WriteChunk { req_id, .. }
                            | PendingBinary::Drain { req_id, .. } => *req_id,
                        };
                        let _ = sink.send(Message::Text(err_json(req_id, "payload too large"))).await;
                    } else {
                        let _ = sink
                            .send(Message::Text(err_json(
                                0,
                                "unexpected oversized binary frame",
                            )))
                            .await;
                    }
                    return Ok(SessionStats {
                        bytes_up,
                        bytes_down,
                        close_reason: "oversized_binary_frame",
                    });
                }
                bytes_up = bytes_up.saturating_add(data.len());

                match pending_binary.take() {
                    Some(PendingBinary::Drain { req_id, reason }) => {
                        // SR2: drop the follow-up binary for a JSON command
                        // that already errored, so the client sees a clear
                        // response instead of waiting for a silent ack.
                        let _ = sink.send(Message::Text(err_json(req_id, reason))).await;
                    }
                    Some(PendingBinary::Write { req_id, path }) => {
                        // Legacy single-shot: write full file in one SFTP call.
                        let resp = match sftp.write(&path, &data).await {
                            Ok(_) => ok_json(req_id, serde_json::json!({})),
                            Err(e) => err_json(req_id, e),
                        };
                        let _ = sink.send(Message::Text(resp)).await;
                    }
                    Some(PendingBinary::WriteChunk { req_id, handle }) => {
                        // Streaming chunk: append to the session buffer.
                        // Enforce the 200 MiB cap as an aggregate across every
                        // open write session, so N concurrent write_open handles
                        // cannot multiply the server's buffer commitment.
                        match write_sessions.get_mut(&handle) {
                            Some(session) => {
                                if total_buffered.saturating_add(data.len()) > MAX_STREAM_BUFFER {
                                    let _ = sink.send(Message::Text(err_json(req_id, "stream buffer limit exceeded"))).await;
                                } else {
                                    session.buffer.extend_from_slice(&data);
                                    total_buffered = total_buffered.saturating_add(data.len());
                                    let _ = sink.send(Message::Text(ok_json(req_id, serde_json::json!({})))).await;
                                }
                            }
                            None => {
                                let _ = sink.send(Message::Text(err_json(req_id, "unknown write handle"))).await;
                            }
                        }
                    }
                    None => {} // Unexpected binary frame — ignore silently
                }
            }

            Message::Close(_) => {
                return Ok(SessionStats {
                    bytes_up,
                    bytes_down,
                    close_reason: "client_closed",
                });
            }
            _ => {}
        }
    }
}

async fn handle_text_command(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    sftp: &SftpSession,
    req: WsRequest,
    pending_binary: &mut Option<PendingBinary>,
    write_sessions: &mut std::collections::HashMap<String, WriteSession>,
    total_buffered: &mut usize,
    bytes_down: &mut usize,
) {
    let id = req.id;
    match req.method.as_str() {
        "stat" => {
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            let resp = match sftp.metadata(&path).await {
                Ok(m) => ok_json(
                    id,
                    serde_json::json!({
                        "mtime": m.mtime.unwrap_or(0),
                        "size": m.size.unwrap_or(0),
                        "isDir": m.file_type().is_dir(),
                    }),
                ),
                Err(e) => err_json(id, e),
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "list" => {
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            let resp =
                match sftp.read_dir(&path).await {
                    Ok(entries) => {
                        let items: Vec<Value> = entries.map(|e| {
                        let m = e.metadata();
                        serde_json::json!({
                            "name": e.file_name(),
                            "path": format!("{}/{}", path.trim_end_matches('/'), e.file_name()),
                            "size": m.size.unwrap_or(0),
                            "mtime": m.mtime.unwrap_or(0),
                            "isDir": m.file_type().is_dir(),
                        })
                    }).collect();
                        ok_json(id, serde_json::json!({ "entries": items }))
                    }
                    Err(e) => err_json(id, e),
                };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "read" => {
            // Two-frame response: JSON {id, result: {size}} + binary frame
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            match sftp.read(&path).await {
                Ok(data) => {
                    // Frame 1: JSON header
                    let header = ok_json(id, serde_json::json!({ "size": data.len() }));
                    let header_len = header.len();
                    if sink.send(Message::Text(header)).await.is_err() {
                        return;
                    }
                    // D5: track the download bandwidth for stats. Previously the
                    // counter was declared immutable and never incremented, so
                    // the relay reported zero SFTP download bytes.
                    *bytes_down = bytes_down.saturating_add(header_len);
                    let data_len = data.len();
                    // Frame 2: binary data
                    let _ = sink.send(Message::Binary(data)).await;
                    *bytes_down = bytes_down.saturating_add(data_len);
                }
                Err(e) => {
                    let _ = sink.send(Message::Text(err_json(id, e))).await;
                }
            }
        }

        "write" => {
            // Legacy single-shot write: next binary frame contains full file data.
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    // SR2: drain the follow-up binary so the client sees a real error.
                    *pending_binary = Some(PendingBinary::Drain {
                        req_id: id,
                        reason: "missing path",
                    });
                    return;
                }
            };
            *pending_binary = Some(PendingBinary::Write { req_id: id, path });
            // No response yet — sent after binary frame arrives.
        }

        // ── Streaming write verbs (relay_version >= 2) ──────────────────────

        "write_open" => {
            // Open a new streaming write session. Returns a handle ID.
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            // D13: handle IDs are random, not a process-global sequential
            // counter. Sequential handles leaked aggregate session volume
            // ("wh24017") across sessions and made client-side bugs that
            // reused a leftover handle from another connection very noisy;
            // a random 128-bit handle is effectively unguessable and carries
            // no cross-session information.
            let mut rand_bytes = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
            let handle = format!(
                "wh-{}",
                rand_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            write_sessions.insert(handle.clone(), WriteSession { path, buffer: Vec::new() });
            let _ = sink.send(Message::Text(ok_json(id, serde_json::json!({ "handle": handle })))).await;
        }

        "write_chunk" => {
            // Expect the next binary frame to be the chunk data for this handle.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    // SR2: the protocol still delivers a binary frame after
                    // this JSON command; mark it to be drained so the client
                    // gets a real error instead of a silent drop.
                    *pending_binary = Some(PendingBinary::Drain {
                        req_id: id,
                        reason: "missing handle",
                    });
                    return;
                }
            };
            if !write_sessions.contains_key(&handle) {
                *pending_binary = Some(PendingBinary::Drain {
                    req_id: id,
                    reason: "unknown write handle",
                });
                return;
            }
            *pending_binary = Some(PendingBinary::WriteChunk { req_id: id, handle });
            // No response yet — sent after binary frame arrives.
        }

        "write_close" => {
            // Flush the accumulated buffer to SFTP and remove the session.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing handle"))).await;
                    return;
                }
            };
            let session = match write_sessions.remove(&handle) {
                Some(s) => s,
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "unknown write handle"))).await;
                    return;
                }
            };
            *total_buffered = total_buffered.saturating_sub(session.buffer.len());
            let resp = match sftp.write(&session.path, &session.buffer).await {
                Ok(_) => ok_json(id, serde_json::json!({})),
                Err(e) => err_json(id, e),
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "write_abort" => {
            // Discard the session buffer — no SFTP call needed.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing handle"))).await;
                    return;
                }
            };
            if let Some(session) = write_sessions.remove(&handle) {
                *total_buffered = total_buffered.saturating_sub(session.buffer.len());
            }
            let _ = sink.send(Message::Text(ok_json(id, serde_json::json!({})))).await;
        }

        "mkdir" => {
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            let resp = match sftp.create_dir(&path).await {
                Ok(_) => ok_json(id, serde_json::json!({})),
                Err(e) => err_json(id, e),
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "delete" => {
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            // Try file first, then directory (SftpProvider.delete uses same for both)
            let resp = match sftp.remove_file(&path).await {
                Ok(_) => ok_json(id, serde_json::json!({})),
                Err(_) => match sftp.remove_dir(&path).await {
                    Ok(_) => ok_json(id, serde_json::json!({})),
                    Err(e) => err_json(id, e),
                },
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "rename" => {
            // D3: SPEC-BYO §BYO Relay Server names these params `from`/`to`.
            // We also accept the legacy `oldPath`/`newPath` keys that prior
            // builds used, so a rolling upgrade (server first, then client)
            // doesn't break sessions in flight.
            let old = match param_str(&req.params, "from")
                .or_else(|| param_str(&req.params, "oldPath"))
            {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing from")))
                        .await;
                    return;
                }
            };
            let new = match param_str(&req.params, "to")
                .or_else(|| param_str(&req.params, "newPath"))
            {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing to")))
                        .await;
                    return;
                }
            };
            let resp = match sftp.rename(&old, &new).await {
                Ok(_) => ok_json(id, serde_json::json!({})),
                Err(e) => err_json(id, e),
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        _ => {
            let _ = sink
                .send(Message::Text(err_json(id, "unknown method")))
                .await;
        }
    }
}

// ── Auth helpers ────────────────────────────────────────────────────────────────

enum Credential {
    Password(String),
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

struct AuthParams {
    id: u32,
    username: String,
    credential: Credential,
}

fn parse_auth(msg: Message) -> Result<AuthParams, SftpRelayError> {
    let text = match msg {
        Message::Text(t) => t,
        _ => return Err(SftpRelayError::UnexpectedMessage),
    };
    let req: WsRequest =
        serde_json::from_str(&text).map_err(|_| SftpRelayError::UnexpectedMessage)?;
    if req.method != "auth" {
        return Err(SftpRelayError::UnexpectedMessage);
    }

    let username = param_str(&req.params, "username")
        .ok_or(SftpRelayError::SshAuth)?
        .to_string();

    let credential = match param_str(&req.params, "type").unwrap_or("password") {
        "password" => {
            let pw = param_str(&req.params, "password")
                .ok_or(SftpRelayError::SshAuth)?
                .to_string();
            Credential::Password(pw)
        }
        "publickey" => {
            let pem = param_str(&req.params, "privateKey")
                .ok_or(SftpRelayError::SshAuth)?
                .to_string();
            let passphrase = param_str(&req.params, "passphrase").map(|s| s.to_string());
            Credential::PrivateKey { pem, passphrase }
        }
        _ => return Err(SftpRelayError::SshAuth),
    };

    Ok(AuthParams {
        id: req.id,
        username,
        credential,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ws::Message;

    fn text_msg(s: &str) -> Message {
        Message::Text(s.to_owned())
    }

    #[test]
    fn parse_auth_password_ok() {
        let msg = text_msg(r#"{"id":1,"method":"auth","params":{"username":"alice","type":"password","password":"s3cr3t"}}"#);
        let params = parse_auth(msg).unwrap();
        assert_eq!(params.id, 1);
        assert_eq!(params.username, "alice");
        assert!(matches!(params.credential, Credential::Password(pw) if pw == "s3cr3t"));
    }

    #[test]
    fn parse_auth_publickey_ok() {
        let msg = text_msg(r#"{"id":2,"method":"auth","params":{"username":"bob","type":"publickey","privateKey":"---KEY---","passphrase":"mypp"}}"#);
        let params = parse_auth(msg).unwrap();
        assert_eq!(params.id, 2);
        assert_eq!(params.username, "bob");
        match params.credential {
            Credential::PrivateKey { pem, passphrase } => {
                assert_eq!(pem, "---KEY---");
                assert_eq!(passphrase, Some("mypp".to_string()));
            }
            _ => panic!("expected PrivateKey"),
        }
    }

    #[test]
    fn parse_auth_publickey_no_passphrase() {
        let msg = text_msg(r#"{"id":3,"method":"auth","params":{"username":"carol","type":"publickey","privateKey":"---KEY---"}}"#);
        let params = parse_auth(msg).unwrap();
        match params.credential {
            Credential::PrivateKey { passphrase, .. } => assert!(passphrase.is_none()),
            _ => panic!("expected PrivateKey"),
        }
    }

    #[test]
    fn parse_auth_password_default_type() {
        // No "type" field — defaults to password
        let msg = text_msg(r#"{"id":4,"method":"auth","params":{"username":"dave","password":"pw"}}"#);
        let params = parse_auth(msg).unwrap();
        assert!(matches!(params.credential, Credential::Password(_)));
    }

    #[test]
    fn parse_auth_missing_username_is_error() {
        let msg = text_msg(r#"{"id":5,"method":"auth","params":{"type":"password","password":"pw"}}"#);
        assert!(matches!(parse_auth(msg), Err(SftpRelayError::SshAuth)));
    }

    #[test]
    fn parse_auth_non_text_message_is_error() {
        let msg = Message::Binary(b"not text".to_vec());
        assert!(matches!(
            parse_auth(msg),
            Err(SftpRelayError::UnexpectedMessage)
        ));
    }

    #[test]
    fn parse_auth_wrong_method_is_error() {
        let msg = text_msg(r#"{"id":6,"method":"stat","params":{"path":"/tmp"}}"#);
        assert!(matches!(
            parse_auth(msg),
            Err(SftpRelayError::UnexpectedMessage)
        ));
    }

    #[test]
    fn parse_auth_unknown_type_is_error() {
        let msg = text_msg(r#"{"id":7,"method":"auth","params":{"username":"eve","type":"kerberos"}}"#);
        assert!(matches!(parse_auth(msg), Err(SftpRelayError::SshAuth)));
    }

    #[test]
    fn relay_version_constant_is_two() {
        assert_eq!(RELAY_PROTOCOL_VERSION, 2);
    }

    #[test]
    fn host_key_frame_includes_relay_version() {
        let frame = serde_json::json!({
            "type": "host_key",
            "fingerprint": "SHA256:abc",
            "relay_version": RELAY_PROTOCOL_VERSION,
        });
        assert_eq!(frame["relay_version"], 2);
    }

    #[test]
    fn parse_write_open_params() {
        // Verify that param_str correctly extracts path from write_open params
        let params = serde_json::json!({ "path": "/tmp/upload.tmp" });
        assert_eq!(param_str(&params, "path"), Some("/tmp/upload.tmp"));
    }

    #[test]
    fn parse_write_chunk_params() {
        let params = serde_json::json!({ "handle": "wh42" });
        assert_eq!(param_str(&params, "handle"), Some("wh42"));
    }

    #[test]
    fn parse_write_close_params() {
        let params = serde_json::json!({ "handle": "wh1" });
        assert_eq!(param_str(&params, "handle"), Some("wh1"));
    }

    #[test]
    fn max_stream_buffer_is_larger_than_max_frame() {
        assert!(MAX_STREAM_BUFFER > MAX_BINARY_FRAME);
        assert_eq!(MAX_STREAM_BUFFER, 200 * 1024 * 1024);
        assert_eq!(MAX_BINARY_FRAME, 16 * 1024 * 1024);
    }

    #[test]
    fn ssh_banner_accepted_for_valid_ssh2() {
        assert!(is_ssh_banner(b"SSH-2.0-OpenSSH_9.0\r\n"));
        assert!(is_ssh_banner(b"SSH-2.0-PuTTY_Release_0.79\r\n"));
    }

    #[test]
    fn ssh_banner_accepted_for_ssh199() {
        assert!(is_ssh_banner(b"SSH-1.99-OpenSSH_8.4\r\n"));
    }

    #[test]
    fn ssh_banner_rejected_for_non_ssh() {
        assert!(!is_ssh_banner(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_ssh_banner(b"220 mail.example.com ESMTP Postfix\r\n"));
        assert!(!is_ssh_banner(b"+PONG\r\n"));
        assert!(!is_ssh_banner(b"\x00\x01\x02\x03"));
        assert!(!is_ssh_banner(b""));
    }
}

async fn auth_pubkey(
    ssh: &mut Handle<CapturingKeyHandler>,
    username: &str,
    pem: &str,
    passphrase: Option<&str>,
) -> Result<bool, SftpRelayError> {
    let key = if let Some(pp) = passphrase {
        PrivateKey::from_openssh(pem.as_bytes())
            .map_err(|_| SftpRelayError::SshAuth)?
            .decrypt(pp)
            .map_err(|_| SftpRelayError::SshAuth)?
    } else {
        PrivateKey::from_openssh(pem.as_bytes()).map_err(|_| SftpRelayError::SshAuth)?
    };

    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);

    let result = ssh
        .authenticate_publickey(username, key_with_alg)
        .await
        .map_err(|e| SftpRelayError::SshConnect(e.to_string()))?;

    Ok(result.success())
}
