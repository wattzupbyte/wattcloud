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
use rand::Rng;
use russh::client::{self, Config as SshConfig, Handle};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};

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
/// Per-chunk size for streaming reads. Matches PROGRESS_CHUNK on the client
/// side so progress cadence and SFTP read buffer are aligned.
const READ_CHUNK_SIZE: usize = 256 * 1024;
/// Maximum concurrent open read-streaming sessions per WebSocket connection.
/// Caps relay memory (each holds a small russh_sftp File handle) and prevents
/// handle-exhaustion attacks against the SSH server.
const MAX_READ_SESSIONS: usize = 8;
/// Protocol version advertised in the `host_key` frame.
/// Clients use this to decide whether to use the streaming write verbs.
///
/// Version history:
///   1 — initial (write = single-shot two-frame)
///   2 — adds write_open / write_chunk / write_close / write_abort
///   3 — adds read_open / read_chunk / read_close (streaming download)
const RELAY_PROTOCOL_VERSION: u32 = 3;

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

/// Tag a `Message` variant by name for diagnostic logs. The default
/// `{:?}` for `Message` would include payload bytes which we do NOT want
/// in logs (could be ciphertext fragments or credentials mid-frame).
fn ws_variant_name(m: &Message) -> &'static str {
    match m {
        Message::Text(_) => "text",
        Message::Binary(_) => "binary",
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::Close(_) => "close",
    }
}

/// Read the next `Message::Text` or `Message::Close` from the stream,
/// transparently skipping any WS-level `Ping`/`Pong` keepalive frames,
/// AND sending a server-side `Ping` every `KEEPALIVE_PING_INTERVAL`
/// while waiting. The overall `timeout_dur` budget is honored across
/// ping sends and Ping/Pong skips — neither resets the clock.
///
/// Why the ping: during the pre-auth TOFU wait the relay holds the WS
/// idle for up to 30 seconds while the human clicks Accept. Cellular
/// NAT and mobile-browser-tab-background timers can silently RST the
/// TCP during that window (observed as tungstenite "Connection reset
/// without closing handshake"). A ~10 s server-ping prods NAT middle
/// boxes, keeps the connection accounted-for by mobile OSes, and lets
/// us detect a dead peer sooner than tungstenite's own read timeout.
async fn recv_text_or_close(
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    timeout_dur: Duration,
    step: &'static str,
) -> Result<Message, SftpRelayError> {
    const KEEPALIVE_PING_INTERVAL: Duration = Duration::from_secs(10);
    let deadline = Instant::now() + timeout_dur;
    let mut next_ping = Instant::now() + KEEPALIVE_PING_INTERVAL;
    loop {
        let wake_at = deadline.min(next_ping);
        let recv_outcome = timeout_at(wake_at, stream.next()).await;
        match recv_outcome {
            Err(_) => {
                // timeout_at elapsed — either we hit the hard deadline or
                // it's time to send a keepalive ping.
                let now = Instant::now();
                if now >= deadline {
                    return Err(SftpRelayError::Timeout);
                }
                if let Err(e) = sink.send(Message::Ping(Vec::new())).await {
                    // Ping send failure usually means the peer is already
                    // gone; don't bail here, let the next stream.next()
                    // surface the terminal error with full context.
                    tracing::debug!(step, error = %e, "ws ping send failed");
                }
                next_ping = now + KEEPALIVE_PING_INTERVAL;
            }
            Ok(None) => {
                tracing::debug!(step, "ws stream closed before frame arrived");
                return Err(SftpRelayError::HostKeyRejected);
            }
            Ok(Some(Err(e))) => {
                tracing::warn!(step, error = %e, "ws read error");
                return Err(SftpRelayError::UnexpectedMessage);
            }
            Ok(Some(Ok(msg))) => match msg {
                Message::Ping(_) | Message::Pong(_) => {
                    tracing::debug!(
                        step,
                        variant = ws_variant_name(&msg),
                        "ignoring ws keepalive frame"
                    );
                    continue;
                }
                Message::Text(_) | Message::Close(_) => return Ok(msg),
                other => {
                    tracing::warn!(
                        step,
                        variant = ws_variant_name(&other),
                        "unexpected ws message variant during setup"
                    );
                    return Err(SftpRelayError::UnexpectedMessage);
                }
            },
        }
    }
}

fn param_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

/// SR8: create-or-truncate write helper. Replaces `SftpSession::write` (which
/// opens with `OpenFlags::WRITE` only — compliant servers reject writes to a
/// path that doesn't exist because CREATE isn't set). Uploads always target a
/// new temp file, so CREATE | WRITE | TRUNCATE is the right flag set.
async fn sftp_write_file(
    sftp: &SftpSession,
    path: &str,
    data: &[u8],
) -> Result<(), russh_sftp::client::error::Error> {
    let mut file = sftp
        .open_with_flags(
            path,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
        )
        .await?;
    file.write_all(data).await?;
    file.shutdown().await.ok();
    Ok(())
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
    let captured_fp: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    // russh 0.60's default `GexParams` requires a 3072-bit DH group, which
    // rejects real-world providers (Hetzner Storage Box, etc.) that advertise
    // a 2048-bit group during `diffie-hellman-group-exchange-sha256`. Drop
    // the floor to 2048 (matching RFC 8270) — Wattcloud's files are already
    // AES-256-GCM encrypted client-side (ZK-5), so SSH transport only
    // protects metadata ops; 2048-bit DH is acceptable here.
    let mut ssh_config = SshConfig::default();
    if let Ok(gex) = russh::client::GexParams::new(2048, 4096, 8192) {
        ssh_config.gex = gex;
    }
    // Send SSH keepalives every 15s; close after 4 unanswered. Without this,
    // providers like Hetzner Storage Box silently drop idle SSH connections
    // during long client-side work (e.g. Argon2 rewrap on recovery), and the
    // next SFTP packet disappears into a void until russh-sftp's own timeout
    // fires with "Timeout".
    ssh_config.keepalive_interval = Some(Duration::from_secs(15));
    ssh_config.keepalive_max = 4;
    let config = Arc::new(ssh_config);
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
    .map_err(|e| {
        tracing::warn!(step = "send_host_key", error = %e, "ws send failed");
        SftpRelayError::UnexpectedMessage
    })?;

    // Step 3: Wait for host_key_accepted (30 s). Credentials must not arrive
    // first. Ignore Ping/Pong keepalive frames — anything else is terminal.
    let ack = recv_text_or_close(
        &mut stream,
        &mut sink,
        Duration::from_secs(30),
        "host_key_ack",
    )
    .await?;

    match ack {
        Message::Text(t) => {
            let v: serde_json::Value = serde_json::from_str(&t).map_err(|e| {
                tracing::warn!(step = "host_key_ack", error = %e, body = %t, "malformed JSON");
                SftpRelayError::UnexpectedMessage
            })?;
            if v.get("type").and_then(|t| t.as_str()) != Some("host_key_accepted") {
                return Err(SftpRelayError::HostKeyRejected);
            }
        }
        Message::Close(_) => return Err(SftpRelayError::HostKeyRejected),
        _ => unreachable!("recv_text_or_close only returns Text or Close"),
    }

    // Step 4: Read auth message (credentials only arrive after TOFU is
    // confirmed). Ping/Pong tolerated; Close or WS error terminates.
    let auth_msg =
        recv_text_or_close(&mut stream, &mut sink, Duration::from_secs(30), "auth_read").await?;

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
    // russh-sftp defaults to a 10s per-packet deadline, which is too tight for
    // real-world servers — atomic rename over an existing file on Hetzner
    // Storage Boxes can take >10s after the channel has been idle (e.g.
    // during a client-side Argon2 rewrap). Lift it to 60s.
    sftp.set_timeout(60).await;

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

/// In-progress streaming read session (v3 protocol).
/// Holds a live SFTP file handle whose `AsyncRead` impl is pulled one chunk
/// per `read_chunk` request. The russh_sftp::File `Drop` impl closes the
/// remote handle on tokio runtime, so a client that disconnects mid-stream
/// (or forgets `read_close`) still releases the server-side resource.
struct ReadSession {
    file: russh_sftp::client::fs::File,
    path: String,
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
    let mut write_sessions: std::collections::HashMap<String, WriteSession> =
        std::collections::HashMap::new();
    // Per-connection read-session map. Each entry holds a live SFTP file
    // handle; dropping the map (connection close) runs the russh_sftp File
    // Drop impl and spawns handle close on the runtime.
    let mut read_sessions: std::collections::HashMap<String, ReadSession> =
        std::collections::HashMap::new();
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
                    &mut read_sessions,
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
                        let _ = sink
                            .send(Message::Text(err_json(req_id, "payload too large")))
                            .await;
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
                        // SR8: russh-sftp 2.1.1's `.write()` convenience opens
                        // with `OpenFlags::WRITE` only, so the SSH server
                        // replies `SSH_FX_NO_SUCH_FILE` for any non-existing
                        // target. Explicitly `CREATE | WRITE | TRUNCATE` is
                        // the semantics callers actually want.
                        let resp = match sftp_write_file(sftp, &path, &data).await {
                            Ok(_) => ok_json(req_id, serde_json::json!({})),
                            Err(e) => {
                                tracing::warn!(path = %path, error = %e, "sftp single-shot write failed");
                                err_json(req_id, format!("write to {path}: {e}"))
                            }
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
                                    let _ = sink
                                        .send(Message::Text(err_json(
                                            req_id,
                                            "stream buffer limit exceeded",
                                        )))
                                        .await;
                                } else {
                                    session.buffer.extend_from_slice(&data);
                                    total_buffered = total_buffered.saturating_add(data.len());
                                    let _ = sink
                                        .send(Message::Text(ok_json(req_id, serde_json::json!({}))))
                                        .await;
                                }
                            }
                            None => {
                                let _ = sink
                                    .send(Message::Text(err_json(req_id, "unknown write handle")))
                                    .await;
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

#[allow(clippy::too_many_arguments)]
async fn handle_text_command(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    sftp: &SftpSession,
    req: WsRequest,
    pending_binary: &mut Option<PendingBinary>,
    write_sessions: &mut std::collections::HashMap<String, WriteSession>,
    read_sessions: &mut std::collections::HashMap<String, ReadSession>,
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
                Ok(m) => {
                    tracing::debug!(path = %path, is_dir = m.file_type().is_dir(), size = m.size.unwrap_or(0), "sftp stat ok");
                    ok_json(
                        id,
                        serde_json::json!({
                            "mtime": m.mtime.unwrap_or(0),
                            "size": m.size.unwrap_or(0),
                            "isDir": m.file_type().is_dir(),
                        }),
                    )
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "sftp stat failed");
                    err_json(id, e)
                }
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "fs_info" => {
            // RFC-less disk-space query via the `statvfs@openssh.com` SFTP
            // extension. Returns `{ supported: false }` when the server
            // doesn't advertise the extension (non-OpenSSH) so the client
            // can skip the quota gate without treating it as an error.
            let path = param_str(&req.params, "path")
                .map(|p| p.to_string())
                .unwrap_or_else(|| "/".to_string());
            let resp = match sftp.fs_info(path.clone()).await {
                Ok(Some(s)) => {
                    let free = s.blocks_avail.saturating_mul(s.fragment_size);
                    let total = s.blocks.saturating_mul(s.fragment_size);
                    ok_json(
                        id,
                        serde_json::json!({
                            "supported": true,
                            "freeBytes": free,
                            "totalBytes": total,
                        }),
                    )
                }
                Ok(None) => ok_json(id, serde_json::json!({ "supported": false })),
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "sftp fs_info failed");
                    // Wire errors are indistinguishable from "unsupported" to
                    // the client — same outcome (skip the gate), clearer logs.
                    ok_json(
                        id,
                        serde_json::json!({ "supported": false, "reason": e.to_string() }),
                    )
                }
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
            rand::rng().fill_bytes(&mut rand_bytes);
            let handle = format!(
                "wh-{}",
                rand_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            write_sessions.insert(
                handle.clone(),
                WriteSession {
                    path,
                    buffer: Vec::new(),
                },
            );
            let _ = sink
                .send(Message::Text(ok_json(
                    id,
                    serde_json::json!({ "handle": handle }),
                )))
                .await;
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
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing handle")))
                        .await;
                    return;
                }
            };
            let session = match write_sessions.remove(&handle) {
                Some(s) => s,
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "unknown write handle")))
                        .await;
                    return;
                }
            };
            *total_buffered = total_buffered.saturating_sub(session.buffer.len());
            let write_path = session.path.clone();
            // See SR8 above: russh-sftp's `.write()` omits CREATE, so upload
            // of a new file always fails with NoSuchFile on compliant servers
            // (e.g. Hetzner Storage Box). Use explicit CREATE|WRITE|TRUNCATE.
            let resp = match sftp_write_file(sftp, &session.path, &session.buffer).await {
                Ok(_) => ok_json(id, serde_json::json!({})),
                Err(e) => {
                    tracing::warn!(
                        path = %write_path,
                        buffer_len = session.buffer.len(),
                        error = %e,
                        "sftp write_close failed",
                    );
                    err_json(id, format!("write to {write_path}: {e}"))
                }
            };
            let _ = sink.send(Message::Text(resp)).await;
        }

        "write_abort" => {
            // Discard the session buffer — no SFTP call needed.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing handle")))
                        .await;
                    return;
                }
            };
            if let Some(session) = write_sessions.remove(&handle) {
                *total_buffered = total_buffered.saturating_sub(session.buffer.len());
            }
            let _ = sink
                .send(Message::Text(ok_json(id, serde_json::json!({}))))
                .await;
        }

        // ── Streaming read verbs (relay_version >= 3) ───────────────────────
        "read_open" => {
            // Open an SFTP file for streaming reads. Returns an opaque handle.
            let path = match param_str(&req.params, "path") {
                Some(p) => p.to_string(),
                None => {
                    let _ = sink.send(Message::Text(err_json(id, "missing path"))).await;
                    return;
                }
            };
            if read_sessions.len() >= MAX_READ_SESSIONS {
                let _ = sink
                    .send(Message::Text(err_json(id, "too many open read sessions")))
                    .await;
                return;
            }
            let file = match sftp.open_with_flags(&path, OpenFlags::READ).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "sftp read_open failed");
                    // Plain russh-sftp error — sdk-core's read_open wrapper
                    // adds the "read_open {path}: " prefix once. Pre-existing
                    // double prefix here is what produced the duplicated
                    // "read_open /x: read_open /x: …" the user reported.
                    let _ = sink.send(Message::Text(err_json(id, e))).await;
                    return;
                }
            };
            // Random 128-bit handle ID — same rationale as write handles
            // (D13): unguessable, no cross-session information leak.
            let mut rand_bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut rand_bytes);
            let handle = format!(
                "rh-{}",
                rand_bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            read_sessions.insert(handle.clone(), ReadSession { file, path });
            let _ = sink
                .send(Message::Text(ok_json(
                    id,
                    serde_json::json!({ "handle": handle }),
                )))
                .await;
        }

        "read_chunk" => {
            // Pull the next chunk. Two-frame response: JSON header +
            // binary frame. An empty binary frame signals EOF.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing handle")))
                        .await;
                    return;
                }
            };
            let session = match read_sessions.get_mut(&handle) {
                Some(s) => s,
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "unknown read handle")))
                        .await;
                    return;
                }
            };
            let mut buf = vec![0u8; READ_CHUNK_SIZE];
            let n = match session.file.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        path = %session.path,
                        handle = %handle,
                        error = %e,
                        "sftp read_chunk failed"
                    );
                    // sdk-core's read_chunk wrapper adds the verb+handle
                    // prefix; emit the plain russh-sftp error here so we
                    // don't double-prefix.
                    let _ = sink.send(Message::Text(err_json(id, e))).await;
                    // Drop the session on read error — caller should reopen.
                    read_sessions.remove(&handle);
                    return;
                }
            };
            buf.truncate(n);
            let header = ok_json(id, serde_json::json!({ "size": n }));
            let header_len = header.len();
            if sink.send(Message::Text(header)).await.is_err() {
                return;
            }
            *bytes_down = bytes_down.saturating_add(header_len);
            let body_len = buf.len();
            // Always send the binary frame, even on EOF (empty body). The
            // client uses body length == 0 to detect EOF, so the two-frame
            // shape stays consistent.
            let _ = sink.send(Message::Binary(buf)).await;
            *bytes_down = bytes_down.saturating_add(body_len);
        }

        "read_close" => {
            // Drop the session. Idempotent — unknown handles return ok to
            // keep client cleanup paths simple.
            let handle = match param_str(&req.params, "handle") {
                Some(h) => h.to_string(),
                None => {
                    let _ = sink
                        .send(Message::Text(err_json(id, "missing handle")))
                        .await;
                    return;
                }
            };
            read_sessions.remove(&handle);
            let _ = sink
                .send(Message::Text(ok_json(id, serde_json::json!({}))))
                .await;
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
                Ok(_) => {
                    tracing::debug!(path = %path, "sftp mkdir ok");
                    ok_json(id, serde_json::json!({}))
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "sftp mkdir failed");
                    err_json(id, e)
                }
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
                    let _ = sink.send(Message::Text(err_json(id, "missing from"))).await;
                    return;
                }
            };
            let new =
                match param_str(&req.params, "to").or_else(|| param_str(&req.params, "newPath")) {
                    Some(p) => p.to_string(),
                    None => {
                        let _ = sink.send(Message::Text(err_json(id, "missing to"))).await;
                        return;
                    }
                };
            // SSH_FXP_RENAME (v3) requires the target to NOT exist. Some servers
            // (Hetzner Storage Box) also return the v4-only status 11
            // FILE_ALREADY_EXISTS which russh-sftp 2.1.1 can't parse — the reply
            // gets dropped as "Bad message" and the rename future never resolves,
            // hanging until the per-packet timeout fires. Pre-unlink the target
            // (ignore errors — it may not exist) before the rename so we never
            // exercise the replace-rename path.
            let _ = sftp.remove_file(&new).await;
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
        other => {
            tracing::warn!(
                step = "parse_auth",
                variant = ws_variant_name(&other),
                "auth msg wrong ws variant"
            );
            return Err(SftpRelayError::UnexpectedMessage);
        }
    };
    let req: WsRequest = serde_json::from_str(&text).map_err(|e| {
        tracing::warn!(step = "parse_auth", error = %e, "auth msg not JSON");
        SftpRelayError::UnexpectedMessage
    })?;
    if req.method != "auth" {
        tracing::warn!(
            step = "parse_auth",
            method = %req.method,
            "auth msg method mismatch (expected 'auth')"
        );
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

// Compile-time guard: the buffer must be strictly larger than a single frame.
// If the constants drift below this invariant, the crate won't compile.
const _: () = assert!(MAX_STREAM_BUFFER > MAX_BINARY_FRAME);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ws::Message;

    fn text_msg(s: &str) -> Message {
        Message::Text(s.to_owned())
    }

    #[test]
    fn parse_auth_password_ok() {
        let msg = text_msg(
            r#"{"id":1,"method":"auth","params":{"username":"alice","type":"password","password":"s3cr3t"}}"#,
        );
        let params = parse_auth(msg).unwrap();
        assert_eq!(params.id, 1);
        assert_eq!(params.username, "alice");
        assert!(matches!(params.credential, Credential::Password(pw) if pw == "s3cr3t"));
    }

    #[test]
    fn parse_auth_publickey_ok() {
        let msg = text_msg(
            r#"{"id":2,"method":"auth","params":{"username":"bob","type":"publickey","privateKey":"---KEY---","passphrase":"mypp"}}"#,
        );
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
        let msg = text_msg(
            r#"{"id":3,"method":"auth","params":{"username":"carol","type":"publickey","privateKey":"---KEY---"}}"#,
        );
        let params = parse_auth(msg).unwrap();
        match params.credential {
            Credential::PrivateKey { passphrase, .. } => assert!(passphrase.is_none()),
            _ => panic!("expected PrivateKey"),
        }
    }

    #[test]
    fn parse_auth_password_default_type() {
        // No "type" field — defaults to password
        let msg =
            text_msg(r#"{"id":4,"method":"auth","params":{"username":"dave","password":"pw"}}"#);
        let params = parse_auth(msg).unwrap();
        assert!(matches!(params.credential, Credential::Password(_)));
    }

    #[test]
    fn parse_auth_missing_username_is_error() {
        let msg =
            text_msg(r#"{"id":5,"method":"auth","params":{"type":"password","password":"pw"}}"#);
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
        let msg =
            text_msg(r#"{"id":7,"method":"auth","params":{"username":"eve","type":"kerberos"}}"#);
        assert!(matches!(parse_auth(msg), Err(SftpRelayError::SshAuth)));
    }

    #[test]
    fn relay_version_constant_is_three() {
        // v3 added streaming read verbs alongside v2's streaming writes.
        // Bump the assertion whenever RELAY_PROTOCOL_VERSION changes so
        // the tests document the wire-compat expectation.
        assert_eq!(RELAY_PROTOCOL_VERSION, 3);
    }

    #[test]
    fn host_key_frame_includes_relay_version() {
        let frame = serde_json::json!({
            "type": "host_key",
            "fingerprint": "SHA256:abc",
            "relay_version": RELAY_PROTOCOL_VERSION,
        });
        assert_eq!(frame["relay_version"], 3);
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
        // The strict-inequality invariant is enforced as a compile-time
        // assertion above `mod tests`. Here we lock in the concrete numbers
        // so a change to either constant has to update this test too.
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
