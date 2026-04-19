use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::errors::RelayError;

/// Channel ID: 16 random bytes from the QR code payload.
pub type ChannelId = [u8; 16];

/// Max 2 clients per channel (enrollment is always a pair).
const MAX_CLIENTS: usize = 2;
/// Channels expire after 3 minutes idle (reduced from 10 min to limit tunnel abuse).
const CHANNEL_IDLE_TTL: Duration = Duration::from_secs(180);
/// TTL sweeper runs every 30 seconds.
const SWEEPER_INTERVAL: Duration = Duration::from_secs(30);
/// Max WebSocket message size: 1 KB.
/// Shard envelope = 92 bytes, public keys = 32 bytes — 1 KB is more than sufficient
/// for any legitimate enrollment message and prevents the channel from being used
/// as a general-purpose WS tunnel for large payloads.
pub const MAX_MESSAGE_BYTES: usize = 1024;
/// Max total bytes forwarded per channel lifetime: 8 KB.
/// A complete enrollment (4 messages: pkA, pkB, shard_envelope, ACK) is well under 1 KB.
/// Exceeding this cap closes the channel immediately.
const MAX_CHANNEL_BYTES: usize = 8 * 1024;

pub struct Channel {
    /// Senders for each client slot (None = slot empty).
    senders: [Option<mpsc::UnboundedSender<Message>>; MAX_CLIENTS],
    last_activity: Instant,
    /// Total bytes forwarded across this channel's lifetime.
    /// Channel is closed immediately when this exceeds MAX_CHANNEL_BYTES.
    total_bytes: usize,
}

impl Channel {
    fn new() -> Self {
        Self {
            senders: [None, None],
            last_activity: Instant::now(),
            total_bytes: 0,
        }
    }

    fn active_slots(&self) -> usize {
        self.senders.iter().filter(|s| s.is_some()).count()
    }

    fn first_empty_slot(&self) -> Option<usize> {
        self.senders.iter().position(|s| s.is_none())
    }

    fn peer_sender(&self, my_slot: usize) -> Option<&mpsc::UnboundedSender<Message>> {
        let peer_slot = 1 - my_slot; // 0↔1
        self.senders[peer_slot].as_ref()
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_idle_expired(&self) -> bool {
        self.last_activity.elapsed() > CHANNEL_IDLE_TTL
    }

    /// Add `n` bytes to the channel total.
    /// Returns true if the channel has now exceeded MAX_CHANNEL_BYTES.
    fn add_bytes(&mut self, n: usize) -> bool {
        self.total_bytes = self.total_bytes.saturating_add(n);
        self.total_bytes > MAX_CHANNEL_BYTES
    }
}

/// Thread-safe registry of enrollment relay channels.
pub struct ChannelRegistry {
    channels: RwLock<HashMap<ChannelId, Arc<std::sync::Mutex<Channel>>>>,
}

/// Type alias for the join return type to satisfy clippy::type_complexity.
type JoinResult = Result<
    (
        Arc<std::sync::Mutex<Channel>>,
        usize,
        mpsc::UnboundedReceiver<Message>,
    ),
    RelayError,
>;

impl Default for ChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
        }
    }

    /// Start the background TTL sweeper. Must be called once at startup.
    pub fn start_sweeper(registry: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEPER_INTERVAL);
            loop {
                interval.tick().await;
                registry.sweep_expired();
            }
        });
    }

    fn sweep_expired(&self) {
        let mut channels = self
            .channels
            .write()
            .expect("channel registry lock poisoned");
        channels.retain(|_, ch| {
            let ch = ch.lock().expect("channel lock poisoned");
            !ch.is_idle_expired()
        });
    }

    /// Try to join a channel. Returns (slot_index, receiver) or an error.
    ///
    /// - If channel doesn't exist: creates it, returns slot 0.
    /// - If channel has 1 client: joins as slot 1.
    /// - If channel has 2 clients: returns ChannelFull.
    pub fn join(&self, channel_id: ChannelId) -> JoinResult {
        let mut channels = self
            .channels
            .write()
            .expect("channel registry lock poisoned");
        let channel = channels
            .entry(channel_id)
            .or_insert_with(|| Arc::new(std::sync::Mutex::new(Channel::new())));
        let channel = Arc::clone(channel);

        let mut ch = channel.lock().expect("channel lock poisoned");
        let slot = ch.first_empty_slot().ok_or(RelayError::ChannelFull)?;

        let (tx, rx) = mpsc::unbounded_channel();
        ch.senders[slot] = Some(tx);
        ch.touch();

        Ok((Arc::clone(&channel), slot, rx))
    }

    /// Remove a client from a channel. If the channel becomes empty, remove it.
    pub fn leave(&self, channel_id: ChannelId, slot: usize) {
        let mut channels = self
            .channels
            .write()
            .expect("channel registry lock poisoned");
        if let Some(ch_arc) = channels.get(&channel_id) {
            let mut ch = ch_arc.lock().expect("channel lock poisoned");
            ch.senders[slot] = None;
            if ch.active_slots() == 0 {
                drop(ch);
                channels.remove(&channel_id);
            }
        }
    }
}

/// Handle a WebSocket connection for enrollment relay.
///
/// - Messages from this client are forwarded to the peer (if present).
/// - Messages from the peer arrive via `rx` and are forwarded to this WebSocket.
/// - Channel auto-expires on idle, byte cap, or when both clients disconnect.
pub async fn handle_enrollment_ws(
    ws: WebSocket,
    registry: Arc<ChannelRegistry>,
    channel_id: ChannelId,
    client_ip: std::net::IpAddr,
) {
    let (channel, slot, rx) = match registry.join(channel_id) {
        Ok(v) => v,
        Err(_) => {
            // Channel full or other error — close immediately
            let _ = ws.close().await;
            return;
        }
    };

    relay_loop(ws, registry.clone(), channel, channel_id, slot, rx, client_ip).await;
    registry.leave(channel_id, slot);
}

async fn relay_loop(
    ws: WebSocket,
    _registry: Arc<ChannelRegistry>,
    channel: Arc<std::sync::Mutex<Channel>>,
    channel_id: ChannelId,
    my_slot: usize,
    mut rx: mpsc::UnboundedReceiver<Message>,
    _client_ip: std::net::IpAddr,
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let idle_timeout = tokio::time::Duration::from_secs(CHANNEL_IDLE_TTL.as_secs());
    // Per-session bytes sent by this client (for logging).
    let mut bytes_up: usize = 0;
    // 4-byte prefix as hex — short, non-identifying, sufficient for log correlation.
    let channel_hash = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        channel_id[0], channel_id[1], channel_id[2], channel_id[3]
    );

    tracing::info!(

        channel = %channel_hash,
        slot = my_slot,
        "enrollment session started"
    );

    let close_reason = loop {
        tokio::select! {
            // Message from this client's WebSocket → forward to peer
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        let msg_len = data.len();
                        if msg_len > MAX_MESSAGE_BYTES {
                            // Oversized message — close the channel immediately.
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break "message_too_large";
                        }
                        // Check channel byte cap.
                        let cap_exceeded = {
                            let mut ch = channel.lock().expect("channel lock poisoned");
                            ch.touch();
                            ch.add_bytes(msg_len)
                        };
                        if cap_exceeded {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break "channel_byte_cap";
                        }
                        bytes_up = bytes_up.saturating_add(msg_len);
                        let ch = channel.lock().expect("channel lock poisoned");
                        if let Some(peer_tx) = ch.peer_sender(my_slot) {
                            let _ = peer_tx.send(Message::Binary(data));
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        let msg_len = text.len();
                        if msg_len > MAX_MESSAGE_BYTES {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break "message_too_large";
                        }
                        let cap_exceeded = {
                            let mut ch = channel.lock().expect("channel lock poisoned");
                            ch.touch();
                            ch.add_bytes(msg_len)
                        };
                        if cap_exceeded {
                            let _ = ws_sink.send(Message::Close(None)).await;
                            break "channel_byte_cap";
                        }
                        bytes_up = bytes_up.saturating_add(msg_len);
                        let ch = channel.lock().expect("channel lock poisoned");
                        if let Some(peer_tx) = ch.peer_sender(my_slot) {
                            let _ = peer_tx.send(Message::Text(text));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break "client_closed",
                    _ => {} // Ping/Pong handled by Axum automatically
                }
            }
            // Message from peer → forward to this client's WebSocket
            msg = rx.recv() => {
                match msg {
                    Some(m) => {
                        if ws_sink.send(m).await.is_err() {
                            break "ws_send_error";
                        }
                        channel.lock().expect("channel lock poisoned").touch();
                    }
                    None => break "peer_disconnected",
                }
            }
            // Idle timeout
            _ = tokio::time::sleep(idle_timeout) => {
                let _ = ws_sink.send(Message::Close(None)).await;
                break "idle_timeout";
            }
        }
    };

    tracing::info!(

        channel = %channel_hash,
        slot = my_slot,
        bytes_up,
        close_reason,
        "enrollment session ended"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(b: u8) -> ChannelId {
        [b; 16]
    }

    #[test]
    fn channel_join_first_client_gets_slot_0() {
        let registry = ChannelRegistry::new();
        let id = make_id(1);
        let result = registry.join(id);
        assert!(result.is_ok());
        let (_ch, slot, _rx) = result.unwrap();
        assert_eq!(slot, 0);
    }

    #[test]
    fn channel_join_second_client_gets_slot_1() {
        let registry = ChannelRegistry::new();
        let id = make_id(2);
        let (_ch, _slot, _rx) = registry.join(id).unwrap();
        let result = registry.join(id);
        assert!(result.is_ok());
        let (_ch, slot, _rx) = result.unwrap();
        assert_eq!(slot, 1);
    }

    #[test]
    fn channel_full_after_two_clients() {
        let registry = ChannelRegistry::new();
        let id = make_id(3);
        registry.join(id).unwrap();
        registry.join(id).unwrap();
        let result = registry.join(id);
        assert!(matches!(result, Err(RelayError::ChannelFull)));
    }

    #[test]
    fn channel_removed_when_both_leave() {
        let registry = ChannelRegistry::new();
        let id = make_id(4);
        registry.join(id).unwrap();
        registry.join(id).unwrap();
        registry.leave(id, 0);
        registry.leave(id, 1);
        // Channel should be gone — a new join should get slot 0 again
        let result = registry.join(id);
        assert!(result.is_ok());
        let (_, slot, _) = result.unwrap();
        assert_eq!(slot, 0);
    }

    #[test]
    fn different_channels_independent() {
        let registry = ChannelRegistry::new();
        let id_a = make_id(5);
        let id_b = make_id(6);
        // Fill channel A
        registry.join(id_a).unwrap();
        registry.join(id_a).unwrap();
        // Channel B is unaffected
        let result = registry.join(id_b);
        assert!(result.is_ok());
    }

    #[test]
    fn sweep_removes_idle_channels() {
        let registry = ChannelRegistry::new();
        let id = make_id(7);
        {
            let mut channels = registry.channels.write().unwrap();
            let mut ch = Channel::new();
            // Backdate last_activity to simulate idle timeout
            ch.last_activity = Instant::now() - Duration::from_secs(700);
            channels.insert(id, Arc::new(std::sync::Mutex::new(ch)));
        }
        registry.sweep_expired();
        // Channel should be removed
        let result = registry.join(id);
        let (_, slot, _) = result.unwrap();
        assert_eq!(slot, 0); // New channel, slot 0
    }
}
