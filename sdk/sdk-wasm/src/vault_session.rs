//! In-WASM vault session registry.
//!
//! Key material (vault_key, client_kek_half, kek) lives inside WASM heap.
//! The JS side receives only an opaque u32 session ID. Sessions implement
//! ZeroizeOnDrop; removing from the registry wipes keys from memory.
//!
//! WASM is single-threaded, so `thread_local! + RefCell` is safe and avoids
//! Mutex overhead. The AtomicU32 counter survives across reloads within the
//! same WASM module lifetime.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use sdk_core::crypto::zeroize_utils::SymmetricKey;
use zeroize::ZeroizeOnDrop;

/// All key material for one open vault.
#[derive(ZeroizeOnDrop)]
pub struct VaultSession {
    /// AES-256-GCM key protecting the vault body and header HMAC.
    pub vault_key: SymmetricKey,
    /// The client half of the KEK — combined with the server shard via HKDF to
    /// produce the full KEK used to wrap/unwrap private keys.
    pub client_kek_half: SymmetricKey,
    /// Full BYO KEK — populated by `byo_vault_derive_kek` after the shard arrives.
    pub kek: Option<SymmetricKey>,
}

thread_local! {
    static VAULT_SESSIONS: RefCell<HashMap<u32, VaultSession>> = RefCell::new(HashMap::new());
}

static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Store a new vault session. Returns an opaque session ID that the caller
/// passes back for every subsequent vault operation.
pub fn store_vault_session(session: VaultSession) -> u32 {
    let id = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    VAULT_SESSIONS.with(|s| s.borrow_mut().insert(id, session));
    id
}

/// Run a closure with an immutable borrow of the session.
/// Returns `None` if the session ID is unknown.
pub fn with_vault_session<T>(id: u32, f: impl FnOnce(&VaultSession) -> T) -> Option<T> {
    VAULT_SESSIONS.with(|s| s.borrow().get(&id).map(f))
}

/// Run a closure with a mutable borrow of the session.
/// Returns `None` if the session ID is unknown.
pub fn with_vault_session_mut<T>(id: u32, f: impl FnOnce(&mut VaultSession) -> T) -> Option<T> {
    VAULT_SESSIONS.with(|s| s.borrow_mut().get_mut(&id).map(f))
}

/// Remove and zeroize the session. ZeroizeOnDrop fires when the value is dropped.
pub fn close_vault_session(id: u32) {
    VAULT_SESSIONS.with(|s| s.borrow_mut().remove(&id));
}
