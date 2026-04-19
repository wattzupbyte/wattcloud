//! In-WASM enrollment session registry.
//!
//! Stores ephemeral X25519 secret key and derived enc_key/mac_key inside WASM
//! heap. The JS side receives only an opaque u32 session ID. Sessions implement
//! ZeroizeOnDrop; removing from the registry wipes keys from memory.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use sdk_core::crypto::zeroize_utils::{SymmetricKey, X25519SecretKey};
use zeroize::ZeroizeOnDrop;

/// All ephemeral key material for one enrollment channel.
#[derive(ZeroizeOnDrop)]
pub struct WasmEnrollmentSession {
    /// Ephemeral X25519 secret key — taken by `byo_enrollment_derive_keys`.
    pub eph_sk: Option<X25519SecretKey>,
    /// 16-byte channel ID — bound into HKDF for key derivation.
    pub channel_id: [u8; 16],
    /// AES-256-GCM key for shard transfer — populated by `byo_enrollment_derive_keys`.
    pub enc_key: Option<SymmetricKey>,
    /// HMAC-SHA256 key for shard transfer — populated by `byo_enrollment_derive_keys`.
    pub mac_key: Option<SymmetricKey>,
    /// Decrypted shard bytes — stored here after `byo_enrollment_session_decrypt_shard`,
    /// consumed (and zeroed) by `byo_enrollment_session_get_shard`.
    pub received_shard: Option<Vec<u8>>,
}

thread_local! {
    static ENROLLMENT_SESSIONS: RefCell<HashMap<u32, WasmEnrollmentSession>> =
        RefCell::new(HashMap::new());
}

static ENROLLMENT_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Store a new enrollment session. Returns an opaque session ID.
pub fn store_enrollment_session(session: WasmEnrollmentSession) -> u32 {
    let id = ENROLLMENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    ENROLLMENT_SESSIONS.with(|s| s.borrow_mut().insert(id, session));
    id
}

/// Run a closure with a mutable borrow of the session. Returns `None` if unknown.
pub fn with_enrollment_session_mut<T>(
    id: u32,
    f: impl FnOnce(&mut WasmEnrollmentSession) -> T,
) -> Option<T> {
    ENROLLMENT_SESSIONS.with(|s| s.borrow_mut().get_mut(&id).map(f))
}

/// Remove and zeroize the session. ZeroizeOnDrop fires when the value is dropped.
pub fn close_enrollment_session(id: u32) {
    ENROLLMENT_SESSIONS.with(|s| s.borrow_mut().remove(&id));
}
