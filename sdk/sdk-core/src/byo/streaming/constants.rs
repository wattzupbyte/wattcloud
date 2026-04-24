// BYO streaming constants — single source of truth.
//
// All values are re-exported from `crypto::constants` so there is exactly one
// definition site. A compile-time assertion guards against silent drift between
// the two modules.

pub use crate::crypto::constants::{
    V7_ENCRYPT_CHUNK_SIZE, V7_FOOTER_LEN, V7_FRAME_OVERHEAD, V7_HEADER_MIN,
};

// ─── Drift guards ─────────────────────────────────────────────────────────────
//
// If any constant is ever changed in crypto::constants without updating the BYO
// streaming code, these assertions will catch the inconsistency at compile time.

const _: () = assert!(
    V7_HEADER_MIN == 1709,
    "V7 header size changed — update streaming code"
);
const _: () = assert!(
    V7_FOOTER_LEN == 32,
    "V7 footer size changed — update streaming code"
);
const _: () = assert!(
    V7_ENCRYPT_CHUNK_SIZE == 512 * 1024,
    "V7 encrypt chunk size changed"
);
