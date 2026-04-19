// BYO vault file format v2: binary header parsing and serialization.
// See crypto/constants.rs for the full binary layout specification.
//
// Format v2 (1227 bytes fixed header):
//   [0..8]      magic "SCVAULT\x00"
//   [8..10]     format_version (u16 LE) = 2
//   [10..14]    argon2_memory_kb (u32 LE)
//   [14..18]    argon2_iterations (u32 LE)
//   [18..22]    argon2_parallelism (u32 LE)
//   [22..54]    master_salt (32 bytes)
//   [54..70]    vault_id (16 bytes)
//   [70..82]    pass_wrap_iv (12 bytes)
//   [82..130]   pass_wrapped_vault_key (48 bytes)
//   [130..142]  recovery_wrap_iv (12 bytes)
//   [142..190]  recovery_wrapped_vault_key (48 bytes)
//   [190]       num_active_slots (u8)
//   [191..1191] device_slots (8 × 125 bytes)
//   [1191..1195] revocation_epoch (u32 LE)
//   [1195..1227] header_hmac (32 bytes, covers bytes[0..1195])
//
// Format v1 (839 bytes) is accepted for parsing only; the caller migrates to v2.

use crate::crypto::constants::{
    VAULT_DEVICE_SLOT_SIZE, VAULT_DEVICE_SLOT_SIZE_V1, VAULT_FORMAT_VERSION,
    VAULT_FORMAT_VERSION_V1, VAULT_HEADER_SIZE, VAULT_HEADER_SIZE_V1, VAULT_HMAC_OFFSET,
    VAULT_HMAC_OFFSET_V1, VAULT_MAGIC, VAULT_MAX_DEVICES, VAULT_REVOCATION_EPOCH_OFFSET,
};
use crate::error::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Device slot status.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SlotStatus {
    Empty = 0x00,
    Active = 0x01,
}

impl SlotStatus {
    fn from_byte(byte: u8) -> Result<Self, VaultError> {
        match byte {
            0x00 => Ok(SlotStatus::Empty),
            0x01 => Ok(SlotStatus::Active),
            _ => Err(VaultError::InvalidHeader(format!(
                "invalid slot status byte: {byte:#04x}"
            ))),
        }
    }
}

/// A single device slot (125 bytes in v2) storing an encrypted shard and
/// an optional wrapped Ed25519 signing-key seed.
///
/// **v2 layout (125 bytes):**
/// - `[0]`      status (0x00=Empty, 0x01=Active)
/// - `[1..17]`  device_id (16 random bytes per device)
/// - `[17..29]` wrap_iv (12-byte AES-GCM nonce for shard)
/// - `[29..77]` encrypted_payload (48 bytes = AES-GCM(device_crypto_key, wrap_iv, shard))
/// - `[77..125]` signing_key_wrapped (48 bytes = AES-GCM(vault_key, device_id[0:12], ed25519_seed))
///   All-zeros when no signing key has been provisioned yet.
///
/// The nonce for `signing_key_wrapped` is `device_id[0:12]` (deterministic, not stored).
/// Re-enrollment must generate a new device_id to avoid nonce reuse with the same vault_key.
///
/// `Clone` is intentionally not derived — copying wrapped key material risks a second
/// copy surviving in memory after the original is zeroized on drop.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DeviceSlot {
    #[zeroize(skip)]
    pub status: SlotStatus,
    pub device_id: [u8; 16],
    pub wrap_iv: [u8; 12],
    pub encrypted_payload: [u8; 48],
    /// Wrapped Ed25519 signing-key seed.
    /// All-zeros = no signing key provisioned (pre-migration slots or empty slots).
    pub signing_key_wrapped: [u8; 48],
}

impl DeviceSlot {
    /// Create an empty device slot (all zeros).
    pub fn empty() -> Self {
        Self {
            status: SlotStatus::Empty,
            device_id: [0u8; 16],
            wrap_iv: [0u8; 12],
            encrypted_payload: [0u8; 48],
            signing_key_wrapped: [0u8; 48],
        }
    }

    /// Create an active device slot with the given fields.
    /// `signing_key_wrapped` defaults to all-zeros if not yet provisioned.
    pub fn active(
        device_id: [u8; 16],
        wrap_iv: [u8; 12],
        encrypted_payload: [u8; 48],
    ) -> Self {
        Self {
            status: SlotStatus::Active,
            device_id,
            wrap_iv,
            encrypted_payload,
            signing_key_wrapped: [0u8; 48],
        }
    }

    /// Create an active slot with all fields including the signing key.
    pub fn active_with_signing_key(
        device_id: [u8; 16],
        wrap_iv: [u8; 12],
        encrypted_payload: [u8; 48],
        signing_key_wrapped: [u8; 48],
    ) -> Self {
        Self {
            status: SlotStatus::Active,
            device_id,
            wrap_iv,
            encrypted_payload,
            signing_key_wrapped,
        }
    }

    /// Returns true if this slot has a signing key provisioned.
    pub fn has_signing_key(&self) -> bool {
        self.signing_key_wrapped != [0u8; 48]
    }

    /// Serialize to 125 bytes (v2 format).
    pub fn to_bytes(&self) -> [u8; VAULT_DEVICE_SLOT_SIZE] {
        let mut buf = [0u8; VAULT_DEVICE_SLOT_SIZE];
        buf[0] = self.status as u8;
        buf[1..17].copy_from_slice(&self.device_id);
        buf[17..29].copy_from_slice(&self.wrap_iv);
        buf[29..77].copy_from_slice(&self.encrypted_payload);
        buf[77..125].copy_from_slice(&self.signing_key_wrapped);
        buf
    }

    /// Parse from 125 bytes (v2 format).
    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() != VAULT_DEVICE_SLOT_SIZE {
            return Err(VaultError::InvalidHeader(format!(
                "device slot must be {} bytes, got {}",
                VAULT_DEVICE_SLOT_SIZE,
                data.len()
            )));
        }
        let status = SlotStatus::from_byte(data[0])?;
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&data[1..17]);
        let mut wrap_iv = [0u8; 12];
        wrap_iv.copy_from_slice(&data[17..29]);
        let mut encrypted_payload = [0u8; 48];
        encrypted_payload.copy_from_slice(&data[29..77]);
        let mut signing_key_wrapped = [0u8; 48];
        signing_key_wrapped.copy_from_slice(&data[77..125]);
        Ok(Self {
            status,
            device_id,
            wrap_iv,
            encrypted_payload,
            signing_key_wrapped,
        })
    }

    /// Parse from 77 bytes (v1 format — migration only).
    /// Produces a slot with signing_key_wrapped = all-zeros (not yet provisioned).
    fn from_bytes_v1(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() != VAULT_DEVICE_SLOT_SIZE_V1 {
            return Err(VaultError::InvalidHeader(format!(
                "v1 device slot must be {} bytes, got {}",
                VAULT_DEVICE_SLOT_SIZE_V1,
                data.len()
            )));
        }
        let status = SlotStatus::from_byte(data[0])?;
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&data[1..17]);
        let mut wrap_iv = [0u8; 12];
        wrap_iv.copy_from_slice(&data[17..29]);
        let mut encrypted_payload = [0u8; 48];
        encrypted_payload.copy_from_slice(&data[29..77]);
        Ok(Self {
            status,
            device_id,
            wrap_iv,
            encrypted_payload,
            signing_key_wrapped: [0u8; 48],
        })
    }
}

/// Parsed BYO vault header (v2: 1227 bytes fixed).
#[derive(Debug)]
pub struct VaultHeader {
    pub format_version: u16,
    pub argon2_memory_kb: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub master_salt: [u8; 32],
    pub vault_id: [u8; 16],
    pub pass_wrap_iv: [u8; 12],
    pub pass_wrapped_vault_key: [u8; 48],
    pub recovery_wrap_iv: [u8; 12],
    pub recovery_wrapped_vault_key: [u8; 48],
    pub device_slots: [DeviceSlot; VAULT_MAX_DEVICES],
    /// Revocation epoch (v2+). Incremented on each device revocation.
    /// Journal entries with epoch < revocation_epoch from non-active devices are rejected.
    pub revocation_epoch: u32,
    pub header_hmac: [u8; 32],
}

impl VaultHeader {
    /// Parse a vault header from raw bytes.
    /// Accepts both v1 (839 bytes) and v2 (1227 bytes) formats.
    /// Returns an error for unknown versions.
    pub fn parse(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() < 10 {
            return Err(VaultError::InvalidHeader(
                "header too short to read version".to_string(),
            ));
        }

        // Verify magic
        if data.len() < 8 || data[0..8] != *VAULT_MAGIC {
            return Err(VaultError::InvalidHeader(
                "invalid vault magic bytes".to_string(),
            ));
        }

        let format_version = u16::from_le_bytes([data[8], data[9]]);
        match format_version {
            v if v == VAULT_FORMAT_VERSION => Self::parse_v2(data),
            v if v == VAULT_FORMAT_VERSION_V1 => Self::parse_v1(data),
            other => Err(VaultError::UnsupportedVersion(other)),
        }
    }

    /// Parse a v2 header (1227 bytes).
    fn parse_v2(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() < VAULT_HEADER_SIZE {
            return Err(VaultError::InvalidHeader(format!(
                "v2 header must be at least {} bytes, got {}",
                VAULT_HEADER_SIZE,
                data.len()
            )));
        }

        let format_version = u16::from_le_bytes([data[8], data[9]]);
        let argon2_memory_kb = u32::from_le_bytes(
            data[10..14]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_memory_kb parse failed".to_string()))?,
        );
        let argon2_iterations = u32::from_le_bytes(
            data[14..18]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_iterations parse failed".to_string()))?,
        );
        let argon2_parallelism = u32::from_le_bytes(
            data[18..22]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_parallelism parse failed".to_string()))?,
        );

        let mut master_salt = [0u8; 32];
        master_salt.copy_from_slice(&data[22..54]);
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&data[54..70]);
        let mut pass_wrap_iv = [0u8; 12];
        pass_wrap_iv.copy_from_slice(&data[70..82]);
        let mut pass_wrapped_vault_key = [0u8; 48];
        pass_wrapped_vault_key.copy_from_slice(&data[82..130]);
        let mut recovery_wrap_iv = [0u8; 12];
        recovery_wrap_iv.copy_from_slice(&data[130..142]);
        let mut recovery_wrapped_vault_key = [0u8; 48];
        recovery_wrapped_vault_key.copy_from_slice(&data[142..190]);

        // Parse device slots (8 × 125 bytes starting at offset 191).
        // The byte at offset 190 is the declared active-slot count; we cross-
        // check it against the actual slot statuses below (A9). The post-unwrap
        // HMAC is authoritative, but fail-fast parsing lets corruption surface
        // before any crypto work and matches the intent of the wire format.
        let declared_active_count = data[190];
        let mut device_slots_vec = Vec::with_capacity(VAULT_MAX_DEVICES);
        for i in 0..VAULT_MAX_DEVICES {
            let offset = 191 + i * VAULT_DEVICE_SLOT_SIZE;
            let slot = DeviceSlot::from_bytes(&data[offset..offset + VAULT_DEVICE_SLOT_SIZE])?;
            device_slots_vec.push(slot);
        }
        if device_slots_vec.len() != VAULT_MAX_DEVICES {
            return Err(VaultError::InvalidHeader(format!(
                "expected {VAULT_MAX_DEVICES} device slots, got {}",
                device_slots_vec.len()
            )));
        }
        let actual_active_count = device_slots_vec
            .iter()
            .filter(|s| s.status == SlotStatus::Active)
            .count() as u8;
        if declared_active_count != actual_active_count {
            return Err(VaultError::InvalidHeader(format!(
                "active_device_count byte {declared_active_count} disagrees with actual slot \
                 statuses ({actual_active_count})"
            )));
        }
        let device_slots: [DeviceSlot; VAULT_MAX_DEVICES] =
            device_slots_vec.try_into().map_err(|_: Vec<_>| {
                VaultError::InvalidHeader("device slots parse failed".to_string())
            })?;

        let revocation_epoch = u32::from_le_bytes(
            data[VAULT_REVOCATION_EPOCH_OFFSET..VAULT_REVOCATION_EPOCH_OFFSET + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("revocation_epoch parse failed".to_string()))?,
        );

        let mut header_hmac = [0u8; 32];
        header_hmac.copy_from_slice(&data[VAULT_HMAC_OFFSET..VAULT_HMAC_OFFSET + 32]);

        Ok(Self {
            format_version,
            argon2_memory_kb,
            argon2_iterations,
            argon2_parallelism,
            master_salt,
            vault_id,
            pass_wrap_iv,
            pass_wrapped_vault_key,
            recovery_wrap_iv,
            recovery_wrapped_vault_key,
            device_slots,
            revocation_epoch,
            header_hmac,
        })
    }

    /// Parse a v1 header (839 bytes) for migration purposes.
    /// The returned header has format_version=1 and revocation_epoch=0.
    /// All device slots have signing_key_wrapped = all-zeros.
    pub fn parse_v1(data: &[u8]) -> Result<Self, VaultError> {
        if data.len() < VAULT_HEADER_SIZE_V1 {
            return Err(VaultError::InvalidHeader(format!(
                "v1 header must be at least {} bytes, got {}",
                VAULT_HEADER_SIZE_V1,
                data.len()
            )));
        }

        let format_version = u16::from_le_bytes([data[8], data[9]]);
        let argon2_memory_kb = u32::from_le_bytes(
            data[10..14]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_memory_kb parse failed".to_string()))?,
        );
        let argon2_iterations = u32::from_le_bytes(
            data[14..18]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_iterations parse failed".to_string()))?,
        );
        let argon2_parallelism = u32::from_le_bytes(
            data[18..22]
                .try_into()
                .map_err(|_| VaultError::InvalidHeader("argon2_parallelism parse failed".to_string()))?,
        );

        let mut master_salt = [0u8; 32];
        master_salt.copy_from_slice(&data[22..54]);
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&data[54..70]);
        let mut pass_wrap_iv = [0u8; 12];
        pass_wrap_iv.copy_from_slice(&data[70..82]);
        let mut pass_wrapped_vault_key = [0u8; 48];
        pass_wrapped_vault_key.copy_from_slice(&data[82..130]);
        let mut recovery_wrap_iv = [0u8; 12];
        recovery_wrap_iv.copy_from_slice(&data[130..142]);
        let mut recovery_wrapped_vault_key = [0u8; 48];
        recovery_wrapped_vault_key.copy_from_slice(&data[142..190]);

        // Parse device slots (8 × 77 bytes starting at offset 191)
        let mut device_slots_vec = Vec::with_capacity(VAULT_MAX_DEVICES);
        for i in 0..VAULT_MAX_DEVICES {
            let offset = 191 + i * VAULT_DEVICE_SLOT_SIZE_V1;
            let slot = DeviceSlot::from_bytes_v1(&data[offset..offset + VAULT_DEVICE_SLOT_SIZE_V1])?;
            device_slots_vec.push(slot);
        }
        let device_slots: [DeviceSlot; VAULT_MAX_DEVICES] =
            device_slots_vec.try_into().map_err(|_: Vec<_>| {
                VaultError::InvalidHeader("v1 device slots parse failed".to_string())
            })?;

        let mut header_hmac = [0u8; 32];
        header_hmac.copy_from_slice(&data[VAULT_HMAC_OFFSET_V1..VAULT_HMAC_OFFSET_V1 + 32]);

        Ok(Self {
            format_version,
            argon2_memory_kb,
            argon2_iterations,
            argon2_parallelism,
            master_salt,
            vault_id,
            pass_wrap_iv,
            pass_wrapped_vault_key,
            recovery_wrap_iv,
            recovery_wrapped_vault_key,
            device_slots,
            revocation_epoch: 0,
            header_hmac,
        })
    }

    /// Serialize the header to bytes (1227 bytes, v2 format).
    /// The caller must compute and write `header_hmac` using `header_bytes_for_hmac()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; VAULT_HEADER_SIZE];
        buf[0..8].copy_from_slice(VAULT_MAGIC);
        // Always write as v2 format regardless of original format_version.
        buf[8..10].copy_from_slice(&VAULT_FORMAT_VERSION.to_le_bytes());
        buf[10..14].copy_from_slice(&self.argon2_memory_kb.to_le_bytes());
        buf[14..18].copy_from_slice(&self.argon2_iterations.to_le_bytes());
        buf[18..22].copy_from_slice(&self.argon2_parallelism.to_le_bytes());
        buf[22..54].copy_from_slice(&self.master_salt);
        buf[54..70].copy_from_slice(&self.vault_id);
        buf[70..82].copy_from_slice(&self.pass_wrap_iv);
        buf[82..130].copy_from_slice(&self.pass_wrapped_vault_key);
        buf[130..142].copy_from_slice(&self.recovery_wrap_iv);
        buf[142..190].copy_from_slice(&self.recovery_wrapped_vault_key);

        // num_active_slots byte at offset 190
        let active_count = self
            .device_slots
            .iter()
            .filter(|s| s.status == SlotStatus::Active)
            .count() as u8;
        buf[190] = active_count;

        // Device slots at offset 191 (8 × 125 bytes)
        for (i, slot) in self.device_slots.iter().enumerate() {
            let offset = 191 + i * VAULT_DEVICE_SLOT_SIZE;
            let slot_bytes = slot.to_bytes();
            buf[offset..offset + VAULT_DEVICE_SLOT_SIZE].copy_from_slice(&slot_bytes);
        }

        // revocation_epoch at offset 1191
        buf[VAULT_REVOCATION_EPOCH_OFFSET..VAULT_REVOCATION_EPOCH_OFFSET + 4]
            .copy_from_slice(&self.revocation_epoch.to_le_bytes());

        // header_hmac at offset 1195
        buf[VAULT_HMAC_OFFSET..VAULT_HMAC_OFFSET + 32].copy_from_slice(&self.header_hmac);

        buf
    }

    /// Return bytes[0..VAULT_HMAC_OFFSET] for HMAC computation.
    /// The HMAC covers everything except the HMAC field itself.
    pub fn header_bytes_for_hmac(&self) -> Vec<u8> {
        let all = self.to_bytes();
        all[0..VAULT_HMAC_OFFSET].to_vec()
    }

    /// Return active device slots.
    pub fn active_device_slots(&self) -> Vec<&DeviceSlot> {
        self.device_slots
            .iter()
            .filter(|s| s.status == SlotStatus::Active)
            .collect()
    }

    /// Find the slot index for a given device_id.
    pub fn find_device_slot(&self, device_id: &[u8; 16]) -> Option<usize> {
        self.device_slots
            .iter()
            .position(|s| s.status == SlotStatus::Active && s.device_id == *device_id)
    }

    /// Find the first empty slot index, or None if all slots are full.
    pub fn first_empty_slot(&self) -> Option<usize> {
        self.device_slots
            .iter()
            .position(|s| s.status == SlotStatus::Empty)
    }

    /// Count active device slots.
    pub fn active_slot_count(&self) -> usize {
        self.device_slots
            .iter()
            .filter(|s| s.status == SlotStatus::Active)
            .count()
    }

    /// Returns true if this vault needs migration to v2.
    pub fn needs_migration(&self) -> bool {
        self.format_version < VAULT_FORMAT_VERSION
    }
}

/// Errors that can occur when parsing or validating a vault header.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid vault header: {0}")]
    InvalidHeader(String),
    #[error("unsupported vault format version: {0}")]
    UnsupportedVersion(u16),
    #[error("vault header HMAC verification failed")]
    HmacVerificationFailed,
    #[error("no active device slot found for device")]
    DeviceSlotNotFound,
    #[error("all device slots full (max {0})")]
    DeviceSlotsFull(usize),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_valid_v2_header() -> VaultHeader {
        let mut device_slots = Vec::with_capacity(VAULT_MAX_DEVICES);
        for _ in 0..VAULT_MAX_DEVICES {
            device_slots.push(DeviceSlot::empty());
        }
        VaultHeader {
            format_version: VAULT_FORMAT_VERSION,
            argon2_memory_kb: 131072,
            argon2_iterations: 3,
            argon2_parallelism: 4,
            master_salt: [0x42u8; 32],
            vault_id: [0x01u8; 16],
            pass_wrap_iv: [0x02u8; 12],
            pass_wrapped_vault_key: [0x03u8; 48],
            recovery_wrap_iv: [0x04u8; 12],
            recovery_wrapped_vault_key: [0x05u8; 48],
            device_slots: device_slots.try_into().unwrap(),
            revocation_epoch: 0,
            header_hmac: [0x06u8; 32],
        }
    }

    fn make_valid_v1_header_bytes() -> Vec<u8> {
        // Build a syntactically valid v1 header (839 bytes) for migration tests.
        let mut buf = vec![0u8; VAULT_HEADER_SIZE_V1];
        buf[0..8].copy_from_slice(VAULT_MAGIC);
        buf[8..10].copy_from_slice(&(VAULT_FORMAT_VERSION_V1 as u16).to_le_bytes());
        // Argon2 params
        buf[10..14].copy_from_slice(&131072u32.to_le_bytes());
        buf[14..18].copy_from_slice(&3u32.to_le_bytes());
        buf[18..22].copy_from_slice(&4u32.to_le_bytes());
        // Salts and keys (dummy values)
        buf[22..54].copy_from_slice(&[0x42u8; 32]);  // master_salt
        buf[54..70].copy_from_slice(&[0x01u8; 16]);  // vault_id
        buf[70..82].copy_from_slice(&[0x02u8; 12]);  // pass_wrap_iv
        buf[82..130].copy_from_slice(&[0x03u8; 48]); // pass_wrapped_vault_key
        buf[130..142].copy_from_slice(&[0x04u8; 12]); // recovery_wrap_iv
        buf[142..190].copy_from_slice(&[0x05u8; 48]); // recovery_wrapped_vault_key
        // num_active_slots = 0 (offset 190)
        // device_slots: all zeros (empty)
        // HMAC at offset 807
        buf[VAULT_HMAC_OFFSET_V1..VAULT_HMAC_OFFSET_V1 + 32].copy_from_slice(&[0x06u8; 32]);
        buf
    }

    #[test]
    fn vault_v2_header_roundtrip() {
        let header = make_valid_v2_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), VAULT_HEADER_SIZE);

        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.format_version, VAULT_FORMAT_VERSION);
        assert_eq!(parsed.argon2_memory_kb, 131072);
        assert_eq!(parsed.argon2_iterations, 3);
        assert_eq!(parsed.argon2_parallelism, 4);
        assert_eq!(parsed.master_salt, [0x42u8; 32]);
        assert_eq!(parsed.vault_id, [0x01u8; 16]);
        assert_eq!(parsed.pass_wrap_iv, [0x02u8; 12]);
        assert_eq!(parsed.pass_wrapped_vault_key, [0x03u8; 48]);
        assert_eq!(parsed.recovery_wrap_iv, [0x04u8; 12]);
        assert_eq!(parsed.recovery_wrapped_vault_key, [0x05u8; 48]);
        assert_eq!(parsed.revocation_epoch, 0);
        assert_eq!(parsed.header_hmac, [0x06u8; 32]);
        assert_eq!(parsed.active_slot_count(), 0);
    }

    #[test]
    fn vault_v1_header_parses_for_migration() {
        let v1_bytes = make_valid_v1_header_bytes();
        let header = VaultHeader::parse(&v1_bytes).unwrap();
        assert_eq!(header.format_version, VAULT_FORMAT_VERSION_V1);
        assert!(header.needs_migration());
        assert_eq!(header.revocation_epoch, 0);
        assert_eq!(header.vault_id, [0x01u8; 16]);
        // All slots empty, signing keys zeroed
        for slot in &header.device_slots {
            assert_eq!(slot.signing_key_wrapped, [0u8; 48]);
        }
    }

    #[test]
    fn vault_v2_to_bytes_produces_correct_size() {
        let header = make_valid_v2_header();
        assert_eq!(header.to_bytes().len(), VAULT_HEADER_SIZE);
    }

    #[test]
    fn vault_v2_header_bytes_for_hmac_length() {
        let header = make_valid_v2_header();
        let hmac_bytes = header.header_bytes_for_hmac();
        assert_eq!(hmac_bytes.len(), VAULT_HMAC_OFFSET); // 1195
    }

    #[test]
    fn vault_header_rejects_short_input() {
        assert!(VaultHeader::parse(&[0u8; 100]).is_err());
    }

    #[test]
    fn vault_header_rejects_wrong_magic() {
        let header = make_valid_v2_header();
        let mut bytes = header.to_bytes();
        bytes[0] = b'X';
        assert!(VaultHeader::parse(&bytes).is_err());
    }

    #[test]
    fn vault_header_rejects_unsupported_version() {
        let header = make_valid_v2_header();
        let mut bytes = header.to_bytes();
        bytes[8] = 99;
        bytes[9] = 0;
        assert!(matches!(
            VaultHeader::parse(&bytes),
            Err(VaultError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn device_slot_v2_roundtrip() {
        let device_id = [0xAAu8; 16];
        let wrap_iv = [0xBBu8; 12];
        let payload = [0xCCu8; 48];
        let signing_key = [0xDDu8; 48];
        let slot = DeviceSlot::active_with_signing_key(device_id, wrap_iv, payload, signing_key);

        let bytes = slot.to_bytes();
        assert_eq!(bytes.len(), VAULT_DEVICE_SLOT_SIZE);

        let parsed = DeviceSlot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.status, SlotStatus::Active);
        assert_eq!(parsed.device_id, device_id);
        assert_eq!(parsed.wrap_iv, wrap_iv);
        assert_eq!(parsed.encrypted_payload, payload);
        assert_eq!(parsed.signing_key_wrapped, signing_key);
    }

    #[test]
    fn device_slot_without_signing_key() {
        let slot = DeviceSlot::active([1u8; 16], [2u8; 12], [3u8; 48]);
        assert!(!slot.has_signing_key());
        assert_eq!(slot.signing_key_wrapped, [0u8; 48]);
    }

    #[test]
    fn device_slot_with_signing_key() {
        let slot = DeviceSlot::active_with_signing_key(
            [1u8; 16], [2u8; 12], [3u8; 48], [4u8; 48],
        );
        assert!(slot.has_signing_key());
    }

    #[test]
    fn empty_device_slot_roundtrip() {
        let slot = DeviceSlot::empty();
        let bytes = slot.to_bytes();
        assert_eq!(bytes.len(), VAULT_DEVICE_SLOT_SIZE);
        let parsed = DeviceSlot::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.status, SlotStatus::Empty);
        assert_eq!(parsed.device_id, [0u8; 16]);
        assert_eq!(parsed.signing_key_wrapped, [0u8; 48]);
    }

    #[test]
    fn active_device_slots() {
        let mut header = make_valid_v2_header();
        header.device_slots[0] = DeviceSlot::active([1u8; 16], [2u8; 12], [3u8; 48]);
        header.device_slots[3] = DeviceSlot::active([4u8; 16], [5u8; 12], [6u8; 48]);
        assert_eq!(header.active_slot_count(), 2);
        assert_eq!(header.active_device_slots().len(), 2);
    }

    #[test]
    fn find_device_slot() {
        let mut header = make_valid_v2_header();
        let target_id = [0xABu8; 16];
        header.device_slots[2] = DeviceSlot::active(target_id, [0u8; 12], [0u8; 48]);
        assert_eq!(header.find_device_slot(&target_id), Some(2));
        assert_eq!(header.find_device_slot(&[0xFFu8; 16]), None);
    }

    #[test]
    fn first_empty_slot() {
        let mut header = make_valid_v2_header();
        assert_eq!(header.first_empty_slot(), Some(0));
        for i in 0..3 {
            header.device_slots[i] = DeviceSlot::active([i as u8; 16], [0u8; 12], [0u8; 48]);
        }
        assert_eq!(header.first_empty_slot(), Some(3));
    }

    #[test]
    fn revocation_epoch_roundtrip() {
        let mut header = make_valid_v2_header();
        header.revocation_epoch = 42;
        let bytes = header.to_bytes();
        let parsed = VaultHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.revocation_epoch, 42);
    }

    #[test]
    fn needs_migration_false_for_v2() {
        let header = make_valid_v2_header();
        assert!(!header.needs_migration());
    }

    #[test]
    fn fuzz_parse_all_zeros_wrong_magic() {
        let data = [0u8; VAULT_HEADER_SIZE];
        assert!(VaultHeader::parse(&data).is_err());
    }

    #[test]
    fn fuzz_parse_random_bytes_does_not_panic() {
        let mut data = [0u8; VAULT_HEADER_SIZE];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i.wrapping_mul(6364136223846793005).wrapping_add(1)) & 0xFF) as u8;
        }
        let _ = VaultHeader::parse(&data);
    }

    #[test]
    fn fuzz_parse_zero_bytes_is_err() {
        assert!(VaultHeader::parse(&[]).is_err());
    }

    #[test]
    fn fuzz_parse_one_byte_is_err() {
        assert!(VaultHeader::parse(&[0x53]).is_err());
    }

    #[test]
    fn fuzz_parse_one_short_of_v2_header_is_err() {
        let header = make_valid_v2_header();
        let bytes = header.to_bytes();
        assert!(VaultHeader::parse(&bytes[..VAULT_HEADER_SIZE - 1]).is_err());
    }

    #[test]
    fn fuzz_parse_unknown_slot_status_is_err() {
        let header = make_valid_v2_header();
        let mut bytes = header.to_bytes();
        bytes[191] = 0xFF; // corrupt first slot status byte
        assert!(VaultHeader::parse(&bytes).is_err());
    }
}
