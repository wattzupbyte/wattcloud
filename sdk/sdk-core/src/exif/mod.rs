// EXIF metadata extraction from JPEG files.
//
// Pure byte parsing — no I/O, no allocator beyond Vec/String.
// Returns an ExifData struct with whatever fields could be parsed.
// Non-JPEG input and any parsing failures return empty/partial data, never error.
//
// This is a faithful port of the hand-rolled JPEG/EXIF parser that previously
// lived in frontend/stores/photos.ts (APP1/TIFF/IFD/GPS, same tag IDs).
//
// Also provides thumbnail encrypt/decrypt helpers (thin wrappers around v7 format).

use serde::{Deserialize, Serialize};

use crate::crypto::wire_format::{decrypt_file_v7, encrypt_file_v7};
use crate::crypto::zeroize_utils::{
    MlKemPublicKey, MlKemSecretKey, X25519PublicKey, X25519SecretKey,
};
use crate::error::CryptoError;

// ─── Public types ─────────────────────────────────────────────────────────────

/// EXIF metadata extracted from a JPEG file.
///
/// All fields are `Option` — absent means the tag was not found or could not
/// be parsed, which is not an error.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExifData {
    /// Date/time the photo was taken (ISO 8601, e.g. "2023-10-15T14:30:00").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at: Option<String>,
    /// GPS latitude in decimal degrees (positive = North).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    /// GPS longitude in decimal degrees (positive = East).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    /// Camera manufacturer (EXIF tag 0x010F Make).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera_make: Option<String>,
    /// Camera model (EXIF tag 0x0110 Model).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera_model: Option<String>,
    /// Exposure time as a fraction string (e.g. "1/125").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_time: Option<String>,
    /// F-number (aperture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub f_number: Option<f64>,
    /// ISO speed rating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso: Option<u32>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Extract EXIF metadata from JPEG bytes.
///
/// Returns `ExifData::default()` (all `None`) for non-JPEG input or if the
/// APP1/EXIF marker is absent. Never panics or returns an error.
pub fn extract_exif(data: &[u8]) -> ExifData {
    extract_exif_inner(data).unwrap_or_default()
}

/// Encrypt thumbnail bytes for server storage.
///
/// Uses the v7 wire format (same as files). The plaintext thumbnail is treated
/// as a single chunk.
pub fn encrypt_thumbnail(
    thumbnail_bytes: &[u8],
    mlkem_pub: &MlKemPublicKey,
    x25519_pub: &X25519PublicKey,
) -> Result<Vec<u8>, CryptoError> {
    encrypt_file_v7(mlkem_pub, x25519_pub, &[thumbnail_bytes])
}

/// Decrypt thumbnail bytes from server storage.
pub fn decrypt_thumbnail(
    encrypted: &[u8],
    mlkem_sec: &MlKemSecretKey,
    x25519_sec: &X25519SecretKey,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_file_v7(encrypted, mlkem_sec, x25519_sec)
}

// ─── JPEG / EXIF parser ───────────────────────────────────────────────────────

fn extract_exif_inner(data: &[u8]) -> Option<ExifData> {
    if !is_jpeg(data) {
        return None;
    }

    let (app1_start, _app1_len) = find_app1_exif(data)?;
    // APP1 payload starts after marker (2) + length (2) = offset 4 from segment start.
    // We already verified "Exif\0\0" in find_app1_exif, so TIFF starts at app1_start + 10.
    let tiff_base = app1_start + 10;
    if tiff_base + 8 > data.len() {
        return None;
    }

    let tiff = &data[tiff_base..];
    let little_endian = match (tiff.first()?, tiff.get(1)?) {
        (0x49, 0x49) => true,  // "II" — Intel / little-endian
        (0x4D, 0x4D) => false, // "MM" — Motorola / big-endian
        _ => return None,
    };

    // TIFF magic: bytes 2-3 should be 42 (0x002A).
    let magic = read_u16(tiff, 2, little_endian)?;
    if magic != 42 {
        return None;
    }

    // Offset of the first IFD.
    let ifd0_offset = read_u32(tiff, 4, little_endian)? as usize;
    let ifd0 = parse_ifd(tiff, ifd0_offset, little_endian);

    let mut exif = ExifData::default();

    // DateTimeOriginal (0x9003) — preferred; fallback to DateTime (0x0132).
    if let Some(IfdValue::Ascii(s)) = ifd0.get(&0x9003u16) {
        exif.taken_at = parse_exif_date(s);
    } else if let Some(IfdValue::Ascii(s)) = ifd0.get(&0x0132u16) {
        exif.taken_at = parse_exif_date(s);
    }

    // Make (0x010F) / Model (0x0110).
    if let Some(IfdValue::Ascii(s)) = ifd0.get(&0x010Fu16) {
        exif.camera_make = Some(s.trim_end_matches('\0').trim().to_string());
    }
    if let Some(IfdValue::Ascii(s)) = ifd0.get(&0x0110u16) {
        exif.camera_model = Some(s.trim_end_matches('\0').trim().to_string());
    }

    // Exif Sub-IFD pointer (0x8769) — ExposureTime, FNumber, ISO live there.
    if let Some(IfdValue::Long(offset)) = ifd0.get(&0x8769u16) {
        let sub_ifd = parse_ifd(tiff, *offset as usize, little_endian);

        // ExposureTime (0x829A) — store as "n/d" string.
        if let Some(IfdValue::Rational(n, d)) = sub_ifd.get(&0x829Au16) {
            if *d != 0 {
                exif.exposure_time = Some(format!("{n}/{d}"));
            }
        }
        // FNumber (0x829D).
        if let Some(IfdValue::Rational(n, d)) = sub_ifd.get(&0x829Du16) {
            if *d != 0 {
                exif.f_number = Some(*n as f64 / *d as f64);
            }
        }
        // ISOSpeedRatings (0x8827).
        if let Some(IfdValue::Short(v)) = sub_ifd.get(&0x8827u16) {
            exif.iso = Some(*v as u32);
        }

        // DateTimeOriginal inside sub-IFD overrides if not already set from IFD0.
        if exif.taken_at.is_none() {
            if let Some(IfdValue::Ascii(s)) = sub_ifd.get(&0x9003u16) {
                exif.taken_at = parse_exif_date(s);
            }
        }
    }

    // GPS IFD pointer (0x8825).
    if let Some(IfdValue::Long(gps_offset)) = ifd0.get(&0x8825u16) {
        let gps_ifd = parse_ifd(tiff, *gps_offset as usize, little_endian);

        // GPSLatitude (0x0002) + GPSLatitudeRef (0x0001).
        if let (Some(IfdValue::Rationals(lat_vals)), Some(IfdValue::Ascii(lat_ref))) =
            (gps_ifd.get(&0x0002u16), gps_ifd.get(&0x0001u16))
        {
            if lat_vals.len() >= 3 {
                let (n0, d0) = lat_vals[0];
                let (n1, d1) = lat_vals[1];
                let (n2, d2) = lat_vals[2];
                let deg = rational_to_f64(n0, d0);
                let min = rational_to_f64(n1, d1);
                let sec = rational_to_f64(n2, d2);
                let mut lat = dms_to_dd(deg, min, sec);
                if lat_ref.starts_with('S') {
                    lat = -lat;
                }
                exif.latitude = Some(lat);
            }
        }

        // GPSLongitude (0x0004) + GPSLongitudeRef (0x0003).
        if let (Some(IfdValue::Rationals(lon_vals)), Some(IfdValue::Ascii(lon_ref))) =
            (gps_ifd.get(&0x0004u16), gps_ifd.get(&0x0003u16))
        {
            if lon_vals.len() >= 3 {
                let (n0, d0) = lon_vals[0];
                let (n1, d1) = lon_vals[1];
                let (n2, d2) = lon_vals[2];
                let deg = rational_to_f64(n0, d0);
                let min = rational_to_f64(n1, d1);
                let sec = rational_to_f64(n2, d2);
                let mut lon = dms_to_dd(deg, min, sec);
                if lon_ref.starts_with('W') {
                    lon = -lon;
                }
                exif.longitude = Some(lon);
            }
        }
    }

    Some(exif)
}

// ─── JPEG helpers ─────────────────────────────────────────────────────────────

fn is_jpeg(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8
}

/// Walk JPEG markers to find the APP1 segment containing "Exif\0\0".
/// Returns `Some((segment_start, segment_len))` on success.
fn find_app1_exif(data: &[u8]) -> Option<(usize, usize)> {
    let mut offset = 2usize; // skip SOI (0xFF 0xD8)
    while offset + 4 <= data.len() {
        if data[offset] != 0xFF {
            break;
        }
        let marker = data[offset + 1];
        if marker == 0xD9 {
            // EOI — end of image
            break;
        }
        // Standalone markers (no length field): 0xD0–0xD8, 0x01
        if (0xD0..=0xD8).contains(&marker) || marker == 0x01 {
            offset += 2;
            continue;
        }
        if offset + 4 > data.len() {
            break;
        }
        let seg_len = (data[offset + 2] as usize) << 8 | data[offset + 3] as usize;
        if seg_len < 2 {
            break;
        }
        if marker == 0xE1 {
            // APP1 — check for "Exif\0\0" header (6 bytes after marker+length).
            if offset + 10 <= data.len() {
                let hdr = &data[offset + 4..offset + 10];
                if hdr == b"Exif\x00\x00" {
                    return Some((offset, seg_len));
                }
            }
        }
        offset += 2 + seg_len;
    }
    None
}

// ─── TIFF/IFD parsing ─────────────────────────────────────────────────────────

/// Parsed IFD entry value.
#[derive(Debug)]
enum IfdValue {
    Short(u16),
    Long(u32),
    Rational(u32, u32),
    Rationals(Vec<(u32, u32)>),
    Ascii(String),
}

type IfdMap = std::collections::HashMap<u16, IfdValue>;

fn parse_ifd(tiff: &[u8], ifd_offset: usize, le: bool) -> IfdMap {
    let mut map = IfdMap::new();
    let count = match read_u16(tiff, ifd_offset, le) {
        Some(c) => c as usize,
        None => return map,
    };

    for i in 0..count {
        let entry_offset = ifd_offset + 2 + i * 12;
        if entry_offset + 12 > tiff.len() {
            break;
        }
        let tag = match read_u16(tiff, entry_offset, le) {
            Some(t) => t,
            None => continue,
        };
        let type_ = match read_u16(tiff, entry_offset + 2, le) {
            Some(t) => t,
            None => continue,
        };
        let count = match read_u32(tiff, entry_offset + 4, le) {
            Some(c) => c as usize,
            None => continue,
        };
        let value_or_offset = entry_offset + 8;

        match type_ {
            // SHORT (2 bytes per value)
            3 => {
                let v = read_u16(tiff, value_or_offset, le).unwrap_or(0);
                map.insert(tag, IfdValue::Short(v));
            }
            // LONG (4 bytes per value)
            4 => {
                let v = read_u32(tiff, value_or_offset, le).unwrap_or(0);
                map.insert(tag, IfdValue::Long(v));
            }
            // RATIONAL (two LONGs: numerator / denominator)
            5 => {
                if count == 1 {
                    let real_offset = read_u32(tiff, value_or_offset, le).unwrap_or(0) as usize;
                    let n = read_u32(tiff, real_offset, le).unwrap_or(0);
                    let d = read_u32(tiff, real_offset + 4, le).unwrap_or(1);
                    map.insert(tag, IfdValue::Rational(n, d));
                } else if count > 1 {
                    let real_offset = read_u32(tiff, value_or_offset, le).unwrap_or(0) as usize;
                    let mut rationals = Vec::with_capacity(count);
                    for j in 0..count {
                        let n = read_u32(tiff, real_offset + j * 8, le).unwrap_or(0);
                        let d = read_u32(tiff, real_offset + j * 8 + 4, le).unwrap_or(1);
                        rationals.push((n, d));
                    }
                    map.insert(tag, IfdValue::Rationals(rationals));
                }
            }
            // ASCII (null-terminated string)
            2 => {
                let s = if count <= 4 {
                    // Value fits inline in the 4-byte value field
                    let bytes = &tiff[value_or_offset..value_or_offset + count];
                    String::from_utf8_lossy(bytes)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    let str_offset = read_u32(tiff, value_or_offset, le).unwrap_or(0) as usize;
                    if str_offset + count <= tiff.len() {
                        String::from_utf8_lossy(&tiff[str_offset..str_offset + count])
                            .trim_end_matches('\0')
                            .to_string()
                    } else {
                        String::new()
                    }
                };
                map.insert(tag, IfdValue::Ascii(s));
            }
            _ => {} // Ignore other types (BYTE, UNDEFINED, SBYTE, SSHORT, SLONG, etc.)
        }
    }

    map
}

// ─── Byte read helpers ────────────────────────────────────────────────────────

fn read_u16(data: &[u8], offset: usize, le: bool) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    let b = [data[offset], data[offset + 1]];
    Some(if le {
        u16::from_le_bytes(b)
    } else {
        u16::from_be_bytes(b)
    })
}

fn read_u32(data: &[u8], offset: usize, le: bool) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    let b = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    Some(if le {
        u32::from_le_bytes(b)
    } else {
        u32::from_be_bytes(b)
    })
}

// ─── Coordinate / date helpers ────────────────────────────────────────────────

fn rational_to_f64(n: u32, d: u32) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

fn dms_to_dd(degrees: f64, minutes: f64, seconds: f64) -> f64 {
    degrees + minutes / 60.0 + seconds / 3600.0
}

/// Convert "YYYY:MM:DD HH:MM:SS" to ISO 8601 "YYYY-MM-DDTHH:MM:SS".
fn parse_exif_date(s: &str) -> Option<String> {
    // Expected format: "2023:10:15 14:30:00"
    let s = s.trim_end_matches('\0').trim();
    if s.len() < 19 {
        return None;
    }
    let bytes = s.as_bytes();
    // Validate rough structure: YYYY:MM:DD HH:MM:SS
    if bytes[4] != b':'
        || bytes[7] != b':'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}",
        &s[0..4],
        &s[5..7],
        &s[8..10],
        &s[11..19]
    ))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn non_jpeg_returns_empty() {
        let exif = extract_exif(b"PNG\r\n\x1a\n");
        assert!(exif.taken_at.is_none());
        assert!(exif.latitude.is_none());
    }

    #[test]
    fn empty_returns_empty() {
        let exif = extract_exif(&[]);
        assert!(exif.taken_at.is_none());
    }

    #[test]
    fn parse_exif_date_valid() {
        let result = parse_exif_date("2023:10:15 14:30:00");
        assert_eq!(result, Some("2023-10-15T14:30:00".to_string()));
    }

    #[test]
    fn parse_exif_date_short_returns_none() {
        assert!(parse_exif_date("2023:10:15").is_none());
    }

    #[test]
    fn dms_to_dd_positive() {
        let dd = dms_to_dd(51.0, 30.0, 0.0);
        assert!((dd - 51.5).abs() < 1e-9);
    }

    #[test]
    fn dms_to_dd_zero_seconds() {
        let dd = dms_to_dd(0.0, 0.0, 0.0);
        assert_eq!(dd, 0.0);
    }

    #[test]
    fn thumbnail_encrypt_decrypt_roundtrip() {
        let kp = crate::crypto::pqc::generate_hybrid_keypair().unwrap();
        let thumb = b"fake thumbnail data 0123456789";
        let enc = encrypt_thumbnail(thumb, &kp.mlkem_public_key, &kp.x25519_public_key).unwrap();
        let dec = decrypt_thumbnail(&enc, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(dec, thumb);
    }
}
