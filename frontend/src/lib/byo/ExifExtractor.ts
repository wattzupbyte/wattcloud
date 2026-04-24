/**
 * EXIF metadata extraction for photos.
 *
 * Runs entirely client-side (exifr npm lib) after the file has been
 * decrypted / loaded into a Blob in-memory — the plaintext bytes never
 * leave the device. Extracted fields are stored (encrypted) in the
 * `metadata` column of `files` so the timeline + lightbox can surface
 * them without re-parsing the full image.
 */

import exifr from 'exifr';

export interface PhotoExif {
  /** ISO timestamp when the photo was taken, if present. */
  takenAt?: string;
  /** GPS latitude in decimal degrees (WGS84). */
  lat?: number;
  /** GPS longitude in decimal degrees (WGS84). */
  lon?: number;
  /** Camera make (e.g. "Canon"). */
  make?: string;
  /** Camera model (e.g. "EOS R6"). */
  model?: string;
  /** ISO speed. */
  iso?: number;
  /** f-number (aperture). */
  fNumber?: number;
  /** Exposure time in seconds. */
  exposureTime?: number;
  /** Focal length in mm. */
  focalLength?: number;
}

/**
 * Parse EXIF from raw image bytes. Returns `{}` on any error so callers
 * can store empty metadata and still track "this file has been scanned".
 */
export async function extractExif(bytes: Uint8Array): Promise<PhotoExif> {
  try {
    const parsed = await exifr.parse(bytes, {
      // `pick` filters by EXIF tag name (e.g. GPSLatitude = 0x0002), NOT by
      // the output key name exifr translates them to. Passing `latitude`
      // here silently drops the GPS block — it doesn't match any real tag
      // and the pick allowlist rejects the whole GPS IFD. So we pick by
      // tag name; exifr post-translates GPSLatitude/GPSLongitude into
      // decimal `latitude`/`longitude` on the output object (see
      // exifr/src/segment-parsers/tiff-exif.mjs).
      pick: [
        'DateTimeOriginal', 'CreateDate', 'ModifyDate',
        'GPSLatitude', 'GPSLongitude', 'GPSLatitudeRef', 'GPSLongitudeRef',
        'Make', 'Model',
        'ISO', 'FNumber', 'ExposureTime', 'FocalLength',
      ],
      gps: true,
    });
    if (!parsed) return {};

    const out: PhotoExif = {};
    const takenAt = parsed.DateTimeOriginal ?? parsed.CreateDate ?? parsed.ModifyDate;
    if (takenAt instanceof Date) out.takenAt = takenAt.toISOString();
    if (typeof parsed.latitude === 'number') out.lat = parsed.latitude;
    if (typeof parsed.longitude === 'number') out.lon = parsed.longitude;
    if (parsed.Make) out.make = String(parsed.Make).trim();
    if (parsed.Model) out.model = String(parsed.Model).trim();
    if (typeof parsed.ISO === 'number') out.iso = parsed.ISO;
    if (typeof parsed.FNumber === 'number') out.fNumber = parsed.FNumber;
    if (typeof parsed.ExposureTime === 'number') out.exposureTime = parsed.ExposureTime;
    if (typeof parsed.FocalLength === 'number') out.focalLength = parsed.FocalLength;
    return out;
  } catch {
    return {};
  }
}

/** Serialize PhotoExif for storage in the `files.metadata` column. */
export function serializeExif(e: PhotoExif): string {
  return JSON.stringify(e);
}

/** Parse PhotoExif back out of the stored string. Returns `{}` on any error. */
export function parseExif(raw: string | null | undefined): PhotoExif {
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return typeof v === 'object' && v ? (v as PhotoExif) : {};
  } catch {
    return {};
  }
}
