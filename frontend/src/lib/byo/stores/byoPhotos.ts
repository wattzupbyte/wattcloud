/**
 * BYO Photo Timeline Store
 *
 * Queries DataProvider.listImageFiles() and groups results by year/month
 * from created_at. Provides thumbnail lazy-loading with blob URL caching
 * and proper cleanup on vault lock.
 *
 * DataProvider must be set via setByoPhotosDataProvider() after unlock.
 * On vault lock, call resetByoPhotos() — revokes all cached blob URLs.
 */

import { writable, derived, get } from 'svelte/store';
import type { DataProvider, FileEntry } from '../DataProvider';
import { getMimeType } from '../../utils';
import { readCachedThumbnail, writeCachedThumbnail } from '../ThumbnailStore';
import { parseExif, extractExif, serializeExif } from '../ExifExtractor';
import { vaultStore } from './vaultStore';

// ── Timeline types ─────────────────────────────────────────────────────────

export interface ByoTimelineGroup {
  year: number;
  month: number;
  day: number;
  files: FileEntry[];
}

// ── Stores ─────────────────────────────────────────────────────────────────

export const byoPhotoTimeline = writable<ByoTimelineGroup[]>([]);
export const byoPhotosLoading = writable<boolean>(false);

/**
 * Folder id that sources the timeline.
 *  - `undefined` → all images across the active provider (default).
 *  - `null`      → images at the vault root only.
 *  - `number`    → that folder and all its descendants.
 *
 * Persisted per-vault in localStorage so the pick survives reloads.
 * (vault_meta would sync across devices — consider promoting later.)
 */
export const byoPhotoFolderFilter = writable<number | null | undefined>(undefined);

const PHOTO_FOLDER_PREF_PREFIX = 'byo:photo_folder:';

export function initByoPhotoFolderFilter(vaultId: string): void {
  try {
    const raw = localStorage.getItem(PHOTO_FOLDER_PREF_PREFIX + vaultId);
    if (raw === null) { byoPhotoFolderFilter.set(undefined); return; }
    if (raw === 'root') { byoPhotoFolderFilter.set(null); return; }
    const n = Number(raw);
    byoPhotoFolderFilter.set(Number.isFinite(n) ? n : undefined);
  } catch {
    byoPhotoFolderFilter.set(undefined);
  }
}

export function setByoPhotoFolderFilter(vaultId: string, v: number | null | undefined): void {
  byoPhotoFolderFilter.set(v);
  try {
    if (v === undefined) localStorage.removeItem(PHOTO_FOLDER_PREF_PREFIX + vaultId);
    else if (v === null) localStorage.setItem(PHOTO_FOLDER_PREF_PREFIX + vaultId, 'root');
    else localStorage.setItem(PHOTO_FOLDER_PREF_PREFIX + vaultId, String(v));
  } catch { /* storage blocked — in-memory state still works */ }
}

/** file_id → blob URL (revoked on vault lock) */
export const byoThumbnailCache = writable<Map<number, string>>(new Map());

// ── DataProvider reference ─────────────────────────────────────────────────

let _dataProvider: DataProvider | null = null;

export function setByoPhotosDataProvider(dp: DataProvider): void {
  _dataProvider = dp;
}

// ── Load timeline ──────────────────────────────────────────────────────────

export async function loadByoPhotoTimeline(): Promise<void> {
  if (!_dataProvider) return;

  byoPhotosLoading.set(true);
  try {
    // Sibling $effects (ByoApp + ByoPhotoTimeline) both react to
    // vaultStore.activeProviderId changes. Svelte's scheduler doesn't
    // guarantee parent-first order, so without this re-sync the timeline
    // can fire its load before ByoApp has pushed the new id onto the
    // dataProvider — listImageFiles would then query under the previous
    // active provider and the user sees the wrong vault's photos. Reading
    // the store directly here keeps the load self-contained. The cast
    // is safe in practice: BYO mode always supplies a ByoDataProvider,
    // and the abstract DataProvider interface intentionally doesn't
    // expose the active-id mutator (single-provider managed mode has
    // no concept of an active id).
    const activeId = get(vaultStore).activeProviderId;
    const dpAny = _dataProvider as unknown as { activeProviderId?: string; setActiveProviderId?(id: string): void };
    if (activeId && dpAny.activeProviderId !== activeId && typeof dpAny.setActiveProviderId === 'function') {
      dpAny.setActiveProviderId(activeId);
    }
    const folderFilter = get(byoPhotoFolderFilter);
    const files = await _dataProvider.listImageFiles(folderFilter);
    byoPhotoTimeline.set(groupByDay(files));
  } catch (e) {
    console.error('[byoPhotos] failed to load timeline:', e);
    byoPhotoTimeline.set([]);
  } finally {
    byoPhotosLoading.set(false);
  }
}

/**
 * Prefer the EXIF "taken" timestamp for grouping/sorting so the timeline
 * reflects when the photo was captured, not when it was uploaded. Falls
 * back to created_at for files without EXIF (non-camera images, older
 * uploads from before extraction was wired). Upload date still lives on
 * `file.created_at` — FilePreview's info panel surfaces both.
 */
function photoTimestamp(file: FileEntry): string {
  const takenAt = parseExif(file.metadata).takenAt;
  return takenAt ?? file.created_at;
}

function groupByDay(files: FileEntry[]): ByoTimelineGroup[] {
  const map = new Map<string, ByoTimelineGroup>();

  for (const file of files) {
    const date = new Date(photoTimestamp(file));
    const year = date.getUTCFullYear();
    const month = date.getUTCMonth() + 1; // 1-indexed
    const day = date.getUTCDate();
    const key = `${year}-${month}-${day}`;

    if (!map.has(key)) {
      map.set(key, { year, month, day, files: [] });
    }
    map.get(key)!.files.push(file);
  }

  // Sort groups newest first
  return Array.from(map.values()).sort((a, b) => {
    if (b.year !== a.year) return b.year - a.year;
    if (b.month !== a.month) return b.month - a.month;
    return b.day - a.day;
  });
}

// ── Thumbnail loading ──────────────────────────────────────────────────────

// Target the typical desktop render size × devicePixelRatio on high-DPI
// displays. The photo grid is 5-col on ≥600px viewports, so tiles are
// ~300 CSS px wide — at DPR=2 that's 600 real px. Anything smaller
// looks soft on Retina/4k.
const THUMB_MAX_PX = 600;
const THUMB_QUALITY = 0.88;

async function streamToUint8Array(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let totalLen = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    totalLen += value.length;
  }

  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

async function resizeToThumbnail(data: Uint8Array, mimeType: string): Promise<Blob> {
  const sourceBlob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  const bitmap = await createImageBitmap(sourceBlob);

  const { width, height } = bitmap;
  const scale = Math.min(1, THUMB_MAX_PX / Math.max(width, height));
  const w = Math.round(width * scale);
  const h = Math.round(height * scale);

  if (typeof OffscreenCanvas !== 'undefined') {
    const canvas = new OffscreenCanvas(w, h);
    const ctx = canvas.getContext('2d') as OffscreenCanvasRenderingContext2D;
    ctx.drawImage(bitmap, 0, 0, w, h);
    bitmap.close();
    const blob = await canvas.convertToBlob({ type: 'image/webp', quality: THUMB_QUALITY });
    return blob.size > 0 ? blob : new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  } else {
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d')!;
    ctx.drawImage(bitmap, 0, 0, w, h);
    bitmap.close();
    const blob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (b) => (b ? resolve(b) : reject(new Error('toBlob returned null'))),
        'image/webp',
        THUMB_QUALITY,
      );
    });
    return blob.size > 0 ? blob : new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  }
}

// Cap concurrent thumbnail downloads. The SFTP relay holds a small,
// fixed pool of read sessions per vault — IntersectionObserver firing
// for an entire grid at once trivially blows past the cap and the
// relay starts rejecting with "too many open read sessions". The
// requests still succeed eventually because each tile's lazyThumbnail
// observer doesn't disconnect on failure (it disconnects on first
// intersection regardless of result), so subsequent load attempts
// come from elsewhere — but the rejected ones spam the console.
// Throttling up front keeps the request rate inside the relay's
// budget and stops the noise at the source. Six is empirical: high
// enough that an idle wide grid finishes warming in a few hundred
// ms, low enough that mobile + relay keep up.
const MAX_CONCURRENT_THUMB_LOADS = 6;
let _thumbInFlight = 0;
const _thumbWaiters: Array<() => void> = [];

async function acquireThumbSlot(): Promise<void> {
  if (_thumbInFlight < MAX_CONCURRENT_THUMB_LOADS) {
    _thumbInFlight++;
    return;
  }
  await new Promise<void>((resolve) => _thumbWaiters.push(resolve));
  _thumbInFlight++;
}
function releaseThumbSlot(): void {
  _thumbInFlight--;
  const next = _thumbWaiters.shift();
  if (next) next();
}

/** True for transient errors that the relay raises under load — the
 *  caller should retry rather than surface as a real failure. */
function isTransientThumbError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /too many open read sessions|read_open|temporarily unavailable/i.test(msg);
}

export async function loadByoThumbnail(file: FileEntry): Promise<string | null> {
  const cache = get(byoThumbnailCache);
  if (cache.has(file.id)) return cache.get(file.id)!;

  if (!_dataProvider) return null;

  const vaultId = get(vaultStore).vaultId ?? null;

  // Tier 1 — persistent IDB cache. Hit = instant return.
  if (vaultId) {
    const hit = await readCachedThumbnail(vaultId, file.id);
    if (hit) {
      const url = URL.createObjectURL(new Blob([hit.bytes.buffer as ArrayBuffer], { type: hit.mime }));
      byoThumbnailCache.update((m) => new Map(m).set(file.id, url));
      return url;
    }
  }

  // Tier 2 — download + decrypt + resize. On success, seed the IDB cache
  // for future reloads. Wrapped in a small retry loop so transient relay
  // back-pressure (e.g. "too many open read sessions" when the user
  // scrolls a fresh grid into view) doesn't surface as a failure — the
  // operation is naturally re-runnable since nothing was committed.
  await acquireThumbSlot();
  let data: Uint8Array | null = null;
  try {
    const MAX_ATTEMPTS = 4;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        const stream = await _dataProvider.downloadFile(file.id);
        data = await streamToUint8Array(stream);
        break;
      } catch (e) {
        if (attempt < MAX_ATTEMPTS && isTransientThumbError(e)) {
          // Exponential backoff with jitter — 200/400/800 ms ± 25%.
          const base = 200 * Math.pow(2, attempt - 1);
          const jitter = base * (Math.random() * 0.5 - 0.25);
          await new Promise((r) => setTimeout(r, base + jitter));
          continue;
        }
        throw e;
      }
    }
    if (!data) return null;

    const mimeType = getMimeType(file.decrypted_name) || file.mime_type || 'image/jpeg';

    let blob: Blob;
    if (mimeType === 'image/svg+xml') {
      blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
    } else {
      try {
        blob = await resizeToThumbnail(data, mimeType);
      } catch {
        blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
      }
    }

    const url = URL.createObjectURL(blob);
    byoThumbnailCache.update((m) => new Map(m).set(file.id, url));

    // Seed the persistent cache — best-effort, errors are swallowed.
    if (vaultId) {
      try {
        const thumbBytes = new Uint8Array(await blob.arrayBuffer());
        await writeCachedThumbnail(vaultId, file.id, thumbBytes, blob.type || mimeType);
      } catch { /* caching is optional */ }
    }
    return url;
  } catch (e) {
    // Demote transient back-pressure to a debug log: the lazyThumbnail
    // IntersectionObserver naturally re-attempts on the next grid scroll,
    // and the cache hit path makes that retry effectively free. Anything
    // else still goes to console.error so genuine failures stay loud.
    if (isTransientThumbError(e)) {
      console.debug(`[byoPhotos] thumbnail throttled for file ${file.id}; will retry on next view.`);
    } else {
      console.error(`[byoPhotos] thumbnail load failed for file ${file.id}:`, e);
    }
    return null;
  } finally {
    if (data) data.fill(0);
    releaseThumbSlot();
  }
}

// ── Re-extract EXIF (backfill) ─────────────────────────────────────────────

/**
 * Re-parse EXIF from the full file (well, first 4 MiB) for every image
 * whose stored metadata lacks GPS. Writes the new metadata via
 * DataProvider.updateFileMetadata. Used when photos uploaded before the
 * upload-path head-slice widening (256 KiB → 4 MiB) are missing GPS data
 * in the vault even though the original image has it.
 *
 * Returns { updated, total } so the UI can report how many entries gained
 * GPS data. Progress callbacks fire after each file (success or failure).
 */
export async function reextractMissingExif(
  onProgress?: (done: number, total: number) => void,
): Promise<{ updated: number; total: number }> {
  if (!_dataProvider) return { updated: 0, total: 0 };

  const files = await _dataProvider.listImageFiles();
  const candidates = files.filter((f) => {
    const e = parseExif(f.metadata);
    return typeof e.lat !== 'number' || typeof e.lon !== 'number';
  });

  let updated = 0;
  const MAX_HEAD = 4 * 1024 * 1024;

  for (let i = 0; i < candidates.length; i++) {
    const file = candidates[i];
    let data: Uint8Array | null = null;
    try {
      const stream = await _dataProvider.downloadFile(file.id);
      data = await streamToUint8Array(stream);
      const head = data.length > MAX_HEAD ? data.slice(0, MAX_HEAD) : data;
      const exif = await extractExif(head);
      if (typeof exif.lat === 'number' && typeof exif.lon === 'number') {
        await _dataProvider.updateFileMetadata(file.id, serializeExif(exif));
        updated++;
      }
    } catch (e) {
      console.warn(`[byoPhotos] re-extract failed for file ${file.id}:`, e);
    } finally {
      if (data) data.fill(0);
    }
    onProgress?.(i + 1, candidates.length);
  }

  if (updated > 0) {
    await loadByoPhotoTimeline();
  }
  return { updated, total: candidates.length };
}

// ── Reset ──────────────────────────────────────────────────────────────────

export function resetByoPhotos(): void {
  // Revoke all cached blob URLs to avoid leaks
  const cache = get(byoThumbnailCache);
  cache.forEach((url) => URL.revokeObjectURL(url));
  byoThumbnailCache.set(new Map());
  byoPhotoTimeline.set([]);
  byoPhotosLoading.set(false);
  // _dataProvider intentionally NOT cleared here — it's app-scoped (set
  // by ByoApp on unlock, set to null on lock). The dashboard's onDestroy
  // also calls this fn on tab-switch remounts (Settings → Photos), and
  // wiping the provider mid-session would race ByoPhotoTimeline.onMount
  // (which fires before the parent dashboard's onMount can re-wire it),
  // leaving the timeline empty until a manual reload.
}

// ── Derived ────────────────────────────────────────────────────────────────

export const hasByoPhotos = derived(byoPhotoTimeline, ($t) => $t.length > 0);
