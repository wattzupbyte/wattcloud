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
    const files = await _dataProvider.listImageFiles();
    byoPhotoTimeline.set(groupByDay(files));
  } catch (e) {
    console.error('[byoPhotos] failed to load timeline:', e);
    byoPhotoTimeline.set([]);
  } finally {
    byoPhotosLoading.set(false);
  }
}

function groupByDay(files: FileEntry[]): ByoTimelineGroup[] {
  const map = new Map<string, ByoTimelineGroup>();

  for (const file of files) {
    const date = new Date(file.created_at);
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

const THUMB_MAX_PX = 400;

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
    const blob = await canvas.convertToBlob({ type: 'image/webp', quality: 0.82 });
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
        0.82,
      );
    });
    return blob.size > 0 ? blob : new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  }
}

export async function loadByoThumbnail(file: FileEntry): Promise<string | null> {
  const cache = get(byoThumbnailCache);
  if (cache.has(file.id)) return cache.get(file.id)!;

  if (!_dataProvider) return null;

  let data: Uint8Array | null = null;
  try {
    const stream = await _dataProvider.downloadFile(file.id);
    data = await streamToUint8Array(stream);

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
    return url;
  } catch (e) {
    console.error(`[byoPhotos] thumbnail load failed for file ${file.id}:`, e);
    return null;
  } finally {
    if (data) data.fill(0);
  }
}

// ── Reset ──────────────────────────────────────────────────────────────────

export function resetByoPhotos(): void {
  // Revoke all cached blob URLs to avoid leaks
  const cache = get(byoThumbnailCache);
  cache.forEach((url) => URL.revokeObjectURL(url));
  byoThumbnailCache.set(new Map());
  byoPhotoTimeline.set([]);
  byoPhotosLoading.set(false);
  _dataProvider = null;
}

// ── Derived ────────────────────────────────────────────────────────────────

export const hasByoPhotos = derived(byoPhotoTimeline, ($t) => $t.length > 0);
