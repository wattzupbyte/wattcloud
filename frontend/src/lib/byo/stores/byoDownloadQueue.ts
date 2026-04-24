/**
 * BYO Download Queue Store
 *
 * Mirrors the managed downloadQueue interface so BYO UI components
 * (ByoDownloadQueue, ByoDashboard) can use the same patterns.
 *
 * ByoDashboard adds items via addFile(), calls updateBytesDownloaded() and
 * setStatus() as the download stream progresses. The store is pure state —
 * no download logic lives here.
 *
 * Pause/cancel: each item has a PauseController. ByoDashboard's read loop
 * checks isCancelled() and isPaused() between reader.read() calls.
 * Retry: ByoDashboard registers a retryCallback per item.
 */

import { writable, derived } from 'svelte/store';
import type { DownloadItem } from '../../stores/downloadQueue';
import type { IOSSaveHandle } from '../iosSave';
import { PauseController } from './byoUploadQueue';

// ── ByoDownloadItem ───────────────────────────────────────────────────────────

export interface ByoDownloadItem extends DownloadItem {
  bytesDone: number;
  retryCount: number;
  /** Set on iOS only: once the decrypted plaintext is fully buffered
   *  in memory, the handle exposes a `save()` that must be called from
   *  a fresh user-gesture click to open the iOS share sheet. When this
   *  is populated, the item's status is 'ready-to-save'. */
  iosSaveHandle?: IOSSaveHandle;
}

// ── Store ─────────────────────────────────────────────────────────────────────

interface ByoDownloadQueueState {
  items: ByoDownloadItem[];
}

// Non-reactive maps
const pauseControllers = new Map<string, PauseController>();
const retryCallbacks = new Map<string, () => void>();

function createByoDownloadQueue() {
  const { subscribe, update, set } = writable<ByoDownloadQueueState>({ items: [] });

  function generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  function addFile(fileId: number, name: string, totalBytes = 0): string {
    const id = generateId();
    pauseControllers.set(id, new PauseController());
    const newItem: ByoDownloadItem = {
      id,
      type: 'file',
      name,
      fileIds: [fileId],
      folderIds: [],
      status: 'pending',
      progress: 0,
      createdAt: new Date(),
      totalSize: totalBytes,
      totalChunks: 1,
      currentChunk: 0,
      chunkProgress: 0,
      filesProcessed: 0,
      totalFiles: 1,
      cancelRequested: false,
      pauseRequested: false,
      bytesDone: 0,
      retryCount: 0,
    };
    update((s) => ({ items: [...s.items, newItem] }));
    return id;
  }

  function addBulk(fileIds: number[], name: string): string {
    const id = generateId();
    pauseControllers.set(id, new PauseController());
    const newItem: ByoDownloadItem = {
      id,
      type: 'bulk',
      name,
      fileIds,
      folderIds: [],
      status: 'pending',
      progress: 0,
      createdAt: new Date(),
      totalSize: 0,
      totalChunks: 1,
      currentChunk: 0,
      chunkProgress: 0,
      filesProcessed: 0,
      totalFiles: fileIds.length,
      cancelRequested: false,
      pauseRequested: false,
      bytesDone: 0,
      retryCount: 0,
    };
    update((s) => ({ items: [...s.items, newItem] }));
    return id;
  }

  function removeItem(id: string): void {
    pauseControllers.get(id)?.cancel();
    pauseControllers.delete(id);
    retryCallbacks.delete(id);
    // OPFS-backed items need their pending file removed from disk.
    // RAM-backed items and non-iOS items expose a no-op cleanup, so
    // always invoking it is safe.
    update((s) => {
      const item = s.items.find((i) => i.id === id);
      if (item?.iosSaveHandle) {
        void item.iosSaveHandle.cleanup();
      }
      return { items: s.items.filter((i) => i.id !== id) };
    });
  }

  function clearCompleted(): void {
    update((s) => {
      s.items
        .filter((i) => i.status === 'completed' || i.status === 'cancelled')
        .forEach((i) => {
          pauseControllers.delete(i.id);
          retryCallbacks.delete(i.id);
          if (i.iosSaveHandle) void i.iosSaveHandle.cleanup();
        });
      return { items: s.items.filter((i) => i.status !== 'completed' && i.status !== 'cancelled') };
    });
  }

  function clearAll(): void {
    for (const ctrl of pauseControllers.values()) ctrl.cancel();
    pauseControllers.clear();
    retryCallbacks.clear();
    update((s) => {
      for (const i of s.items) {
        if (i.iosSaveHandle) void i.iosSaveHandle.cleanup();
      }
      return { items: [] };
    });
    set({ items: [] });
  }

  function updateProgress(id: string, progress: number): void {
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, progress: Math.min(100, Math.max(0, progress)) } : i,
      ),
    }));
  }

  function setStatus(id: string, status: DownloadItem['status'], error?: string): void {
    update((s) => ({
      items: s.items.map((i) => (i.id === id ? { ...i, status, error } : i)),
    }));
  }

  function updateBytesDownloaded(id: string, done: number, total: number): void {
    const progress = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 50;
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, bytesDone: done, totalSize: total, progress } : i,
      ),
    }));
  }

  function cancelDownload(id: string): void {
    pauseControllers.get(id)?.cancel();
    update((s) => ({
      items: s.items.map((i) => (i.id === id ? { ...i, cancelRequested: true } : i)),
    }));
  }

  function pauseDownload(id: string): void {
    pauseControllers.get(id)?.pause();
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, status: 'paused', pauseRequested: true } : i,
      ),
    }));
  }

  function resumeDownload(id: string): void {
    pauseControllers.get(id)?.resume();
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, status: 'downloading', pauseRequested: false } : i,
      ),
    }));
  }

  function registerRetry(id: string, fn: () => void): void {
    retryCallbacks.set(id, fn);
  }

  function retryDownload(id: string): void {
    pauseControllers.set(id, new PauseController());
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id
          ? { ...i, retryCount: i.retryCount + 1, bytesDone: 0, progress: 0, cancelRequested: false, pauseRequested: false, error: undefined }
          : i,
      ),
    }));
    retryCallbacks.get(id)?.();
  }

  function getPauseSignal(id: string): PauseController | undefined {
    return pauseControllers.get(id);
  }

  function updateFilesProcessed(id: string, filesProcessed: number, totalFiles: number): void {
    update((s) => ({
      items: s.items.map((i) => (i.id === id ? { ...i, filesProcessed, totalFiles } : i)),
    }));
  }

  /** iOS-only: attach the buffered File + gesture-bound save() callback
   *  and flip the item into 'ready-to-save'. The queue UI reads this
   *  to render the Save button. */
  function setIOSSaveHandle(id: string, handle: IOSSaveHandle): void {
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, iosSaveHandle: handle, status: 'ready-to-save' } : i,
      ),
    }));
  }

  /** Clear the handle after the user taps Save or the item is removed. */
  function clearIOSSaveHandle(id: string): void {
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, iosSaveHandle: undefined } : i,
      ),
    }));
  }

  return {
    subscribe,
    addFile,
    addBulk,
    removeItem,
    clearCompleted,
    clearAll,
    updateProgress,
    setStatus,
    updateBytesDownloaded,
    cancelDownload,
    pauseDownload,
    resumeDownload,
    registerRetry,
    retryDownload,
    getPauseSignal,
    updateFilesProcessed,
    setIOSSaveHandle,
    clearIOSSaveHandle,
  };
}

export const byoDownloadQueue = createByoDownloadQueue();

// Derived stores
export const byoDownloadQueueItems = derived(byoDownloadQueue, ($q) => $q.items);

export const isByoDownloading = derived(byoDownloadQueue, ($q) =>
  $q.items.some((i) => i.status === 'downloading' || i.status === 'decrypting'),
);

export const byoDownloadCompletedCount = derived(
  byoDownloadQueue,
  ($q) => $q.items.filter((i) => i.status === 'completed').length,
);

export const byoDownloadPendingCount = derived(
  byoDownloadQueue,
  ($q) => $q.items.filter((i) => i.status === 'pending').length,
);

export const byoDownloadErrorCount = derived(
  byoDownloadQueue,
  ($q) => $q.items.filter((i) => i.status === 'error').length,
);
