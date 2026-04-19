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
import { PauseController } from './byoUploadQueue';

// ── ByoDownloadItem ───────────────────────────────────────────────────────────

export interface ByoDownloadItem extends DownloadItem {
  bytesDone: number;
  retryCount: number;
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
    update((s) => ({ items: s.items.filter((i) => i.id !== id) }));
  }

  function clearCompleted(): void {
    update((s) => {
      s.items
        .filter((i) => i.status === 'completed' || i.status === 'cancelled')
        .forEach((i) => {
          pauseControllers.delete(i.id);
          retryCallbacks.delete(i.id);
        });
      return { items: s.items.filter((i) => i.status !== 'completed' && i.status !== 'cancelled') };
    });
  }

  function clearAll(): void {
    for (const ctrl of pauseControllers.values()) ctrl.cancel();
    pauseControllers.clear();
    retryCallbacks.clear();
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
