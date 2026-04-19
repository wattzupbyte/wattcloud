/**
 * BYO Upload Queue Store
 *
 * Mirrors the managed uploadQueue interface so BYO UI components
 * (ByoUploadQueue, ByoDashboard) can use the same patterns.
 *
 * ByoDashboard adds items via addFile(), calls updateProgress() and
 * setStatus() as DataProvider.uploadFile() progresses. The store is
 * pure state — no upload logic lives here.
 *
 * Pause/resume: each item has a PauseController. The upload loop in
 * ByoUploadStream checks pauseSignal.isPaused() between chunk iterations.
 * The WASM ByoUploadFlow session stays alive while paused — no re-encryption.
 *
 * Retry: ByoDashboard registers a retryCallback per item. retryUpload()
 * resets the PauseController and calls the callback to restart the upload.
 */

import { writable, derived } from 'svelte/store';
import type { UploadItem, UploadItemGroup } from '../../stores/uploadQueue';

// ── PauseController ──────────────────────────────────────────────────────────
// Shared by byoDownloadQueue too.

export class PauseController {
  private _paused = false;
  private _cancelled = false;
  private _resolve: (() => void) | null = null;

  isPaused(): boolean { return this._paused && !this._cancelled; }
  isCancelled(): boolean { return this._cancelled; }

  pause(): void {
    if (!this._cancelled) this._paused = true;
  }

  resume(): void {
    this._paused = false;
    const r = this._resolve;
    this._resolve = null;
    r?.();
  }

  cancel(): void {
    this._cancelled = true;
    this._paused = false;
    const r = this._resolve;
    this._resolve = null;
    r?.();
  }

  /** Resolves when resume() or cancel() is called. Call isPaused() first. */
  wait(): Promise<void> {
    if (!this._paused || this._cancelled) return Promise.resolve();
    return new Promise<void>((resolve) => { this._resolve = resolve; });
  }
}

// ── ByoUploadItem ─────────────────────────────────────────────────────────────

export interface ByoUploadItem extends UploadItem {
  bytesDone: number;
  bytesTotal: number;
  /** Upload phase — drives which action button is shown. */
  phase: 'idle' | 'encrypting' | 'uploading' | 'paused';
  retryCount: number;
  /** Timestamp (ms) when the upload first became active — used for ETA. */
  startedAt: number | null;
}

// ── Store ─────────────────────────────────────────────────────────────────────

interface ByoUploadQueueState {
  items: ByoUploadItem[];
}

// Non-reactive maps: hold live controller objects that must not trigger renders.
const pauseControllers = new Map<string, PauseController>();
const retryCallbacks = new Map<string, () => void>();

function createByoUploadQueue() {
  const { subscribe, update, set } = writable<ByoUploadQueueState>({ items: [] });

  function generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  function addFile(
    file: File,
    folderId: number | null,
    opts?: { overrideName?: string; uploadGroup?: UploadItemGroup },
  ): string {
    const id = generateId();
    pauseControllers.set(id, new PauseController());
    const newItem: ByoUploadItem = {
      id,
      file,
      folderId,
      status: 'pending',
      progress: 0,
      createdAt: new Date(),
      overrideName: opts?.overrideName,
      uploadGroup: opts?.uploadGroup,
      bytesDone: 0,
      bytesTotal: file.size,
      phase: 'idle',
      retryCount: 0,
      startedAt: null,
    };
    update((s) => ({ items: [...s.items, newItem] }));
    return id;
  }

  function addFiles(files: File[], folderId: number | null): void {
    const newItems: ByoUploadItem[] = files.map((file) => {
      const id = generateId();
      pauseControllers.set(id, new PauseController());
      return {
        id,
        file,
        folderId,
        status: 'pending',
        progress: 0,
        createdAt: new Date(),
        bytesDone: 0,
        bytesTotal: file.size,
        phase: 'idle',
        retryCount: 0,
        startedAt: null,
      };
    });
    update((s) => ({ items: [...s.items, ...newItems] }));
  }

  function removeItem(id: string): void {
    pauseControllers.get(id)?.cancel();
    pauseControllers.delete(id);
    retryCallbacks.delete(id);
    update((s) => ({ items: s.items.filter((i) => i.id !== id) }));
  }

  function removeGroup(groupId: string): void {
    update((s) => {
      s.items
        .filter((i) => i.uploadGroup?.id === groupId)
        .forEach((i) => {
          pauseControllers.get(i.id)?.cancel();
          pauseControllers.delete(i.id);
          retryCallbacks.delete(i.id);
        });
      return { items: s.items.filter((i) => i.uploadGroup?.id !== groupId) };
    });
  }

  function clearCompleted(): void {
    update((s) => {
      s.items
        .filter((i) => i.status === 'completed')
        .forEach((i) => {
          pauseControllers.delete(i.id);
          retryCallbacks.delete(i.id);
        });
      return { items: s.items.filter((i) => i.status !== 'completed') };
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

  function setStatus(id: string, status: UploadItem['status'], error?: string): void {
    update((s) => ({
      items: s.items.map((i) => (i.id === id ? { ...i, status, error } : i)),
    }));
  }

  /**
   * Set the upload phase.
   * Calling setPhase('uploading') while an item is 'paused' is a no-op —
   * resume() transitions out of paused.
   */
  function setPhase(id: string, phase: ByoUploadItem['phase']): void {
    update((s) => ({
      items: s.items.map((i) => {
        if (i.id !== id) return i;
        if (i.phase === 'paused' && phase !== 'paused') return i;
        const startedAt =
          (phase === 'encrypting' || phase === 'uploading') && !i.startedAt
            ? Date.now()
            : i.startedAt;
        return { ...i, phase, startedAt };
      }),
    }));
  }

  function updateBytes(id: string, done: number, total: number): void {
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id ? { ...i, bytesDone: done, bytesTotal: total } : i,
      ),
    }));
  }

  /** Returns the live PauseController for the given item (use in UploadStream options). */
  function getPauseSignal(id: string): PauseController | undefined {
    return pauseControllers.get(id);
  }

  function pauseUpload(id: string): void {
    pauseControllers.get(id)?.pause();
    update((s) => ({
      items: s.items.map((i) => (i.id === id ? { ...i, phase: 'paused' } : i)),
    }));
  }

  function resumeUpload(id: string): void {
    pauseControllers.get(id)?.resume();
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id && i.phase === 'paused' ? { ...i, phase: 'uploading' } : i,
      ),
    }));
  }

  /** Register a callback that re-runs the upload from the beginning. */
  function registerRetry(id: string, fn: () => void): void {
    retryCallbacks.set(id, fn);
  }

  /**
   * Reset state and re-run the upload.
   * Creates a fresh PauseController so the retryCallback picks up the new signal
   * via getPauseSignal() on its first call.
   */
  function retryUpload(id: string): void {
    pauseControllers.set(id, new PauseController());
    update((s) => ({
      items: s.items.map((i) =>
        i.id === id
          ? { ...i, retryCount: i.retryCount + 1, bytesDone: 0, phase: 'idle', startedAt: null, error: undefined }
          : i,
      ),
    }));
    retryCallbacks.get(id)?.();
  }

  /** Mark all in-flight items as interrupted (call on component unmount / vault lock). */
  function markAllInterrupted(): void {
    update((s) => ({
      items: s.items.map((i) =>
        i.status === 'uploading' || i.status === 'encrypting'
          ? { ...i, status: 'error', error: 'Upload was interrupted — please restart', phase: 'idle' }
          : i,
      ),
    }));
  }

  return {
    subscribe,
    addFile,
    addFiles,
    removeItem,
    removeGroup,
    clearCompleted,
    clearAll,
    updateProgress,
    setStatus,
    setPhase,
    updateBytes,
    getPauseSignal,
    pauseUpload,
    resumeUpload,
    registerRetry,
    retryUpload,
    markAllInterrupted,
  };
}

export const byoUploadQueue = createByoUploadQueue();

// Derived stores (same names as managed equivalents)
export const byoUploadQueueItems = derived(byoUploadQueue, ($q) => $q.items);

export const isByoUploading = derived(byoUploadQueue, ($q) =>
  $q.items.some((i) => i.status === 'uploading' || i.status === 'encrypting'),
);

export const byoUploadCompletedCount = derived(
  byoUploadQueue,
  ($q) => $q.items.filter((i) => i.status === 'completed').length,
);

export const byoUploadPendingCount = derived(
  byoUploadQueue,
  ($q) => $q.items.filter((i) => i.status === 'pending').length,
);

export const byoUploadErrorCount = derived(
  byoUploadQueue,
  ($q) => $q.items.filter((i) => i.status === 'error').length,
);
