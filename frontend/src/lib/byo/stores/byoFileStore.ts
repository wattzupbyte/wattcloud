/**
 * BYO File and Folder Stores
 *
 * Svelte writable stores for files and folders loaded from the in-memory
 * vault SQLite database. Replaces the managed-mode files/folders stores
 * for BYO mode.
 *
 * All filenames arrive encrypted from SQLite. Decryption is batched and
 * runs via the BYO worker (byoWorkerClient). Decrypted names are stored
 * in the respective entry's decrypted_name field.
 *
 * Factory: createByoFileStore(db, workerClient) — pass in the sql.js
 * Database and the worker client when the vault is unlocked.
 */

import { writable, derived, type Readable } from 'svelte/store';
import type { FileEntry, FolderEntry } from '../DataProvider';

// ── Stores ──────────────────────────────────────────────────────────────────

export const byoFiles = writable<FileEntry[]>([]);
export const byoFolders = writable<FolderEntry[]>([]);
export const byoCurrentFolder = writable<number | null>(null);
export const byoFilesLoading = writable<boolean>(false);

// Selection state (mirrors managed-mode pattern)
export const byoSelectedFiles = writable<Set<number>>(new Set());
export const byoSelectedFolders = writable<Set<number>>(new Set());
export const byoSelectionMode = writable<boolean>(false);

// ── Derived ────────────────────────────────────────────────────────────────

export const byoSelectedFilesCount: Readable<number> = derived(
  byoSelectedFiles,
  ($s) => $s.size,
);
export const byoSelectedFoldersCount: Readable<number> = derived(
  byoSelectedFolders,
  ($s) => $s.size,
);
export const byoTotalSelectedCount: Readable<number> = derived(
  [byoSelectedFilesCount, byoSelectedFoldersCount],
  ([$f, $d]) => $f + $d,
);

// ── Selection helpers ──────────────────────────────────────────────────────

export function toggleByoFileSelection(fileId: number): void {
  byoSelectedFiles.update((s) => {
    const next = new Set(s);
    if (next.has(fileId)) next.delete(fileId);
    else next.add(fileId);
    return next;
  });
}

export function toggleByoFolderSelection(folderId: number): void {
  byoSelectedFolders.update((s) => {
    const next = new Set(s);
    if (next.has(folderId)) next.delete(folderId);
    else next.add(folderId);
    return next;
  });
}

export function clearByoSelection(): void {
  byoSelectedFiles.set(new Set());
  byoSelectedFolders.set(new Set());
  byoSelectionMode.set(false);
}

// ── Store reset ────────────────────────────────────────────────────────────

/** Clear all BYO file/folder state on vault lock. */
export function resetByoFileStores(): void {
  byoFiles.set([]);
  byoFolders.set([]);
  byoCurrentFolder.set(null);
  byoFilesLoading.set(false);
  clearByoSelection();
}
