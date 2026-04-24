import { writable, derived } from 'svelte/store';

export interface Folder {
  id: number;
  parent_id: number | null;
  name: string;  // Encrypted name (stored in database)
  decrypted_name?: string;  // Decrypted name (for display)
  path: string;  // Encrypted path
  decrypted_path?: string;  // Decrypted path (for display)
  encrypted_key?: string;  // Base64 encoded encrypted filename key
  created_at: string;
  updated_at: string;
}

export interface FileRecord {
  id: number;
  folder_id: number | null;
  name: string;  // Encrypted filename (stored in database)
  decrypted_name?: string;  // Decrypted filename (for display)
  size: number;
  storage_path: string;
  encrypted_key: string;  // Base64 encoded
  encrypted_filename_key?: string;  // Base64 encoded encrypted filename key
  created_at: string;
  updated_at: string;
}

export const folders = writable<Folder[]>([]);
export const files = writable<FileRecord[]>([]);
export const currentFolder = writable<number | null>(null);

// Selection stores for multi-select functionality
export const selectedFiles = writable<Set<number>>(new Set());
export const selectedFolders = writable<Set<number>>(new Set());
export const selectionMode = writable(false);

// Derived stores for selection counts
export const selectedFilesCount = derived(selectedFiles, $files => $files.size);
export const selectedFoldersCount = derived(selectedFolders, $folders => $folders.size);
export const totalSelectedCount = derived(
  [selectedFilesCount, selectedFoldersCount],
  ([$files, $folders]) => $files + $folders
);

// Helper functions for selection
export function toggleFileSelection(fileId: number) {
  selectedFiles.update(selected => {
    const newSelected = new Set(selected);
    if (newSelected.has(fileId)) {
      newSelected.delete(fileId);
    } else {
      newSelected.add(fileId);
    }
    return newSelected;
  });
}

export function toggleFolderSelection(folderId: number) {
  selectedFolders.update(selected => {
    const newSelected = new Set(selected);
    if (newSelected.has(folderId)) {
      newSelected.delete(folderId);
    } else {
      newSelected.add(folderId);
    }
    return newSelected;
  });
}

export function selectAllFiles(fileIds: number[]) {
  selectedFiles.set(new Set(fileIds));
}

export function selectAllFolders(folderIds: number[]) {
  selectedFolders.set(new Set(folderIds));
}

export function clearFileSelection() {
  selectedFiles.set(new Set());
}

export function clearFolderSelection() {
  selectedFolders.set(new Set());
}

export function clearAllSelection() {
  selectedFiles.set(new Set());
  selectedFolders.set(new Set());
  selectionMode.set(false);
}

export function isFileSelected(fileId: number): boolean {
  let selected = false;
  selectedFiles.subscribe(s => { selected = s.has(fileId); })();
  return selected;
}

export function isFolderSelected(folderId: number): boolean {
  let selected = false;
  selectedFolders.subscribe(s => { selected = s.has(folderId); })();
  return selected;
}
