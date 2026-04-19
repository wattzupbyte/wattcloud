<script lang="ts">
  /**
   * ByoDashboard — BYO mode file manager dashboard.
   *
   * Feature-parity with managed Dashboard. Reuses managed components where
   * possible; injects BYO callbacks for store-coupled components.
   *
   * Gets DataProvider from Svelte context ('byo:dataProvider') set by ByoApp.
   */
  import { onMount, onDestroy, getContext, tick } from 'svelte';
  import { fly, fade, slide } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import { get } from 'svelte/store';
  import type { DataProvider, FileEntry, FolderEntry } from '../../byo/DataProvider';
  import { byoFiles, byoFolders, byoCurrentFolder, byoFilesLoading, byoSelectedFiles, byoSelectedFolders, byoSelectionMode, toggleByoFileSelection, toggleByoFolderSelection, clearByoSelection, resetByoFileStores } from '../../byo/stores/byoFileStore';
  import { byoUploadQueue, isByoUploading, byoUploadErrorCount } from '../../byo/stores/byoUploadQueue';
  import { byoDownloadQueue, isByoDownloading, byoDownloadErrorCount } from '../../byo/stores/byoDownloadQueue';
  import { derived } from 'svelte/store';
  import { setByoSearchDataProvider, clearByoSearch, byoSearchQuery, byoSearchResults, hasByoActiveFilters, setByoSearchQuery, setByoFileTypeFilter } from '../../byo/stores/byoSearch';
  import { setByoPhotosDataProvider, resetByoPhotos } from '../../byo/stores/byoPhotos';
  import { vaultStore, canOperate, isVaultDirty } from '../../byo/stores/vaultStore';
  import type { ProviderMeta } from '../../byo/stores/vaultStore';
  import AddProviderSheet from './AddProviderSheet.svelte';
  import { OfflineDetector } from '../../byo/OfflineDetector';
  import { getProviders, getPrimaryProviderId } from '../../byo/VaultLifecycle';
  import { TrashManager } from '../../byo/TrashManager';
  import type { StorageProvider } from '@secure-cloud/byo';
  import House from 'phosphor-svelte/lib/House';
  import CaretRight from 'phosphor-svelte/lib/CaretRight';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import FolderPlus from 'phosphor-svelte/lib/FolderPlus';
  import Star from 'phosphor-svelte/lib/Star';
  import Image from 'phosphor-svelte/lib/Image';
  import CloudSlash from 'phosphor-svelte/lib/CloudSlash';
  import OfflineBanner from './OfflineBanner.svelte';

  // Reused managed components
  import DashboardHeader from '../DashboardHeader.svelte';
  import BottomNav from '../BottomNav.svelte';
  import FAB from '../FAB.svelte';
  import Drawer from '../Drawer.svelte';
  import SelectionToolbar from '../SelectionToolbar.svelte';
  import SortControl from '../SortControl.svelte';
  import type { SortBy as SortByT, SortDirection as SortDirT } from '../../stores/sorting';
  import FolderTile from '../FolderTile.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import MoveCopyDialog from '../MoveCopyDialog.svelte';

  // Components with BYO callbacks
  import FileListSvelte from '../FileList.svelte';
  import FilePreview from '../FilePreview.svelte';
  import FolderTree from '../FolderTree.svelte';
  import MoveCopyDialog_ from '../MoveCopyDialog.svelte';

  import EncryptionStrip from '../EncryptionStrip.svelte';
  import HexShield from '../HexShield.svelte';
  import PullToRefresh from './PullToRefresh.svelte';

  // BYO-specific components
  import ByoUploadQueue from './ByoUploadQueue.svelte';
  import ByoDownloadQueue from './ByoDownloadQueue.svelte';
  import ShareLinkSheet from './ShareLinkSheet.svelte';
  import ProviderContextSheet from './ProviderContextSheet.svelte';
  import ByoPhotoTimeline from './ByoPhotoTimeline.svelte';
  import ByoFileDetails from './ByoFileDetails.svelte';
  import ProviderMoveSheet from './ProviderMoveSheet.svelte';

  export let onLock: () => void;
  export let onSettings: () => void;
  export let onTrash: () => void;

  const dataProvider = getContext<DataProvider>('byo:dataProvider');
  const storageProvider = getContext<StorageProvider>('byo:storageProvider');

  // Derived encryption state for the status strip (§29.4).
  // Priority: error > offline > syncing > idle.
  const byoEncryptionState = derived(
    [vaultStore, isByoUploading, isByoDownloading, byoUploadErrorCount, byoDownloadErrorCount],
    ([$vault, $uploading, $downloading, $upErr, $dlErr]) => {
      const providers = $vault.providers;
      if ($upErr > 0 || $dlErr > 0 || providers.some((p) => p.status === 'error' || p.status === 'unauthorized')) return 'error' as const;
      if (providers.some((p) => p.status === 'offline')) return 'offline' as const;
      if ($uploading || $downloading || providers.some((p) => p.status === 'syncing')) return 'syncing' as const;
      return 'idle' as const;
    },
  );

  type ViewType = 'files' | 'photos' | 'favorites';

  let view: ViewType = 'files';
  let loading = false;
  let error = '';
  let moveRevokedMsg = '';
  let moveRevokedTimer: ReturnType<typeof setTimeout> | null = null;
  let showSearch = false;
  let drawerOpen = false;
  let sortBy: 'name' | 'date' | 'size' = 'name';
  let sortDir: 'asc' | 'desc' = 'asc';

  // Folder navigation stack
  let folderStack: Array<{ id: number | null; name: string }> = [{ id: null, name: 'Home' }];
  $: currentFolderId = folderStack[folderStack.length - 1].id;

  // Modals
  let showNewFolderModal = false;
  let newFolderName = '';
  let creatingFolder = false;

  let showDeleteModal = false;
  let deleteTarget: { type: 'file' | 'folder'; id: number; name: string } | null = null;
  let deleteLoading = false;

  let showMoveCopyDialog = false;
  let moveCopyMode: 'move' | 'copy' = 'move';

  // Cross-provider move
  let showProviderMoveSheet = false;
  let crossMoveProgress: { done: number; total: number } | null = null;
  let crossMoveErrors: { fileId: number; fileName: string; error: string }[] = [];
  let crossMoveSucceeded: number | null = null;
  let crossMoveDestProviderId = '';

  let previewFile: FileEntry | null = null;
  let previewOpen = false;

  let showFabMenu = false;
  let folderInput: HTMLInputElement | null = null;

  // File details modal
  let showDetailsModal = false;
  let detailsFile: FileEntry | null = null;

  // Share link sheet
  let showShareSheet = false;
  let shareFile: FileEntry | null = null;

  // Favorites
  let favoriteFileIds: Set<number> = new Set();
  let favoriteFolderIds: Set<number> = new Set();
  let favoriteFiles: FileEntry[] = [];
  let favoriteFolders: FolderEntry[] = [];

  let storageUsed = 0;
  let storageQuota: number | null = null;

  // Services
  let offlineDetector: OfflineDetector | null = null;
  let trashManager: TrashManager | null = null;

  // ── Selection ripple (§29.3.4) ─────────────────────────────────────────
  // Record the last pointerdown inside .main-content so we can burst a ring
  // from that spot when long-press enters selection mode.
  let rippleX: number | null = null;
  let rippleY: number | null = null;
  let rippleKey = 0;
  let lastSelectionMode = false;
  const reducedMotion = typeof window !== 'undefined'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function onMainPointerDown(e: PointerEvent) {
    rippleX = e.clientX;
    rippleY = e.clientY;
  }

  // DashboardHeader uses plural tokens ('images', 'documents'…) matching
  // the managed search. BYO's DataProvider expects singular ('image',
  // 'document'…). Map once at the boundary.
  const FILE_TYPE_MAP: Record<string, string | null> = {
    '': null,
    images: 'image',
    documents: 'document',
    videos: 'video',
    archives: 'archive',
    audio: 'audio',
    code: 'code',
    folders: null, // BYO search doesn't filter folders separately
  };
  function normalizeFileType(v: string | undefined | null): string | null {
    if (!v) return null;
    return FILE_TYPE_MAP[v] ?? null;
  }

  $: {
    const now = $byoSelectionMode;
    if (now && !lastSelectionMode && rippleX !== null && rippleY !== null && !reducedMotion) {
      rippleKey++; // force re-render of the ripple element
    }
    lastSelectionMode = now;
  }

  // Per-provider offline state
  $: activeProvider = $vaultStore.providers.find(p => p.providerId === $vaultStore.activeProviderId) ?? null;
  $: activeProviderOffline = activeProvider?.status === 'offline' || activeProvider?.status === 'error' || activeProvider?.status === 'unauthorized';
  $: offlineProviderCount = $vaultStore.providers.filter(p => p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized').length;
  $: canWrite = !activeProviderOffline && $canOperate;

  // Retry ping for active provider
  let retrying = false;
  async function retryActiveProvider() {
    if (!activeProvider || retrying) return;
    retrying = true;
    try {
      // Force immediate re-ping by updating OfflineDetector with current providers
      if (offlineDetector) {
        offlineDetector.updateProviders(getProviders(), getPrimaryProviderId());
      }
      // Brief wait to let the ping settle
      await new Promise(r => setTimeout(r, 2000));
    } finally {
      retrying = false;
    }
  }

  // Derived selection state for FileList selectionContext
  $: selectionContext = {
    isSelectionMode: $byoSelectionMode,
    selectedFiles: $byoSelectedFiles,
    toggle: toggleByoFileSelection,
    selectAll: (ids: number[]) => byoSelectedFiles.set(new Set(ids)),
    clear: clearByoSelection,
  };

  // Files/folders for current folder
  let currentFiles: FileEntry[] = [];
  let currentFolders: FolderEntry[] = [];

  $: sortedFiles = sortEntries(
    view === 'favorites'
      ? favoriteFiles
      : $hasByoActiveFilters ? ($byoSearchResults as unknown as FileEntry[]) : currentFiles,
  );
  $: sortedFolders = view === 'favorites'
    ? sortFolders(favoriteFolders)
    : $hasByoActiveFilters ? [] : sortFolders(currentFolders);

  // Sorting state for SortControl
  $: sortingState = { by: sortBy as SortByT, direction: (sortDir === 'asc' ? 'up' : 'down') as SortDirT };
  function onSortByChange(by: SortByT) { sortBy = by; }
  function onSortDirChange(dir: SortDirT) { sortDir = dir === 'up' ? 'asc' : 'desc'; }
  function onToggleSortDir() { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }

  // Typed aliases for template use (Svelte 4 / Acorn doesn't support `as` casts in templates)
  $: sortedFilesAny = sortedFiles as unknown as any[];
  $: byoFoldersAny = $byoFolders as unknown as any[];
  // Scoped folder list for MoveCopyDialog — only folders belonging to the active provider.
  $: activeFolders = ($byoFolders as unknown as FolderEntry[]).filter(
    (f) => !f.provider_id || f.provider_id === ($vaultStore.activeProviderId ?? ''),
  );
  $: activeFoldersAny = activeFolders as unknown as any[];
  $: previewFileAny = previewFile as unknown as any;
  $: favoriteFilesAny = favoriteFiles as unknown as any[];
  $: detailsFolders = [...currentFolders, ...($byoFolders as unknown as FolderEntry[])];
  $: createFolderAny = handleByoCreateFolder as any;

  function sortEntries(files: FileEntry[]): FileEntry[] {
    return [...files].sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'name') cmp = a.decrypted_name.localeCompare(b.decrypted_name);
      else if (sortBy === 'date') cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      else if (sortBy === 'size') cmp = a.size - b.size;
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }

  function sortFolders(folders: FolderEntry[]): FolderEntry[] {
    return [...folders].sort((a, b) =>
      sortDir === 'asc'
        ? a.decrypted_name.localeCompare(b.decrypted_name)
        : b.decrypted_name.localeCompare(a.decrypted_name),
    );
  }

  // ── Data loading ───────────────────────────────────────────────────────────

  async function loadCurrentFolder() {
    loading = true;
    error = '';
    try {
      const [files, folders] = await Promise.all([
        dataProvider.listFiles(currentFolderId),
        dataProvider.listFolders(currentFolderId),
      ]);
      currentFiles = files;
      currentFolders = folders;
    } catch (e: any) {
      error = e.message || 'Failed to load files';
    } finally {
      loading = false;
    }
  }

  async function loadFavorites() {
    try {
      const favs = await dataProvider.getFavorites();
      favoriteFiles = favs.files;
      favoriteFolders = favs.folders;
      favoriteFileIds = new Set(favs.files.map((f) => f.id));
      favoriteFolderIds = new Set(favs.folders.map((f) => f.id));
    } catch { /* ignore */ }
  }

  async function loadStorageUsage() {
    try {
      const usage = await dataProvider.getStorageUsage();
      storageUsed = usage.used;
      storageQuota = usage.quota;
    } catch { /* ignore */ }
  }

  // ── Navigation ─────────────────────────────────────────────────────────────

  function openFolder(folder: FolderEntry) {
    folderStack = [...folderStack, { id: folder.id, name: folder.decrypted_name }];
  }

  function navigateToBreadcrumb(index: number) {
    folderStack = folderStack.slice(0, index + 1);
  }

  $: {
    // Reload when current folder changes
    if (typeof currentFolderId !== 'undefined') {
      loadCurrentFolder();
    }
  }

  // ── File operations ────────────────────────────────────────────────────────

  async function handleRenameFile(fileId: number, newName: string) {
    await dataProvider.renameFile(fileId, newName);
    await loadCurrentFolder();
  }

  async function handleCreateFolder() {
    const name = newFolderName.trim();
    if (!name) return;
    creatingFolder = true;
    try {
      await dataProvider.createFolder(currentFolderId, name);
      newFolderName = '';
      showNewFolderModal = false;
      await loadCurrentFolder();
    } catch (e: any) {
      error = e.message || 'Failed to create folder';
    } finally {
      creatingFolder = false;
    }
  }

  async function handleRenameFolder(folderId: number, newName: string) {
    await dataProvider.renameFolder(folderId, newName);
    await loadCurrentFolder();
  }

  async function handleDeleteFolder(folderId: number) {
    await dataProvider.deleteFolder(folderId);
    await loadCurrentFolder();
  }

  function promptDelete(type: 'file' | 'folder', id: number, name: string) {
    deleteTarget = { type, id, name };
    showDeleteModal = true;
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    deleteLoading = true;
    try {
      if (deleteTarget.type === 'file') {
        await dataProvider.deleteFile(deleteTarget.id);
      } else {
        await dataProvider.deleteFolder(deleteTarget.id);
      }
      await loadCurrentFolder();
      showDeleteModal = false;
      deleteTarget = null;
    } catch (e: any) {
      error = e.message || 'Delete failed';
    } finally {
      deleteLoading = false;
    }
  }

  async function handleToggleFavorite(type: 'file' | 'folder', id: number) {
    const nowFav = await dataProvider.toggleFavorite(type, id);
    if (type === 'file') {
      const s = new Set(favoriteFileIds);
      if (nowFav) s.add(id); else s.delete(id);
      favoriteFileIds = s;
    } else {
      const s = new Set(favoriteFolderIds);
      if (nowFav) s.add(id); else s.delete(id);
      favoriteFolderIds = s;
    }
    await loadFavorites();
  }

  async function bulkToggleFavorite(makeFavorite: boolean) {
    const fileIds = [...get(byoSelectedFiles)];
    const folderIds = [...get(byoSelectedFolders)];
    for (const id of fileIds) {
      const isFav = favoriteFileIds.has(id);
      if (makeFavorite !== isFav) await dataProvider.toggleFavorite('file', id);
    }
    for (const id of folderIds) {
      const isFav = favoriteFolderIds.has(id);
      if (makeFavorite !== isFav) await dataProvider.toggleFavorite('folder', id);
    }
    await loadFavorites();
    clearByoSelection();
  }

  // ── Upload ─────────────────────────────────────────────────────────────────

  async function handleFiles(files: FileList | File[]) {
    const fileList = Array.from(files);
    for (const file of fileList) {
      const folderId = currentFolderId;
      const itemId = byoUploadQueue.addFile(file, folderId);

      const runUpload = async () => {
        byoUploadQueue.setStatus(itemId, 'encrypting');
        byoUploadQueue.setPhase(itemId, 'encrypting');
        try {
          await dataProvider.uploadFile(
            folderId,
            file,
            (bytes) => {
              const progress = file.size > 0 ? Math.round((bytes / file.size) * 90) : 45;
              byoUploadQueue.updateProgress(itemId, progress);
              byoUploadQueue.updateBytes(itemId, bytes, file.size);
              byoUploadQueue.setStatus(itemId, 'uploading');
              byoUploadQueue.setPhase(itemId, 'uploading');
            },
            { pauseSignal: byoUploadQueue.getPauseSignal(itemId) },
          );
          byoUploadQueue.updateProgress(itemId, 100);
          byoUploadQueue.updateBytes(itemId, file.size, file.size);
          byoUploadQueue.setStatus(itemId, 'completed');
          byoUploadQueue.setPhase(itemId, 'idle');
          await loadCurrentFolder();
        } catch (e: any) {
          byoUploadQueue.setStatus(itemId, 'error', e.message || 'Upload failed');
          byoUploadQueue.setPhase(itemId, 'idle');
        }
      };

      byoUploadQueue.registerRetry(itemId, runUpload);
      runUpload();
    }
  }

  function handleFabUpload() {
    showFabMenu = false;
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.onchange = () => { if (input.files) handleFiles(input.files); };
    input.click();
  }

  function handleFabUploadFolder() {
    showFabMenu = false;
    folderInput?.click();
  }

  function generateUniqueName(name: string, existing: Set<string>): string {
    if (!existing.has(name)) return name;
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.substring(0, dot) : name;
    const ext = dot > 0 ? name.substring(dot) : '';
    let n = 1;
    while (existing.has(`${base} (${n})${ext}`)) n++;
    return `${base} (${n})${ext}`;
  }

  async function onFolderSelected(event: Event) {
    const target = event.target as HTMLInputElement;
    const filesList = target.files;
    if (!filesList || filesList.length === 0) return;
    const selected = Array.from(filesList);
    target.value = '';
    if (!selected[0].webkitRelativePath) return;

    const targetFolderId = currentFolderId;
    const rawRoot = selected[0].webkitRelativePath.split('/')[0];

    const siblings = new Set(currentFolders.map((f) => f.decrypted_name));
    const rootName = generateUniqueName(rawRoot, siblings);

    const dirSet = new Set<string>();
    for (const f of selected) {
      const parts = f.webkitRelativePath.split('/');
      for (let d = 1; d < parts.length; d++) dirSet.add(parts.slice(0, d).join('/'));
    }
    const dirPaths = Array.from(dirSet).sort((a, b) => a.split('/').length - b.split('/').length);

    const folderMap = new Map<string, number>();
    try {
      for (const dirPath of dirPaths) {
        const parts = dirPath.split('/');
        const displayName = parts.length === 1 ? rootName : parts[parts.length - 1];
        const parentPath = parts.slice(0, -1).join('/');
        const parentId = parentPath === '' ? targetFolderId : (folderMap.get(parentPath) ?? null);
        const created = await dataProvider.createFolder(parentId, displayName);
        folderMap.set(dirPath, created.id);
      }
    } catch (e: any) {
      error = 'Failed to create folder structure: ' + (e.message || 'Unknown error');
      return;
    }

    await loadCurrentFolder();

    for (const file of selected) {
      const parts = file.webkitRelativePath.split('/');
      const parentDir = parts.slice(0, -1).join('/');
      const folderId = folderMap.get(parentDir) ?? targetFolderId;
      const itemId = byoUploadQueue.addFile(file, folderId);

      const runUpload = async () => {
        byoUploadQueue.setStatus(itemId, 'encrypting');
        byoUploadQueue.setPhase(itemId, 'encrypting');
        try {
          await dataProvider.uploadFile(
            folderId,
            file,
            (bytes) => {
              const progress = file.size > 0 ? Math.round((bytes / file.size) * 90) : 45;
              byoUploadQueue.updateProgress(itemId, progress);
              byoUploadQueue.updateBytes(itemId, bytes, file.size);
              byoUploadQueue.setStatus(itemId, 'uploading');
              byoUploadQueue.setPhase(itemId, 'uploading');
            },
            { pauseSignal: byoUploadQueue.getPauseSignal(itemId) },
          );
          byoUploadQueue.updateProgress(itemId, 100);
          byoUploadQueue.updateBytes(itemId, file.size, file.size);
          byoUploadQueue.setStatus(itemId, 'completed');
          byoUploadQueue.setPhase(itemId, 'idle');
        } catch (e: any) {
          byoUploadQueue.setStatus(itemId, 'error', e.message || 'Upload failed');
          byoUploadQueue.setPhase(itemId, 'idle');
        }
      };

      byoUploadQueue.registerRetry(itemId, runUpload);
      runUpload();
    }
    await loadCurrentFolder();
  }

  function openDetails(fileId: number) {
    const f = sortedFiles.find((x) => x.id === fileId) ?? currentFiles.find((x) => x.id === fileId);
    if (f) {
      detailsFile = f;
      showDetailsModal = true;
    }
  }

  function openShareSheet(fileId: number) {
    const f = sortedFiles.find((x) => x.id === fileId) ?? currentFiles.find((x) => x.id === fileId);
    if (f) { shareFile = f; showShareSheet = true; }
  }

  // ── Download ───────────────────────────────────────────────────────────────

  async function downloadFile(file: FileEntry) {
    const totalBytes = file.size > 0 ? file.size : 0;
    const itemId = byoDownloadQueue.addFile(file.id, file.decrypted_name, totalBytes);

    const runDownload = async () => {
      byoDownloadQueue.setStatus(itemId, 'downloading');
      const ctrl = byoDownloadQueue.getPauseSignal(itemId);
      try {
        const stream = await dataProvider.downloadFile(file.id);
        const reader = stream.getReader();
        const chunks: Uint8Array[] = [];
        let bytesDownloaded = 0;
        try {
          while (true) {
            if (ctrl?.isCancelled()) { reader.cancel(); break; }
            if (ctrl?.isPaused()) { await ctrl.wait(); }
            if (ctrl?.isCancelled()) { reader.cancel(); break; }

            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            bytesDownloaded += value.length;
            byoDownloadQueue.updateBytesDownloaded(itemId, bytesDownloaded, totalBytes);
          }
        } finally {
          reader.releaseLock();
        }

        if (ctrl?.isCancelled()) {
          byoDownloadQueue.setStatus(itemId, 'cancelled');
          return;
        }

        const blob = new Blob(chunks as unknown as BlobPart[], { type: file.mime_type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.decrypted_name;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        byoDownloadQueue.setStatus(itemId, 'completed');
      } catch (e: any) {
        byoDownloadQueue.setStatus(itemId, 'error', e.message || 'Download failed');
      }
    };

    byoDownloadQueue.registerRetry(itemId, runDownload);
    runDownload();
  }

  // ── File preview ───────────────────────────────────────────────────────────

  async function loadFileData(fileId: number): Promise<Blob> {
    const stream = await dataProvider.downloadFile(fileId);
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const file = currentFiles.find((f) => f.id === fileId);
    const mime = file?.mime_type || 'application/octet-stream';
    return new Blob(chunks as unknown as BlobPart[], { type: mime });
  }

  // ── Move/copy ──────────────────────────────────────────────────────────────

  async function handleMoveCopyConfirm(event: CustomEvent<{ destinationId: number | null; mode: 'move' | 'copy' }>) {
    const { destinationId, mode } = event.detail;
    const selectedFileIds = [...get(byoSelectedFiles)];
    if (mode === 'move') {
      for (const id of selectedFileIds) {
        await dataProvider.moveFile(id, destinationId);
      }
    } else if (mode === 'copy') {
      for (const id of selectedFileIds) {
        const src = currentFiles.find((f) => f.id === id) ?? sortedFiles.find((f) => f.id === id);
        if (!src) continue;
        try {
          const stream = await dataProvider.downloadFile(id);
          const reader = stream.getReader();
          const chunks: Uint8Array[] = [];
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
          }
          const blob = new Blob(chunks as unknown as BlobPart[], { type: src.mime_type || 'application/octet-stream' });
          const copyName = src.decrypted_name;
          const file = new File([blob], copyName, { type: blob.type });
          await dataProvider.uploadFile(destinationId, file);
        } catch (e) {
          console.error('[byo] copy failed:', e);
        }
      }
    }
    clearByoSelection();
    showMoveCopyDialog = false;
    await loadCurrentFolder();
  }

  async function handleByoCreateFolder(name: string, parentId: number | null): Promise<FolderEntry> {
    const folder = await dataProvider.createFolder(parentId, name);
    await loadCurrentFolder();
    return folder;
  }

  // ── Cross-provider move ────────────────────────────────────────────────────

  async function handleCrossProviderMove(destProviderId: string, fileIdsOverride?: number[]) {
    crossMoveDestProviderId = destProviderId;
    const fileIds = fileIdsOverride ?? [...get(byoSelectedFiles)];
    if (fileIds.length === 0) { showProviderMoveSheet = false; return; }

    const total = fileIds.length;
    crossMoveProgress = { done: 0, total };
    moveRevokedMsg = '';
    // On retry (fileIdsOverride truthy) preserve prior succeeded count so banner accumulates correctly.
    if (!fileIdsOverride) {
      crossMoveErrors = [];
      crossMoveSucceeded = null;
    }

    let succeeded = 0;
    const errors: typeof crossMoveErrors = [];

    for (const fileId of fileIds) {
      // Resolve display name from the in-memory file list
      const allFiles = [...sortedFiles, ...favoriteFiles];
      const fileEntry = allFiles.find((f) => (f as any).id === fileId);
      const fileName = (fileEntry as any)?.decrypted_name ?? `File #${fileId}`;
      try {
        const result = await (dataProvider as any).crossProviderMove(
          [fileId],
          destProviderId,
        );
        if (result?.revokedShareIds?.length > 0) {
          const n = result.revokedShareIds.length;
          moveRevokedMsg = `${n} share link${n > 1 ? 's were' : ' was'} revoked — re-share from the new location.`;
          if (moveRevokedTimer) clearTimeout(moveRevokedTimer);
          moveRevokedTimer = setTimeout(() => { moveRevokedMsg = ''; }, 6000);
        }
        succeeded++;
      } catch (e: any) {
        const isHmac = /hmac|integrity/i.test(e.message ?? '');
        const isOom = e?.code === 'UNSUPPORTED';
        errors.push({
          fileId,
          fileName,
          error: isHmac
            ? 'Integrity check failed — not copied'
            : isOom
              ? 'File too large (>512 MiB)'
              : (e.message || 'Move failed'),
        });
      }
      crossMoveProgress = { done: succeeded + errors.length, total };
    }

    crossMoveProgress = null;
    crossMoveSucceeded = (fileIdsOverride ? (crossMoveSucceeded ?? 0) : 0) + succeeded;
    crossMoveErrors = errors;

    if (errors.length === 0) {
      clearByoSelection();
      await loadCurrentFolder();
      setTimeout(() => {
        showProviderMoveSheet = false;
        crossMoveSucceeded = null;
      }, 2500);
    }
  }

  function handleMoveRetry(e: CustomEvent<{ fileIds: number[] }>) {
    handleCrossProviderMove(crossMoveDestProviderId, e.detail.fileIds);
  }

  function handleMoveSkipErrors(e: CustomEvent<{ fileId: number }>) {
    crossMoveErrors = crossMoveErrors.filter(err => err.fileId !== e.detail.fileId);
    if (crossMoveErrors.length === 0) {
      if (crossMoveSucceeded !== null && crossMoveSucceeded > 0) {
        loadCurrentFolder();
      }
      showProviderMoveSheet = false;
      crossMoveSucceeded = null;
    }
  }

  // ── Provider switcher (P9) ────────────────────────────────────────────────

  let showAddProvider = false;

  // Provider context sheet (long-press / right-click on chip)
  let contextSheetProvider: ProviderMeta | null = null;
  let longPressTimer: ReturnType<typeof setTimeout> | null = null;

  function openContextSheet(p: ProviderMeta) {
    contextSheetProvider = p;
  }

  function onChipContextMenu(e: MouseEvent, p: ProviderMeta) {
    e.preventDefault();
    openContextSheet(p);
  }

  function onChipPointerDown(e: PointerEvent, p: ProviderMeta) {
    if (e.button !== 0) return;
    longPressTimer = setTimeout(() => { openContextSheet(p); }, 600);
  }

  function onChipPointerUp() {
    if (longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
  }

  async function onProviderAdded(e: CustomEvent<{ providerId?: string }>) {
    showAddProvider = false;
    if (e.detail?.providerId) {
      vaultStore.setActiveProviderId(e.detail.providerId);
      (dataProvider as any).setActiveProviderId?.(e.detail.providerId);
      folderStack = [{ id: null, name: 'Home' }];
      await loadCurrentFolder();
    }
  }

  async function switchProvider(meta: ProviderMeta) {
    if (meta.providerId === $vaultStore.activeProviderId) return;
    vaultStore.setActiveProviderId(meta.providerId);
    (dataProvider as any).setActiveProviderId?.(meta.providerId);
    // Reset folder navigation and reload
    folderStack = [{ id: null, name: 'Home' }];
    await loadCurrentFolder();
  }

  function providerIcon(type: string): string {
    const icons: Record<string, string> = {
      gdrive: 'G', dropbox: 'D', onedrive: 'O', webdav: 'W', sftp: 'S', box: 'B', pcloud: 'P', s3: 'S3',
    };
    return icons[type] ?? '?';
  }

  // ── Nav items ──────────────────────────────────────────────────────────────

  $: navItems = [
    { id: 'files', label: 'Files', icon: 'folder', active: view === 'files' },
    { id: 'photos', label: 'Photos', icon: 'image', active: view === 'photos' },
    { id: 'favorites', label: 'Favorites', icon: 'star', active: view === 'favorites' },
  ];

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  onMount(() => {
    // Wire up BYO stores
    setByoSearchDataProvider(dataProvider);
    setByoPhotosDataProvider(dataProvider);

    // Start per-provider offline detector
    offlineDetector = new OfflineDetector();
    offlineDetector.start(getProviders(), getPrimaryProviderId());

    // Auto-purge trash handled by ByoTrash component

    loadStorageUsage();
    loadCurrentFolder();
    loadFavorites();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return;
      if (event.ctrlKey && event.key === 'a') {
        event.preventDefault();
        const fileIds = sortedFiles.map((f) => f.id);
        byoSelectedFiles.set(new Set(fileIds));
        byoSelectionMode.set(true);
        return;
      }
      if (event.key === 'Escape') {
        event.preventDefault();
        clearByoSelection();
        return;
      }
      if (event.key === 'Delete' && ($byoSelectedFiles.size + $byoSelectedFolders.size) > 0) {
        event.preventDefault();
        const ids = [...get(byoSelectedFiles)];
        if (ids.length > 0) promptDelete('file', ids[0], `${ids.length} file${ids.length !== 1 ? 's' : ''}`);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  });

  onDestroy(() => {
    offlineDetector?.stop();
    clearByoSearch();
    resetByoPhotos();
    resetByoFileStores();
  });

  // ── Drag and drop ──────────────────────────────────────────────────────────

  let isDragOver = false;

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
    isDragOver = true;
  }

  function handleDragLeave() {
    isDragOver = false;
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    isDragOver = false;
    if (e.dataTransfer?.files) handleFiles(e.dataTransfer.files);
  }

  function handleNavigate(v: unknown): void {
    if (v === 'settings') { onSettings(); }
    else { view = v as ViewType; }
  }
</script>

<div
  class="byo-dashboard"
  on:dragover={handleDragOver}
  on:dragleave={handleDragLeave}
  on:drop={handleDrop}
  role="main"
>
  <!-- Header — search is driven directly by the shared DashboardHeader
       overlay; we map its plural file-type tokens to BYO's singular
       enum so both search UXes collapse to one. -->
  <DashboardHeader
    userName=""
    isAdmin={false}
    {showSearch}
    showSearchPanel={true}
    searchQuery={$byoSearchQuery}
    currentView={view}
    navTabs={[
      { id: 'files', label: 'Files' },
      { id: 'photos', label: 'Photos' },
      { id: 'favorites', label: 'Favorites' },
      { id: 'settings', label: 'Settings' },
    ]}
    on:navigate={(e) => handleNavigate(e.detail?.view ?? e.detail)}
    on:toggleSearch={() => { showSearch = !showSearch; if (!showSearch) clearByoSearch(); }}
    on:closeSearch={() => { showSearch = false; clearByoSearch(); }}
    on:searchChange={(e) => {
      setByoSearchQuery(e.detail?.query ?? '');
      setByoFileTypeFilter(normalizeFileType(e.detail?.fileType));
    }}
    on:openDrawer={() => drawerOpen = true}
    on:lock={onLock}
  />

  <!-- Status + provider chrome row -->
  <div class="status-bar">
    <div class="status-pills">
      {#if $vaultStore.status === 'saving'}
        <span class="status-pill status-saving">Saving…</span>
      {:else if $isVaultDirty}
        <span class="status-pill status-dirty">Unsaved changes</span>
      {:else if $vaultStore.lastSavedAt}
        <span class="status-pill status-saved">Saved</span>
      {/if}
      {#if offlineProviderCount > 0}
        <span class="status-pill status-offline offline-global-pill">
          <CloudSlash size={12} />
          {offlineProviderCount === 1 ? '1 provider offline' : `${offlineProviderCount} providers offline`}
        </span>
      {/if}
    </div>

    <!-- Provider switcher — sits in header chrome when 2+ providers -->
    {#if $vaultStore.providers.length > 1}
      <div class="provider-switcher" role="tablist" aria-label="Storage providers">
        {#each $vaultStore.providers as p (p.providerId)}
          <button
            class="provider-chip"
            class:active={p.providerId === $vaultStore.activeProviderId}
            class:chip-is-offline={p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized'}
            role="tab"
            aria-selected={p.providerId === $vaultStore.activeProviderId}
            title="{p.displayName}{p.status === 'unauthorized' ? ' · Token expired' : (p.status === 'offline' || p.status === 'error') ? ' · Offline' : ''}"
            on:click={() => switchProvider(p)}
            on:contextmenu={(e) => onChipContextMenu(e, p)}
            on:pointerdown={(e) => onChipPointerDown(e, p)}
            on:pointerup={onChipPointerUp}
            on:pointerleave={onChipPointerUp}
          >
            <span class="provider-chip-icon" aria-hidden="true">{providerIcon(p.type)}</span>
            <span class="provider-chip-name">{p.displayName}{p.status === 'unauthorized' ? ' · Token expired' : (p.status === 'offline' || p.status === 'error') ? ' · Offline' : ''}</span>
            {#if p.status === 'syncing'}
              <span class="chip-status chip-syncing" aria-label="Syncing" />
            {:else if p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized'}
              <span class="chip-status chip-offline" aria-label="Offline" />
            {/if}
          </button>
        {/each}
        <button
          class="provider-chip provider-chip-add"
          title="Add provider"
          on:click={() => showAddProvider = true}
          aria-label="Add storage provider"
        >
          <span aria-hidden="true">+</span>
        </button>
      </div>
    {/if}
  </div>

  <!-- Encryption status strip (§29.4) — always shown -->
  <EncryptionStrip state={$byoEncryptionState} />

  <!-- Per-provider offline banner (shown when active tab's provider is offline) -->
  {#if activeProviderOffline && activeProvider}
    <OfflineBanner
      providerName={activeProvider.displayName}
      {retrying}
      on:retry={retryActiveProvider}
    />
  {/if}

  <!-- Share-revoked snackbar toast -->
  {#if moveRevokedMsg}
    <div class="move-revoke-toast" role="status" aria-live="polite">
      <span class="move-revoke-icon" aria-hidden="true">ℹ</span>
      <span>{moveRevokedMsg}</span>
      <button class="move-revoke-dismiss" on:click={() => { moveRevokedMsg = ''; }} aria-label="Dismiss">✕</button>
    </div>
  {/if}

  <!-- Upload/Download queues -->
  <div class="queue-area">
    <ByoUploadQueue />
    <ByoDownloadQueue />
  </div>

  <!-- Selection toolbar -->
  {#if $byoSelectionMode}
    {@const selIds = [...$byoSelectedFiles]}
    {@const favCount = selIds.filter((id) => favoriteFileIds.has(id)).length + [...$byoSelectedFolders].filter((id) => favoriteFolderIds.has(id)).length}
    {@const totalSel = $byoSelectedFiles.size + $byoSelectedFolders.size}
    <SelectionToolbar
      selectedCount={totalSel}
      canDetails={true}
      canShare={true}
      favoriteState={favCount === 0 ? 'none' : favCount === totalSel ? 'all' : 'mixed'}
      on:selectAll={() => {
        const fileIds = sortedFiles.map((f) => f.id);
        byoSelectedFiles.set(new Set(fileIds));
        byoSelectionMode.set(true);
      }}
      on:clear={clearByoSelection}
      on:clearSelection={clearByoSelection}
      on:move={() => { moveCopyMode = 'move'; showMoveCopyDialog = true; }}
      on:copy={() => { moveCopyMode = 'copy'; showMoveCopyDialog = true; }}
      on:moveToProvider={() => { if ($vaultStore.providers.length > 1) showProviderMoveSheet = true; }}
      on:favorite={() => bulkToggleFavorite(true)}
      on:unfavorite={() => bulkToggleFavorite(false)}
      on:download={() => {
        const ids = [...get(byoSelectedFiles)];
        for (const id of ids) {
          const f = currentFiles.find((x) => x.id === id) ?? sortedFiles.find((x) => x.id === id);
          if (f) downloadFile(f);
        }
      }}
      on:details={() => {
        const ids = [...get(byoSelectedFiles)];
        if (ids.length === 1) openDetails(ids[0]);
      }}
      on:share={() => {
        const ids = [...get(byoSelectedFiles)];
        if (ids.length === 1) openShareSheet(ids[0]);
      }}
      on:delete={() => {
        const ids = [...get(byoSelectedFiles)];
        if (ids.length > 0) promptDelete('file', ids[0], `${ids.length} file${ids.length !== 1 ? 's' : ''}`);
      }}
    />
  {/if}

  <!-- Main content (pull-to-refresh per §29.3.5) -->
  <PullToRefresh
    class="byo-main-content"
    onRefresh={view === 'favorites' ? loadFavorites : loadCurrentFolder}
    disabled={view === 'photos'}
    on:pointerdown={onMainPointerDown}>
    {#if view === 'files'}
      <!-- Breadcrumb pill -->
      <nav class="breadcrumb-pill" aria-label="Folder navigation">
        <button class="breadcrumb-home" on:click={() => navigateToBreadcrumb(0)} aria-label="Home">
          <House size={16} weight="fill" />
        </button>
        {#each folderStack.slice(1) as crumb, i}
          <CaretRight size={12} class="breadcrumb-chevron" />
          {#if i === folderStack.length - 2}
            <span class="breadcrumb-current" title={crumb.name}>{crumb.name}</span>
          {:else}
            <button class="breadcrumb-item" on:click={() => navigateToBreadcrumb(i + 1)}>{crumb.name}</button>
          {/if}
        {/each}
      </nav>

      <!-- Sort controls -->
      <SortControl
        sorting={sortingState}
        onByChange={onSortByChange}
        onDirectionChange={onSortDirChange}
        onToggleDirection={onToggleSortDir}
      />

      <!-- New folder button (disabled when active provider is offline) -->
      <div class="toolbar-row">
        <button
          class="btn btn-secondary btn-sm new-folder-btn"
          disabled={!canWrite}
          title={activeProviderOffline ? 'Unavailable while provider is offline' : undefined}
          on:click={() => canWrite && (showNewFolderModal = true)}
        >
          <FolderPlus size={16} weight="regular" />
          <span>New folder</span>
        </button>
      </div>

      {#if loading}
        <div class="loading-state">
          <div class="spinner"></div>
        </div>
      {:else if error}
        <div class="error-state">
          <p>{error}</p>
          <button class="btn btn-secondary btn-sm" on:click={loadCurrentFolder}>Retry</button>
        </div>
      {:else}
        <!-- Folder tiles -->
        {#if sortedFolders.length > 0}
          <div class="folder-section">
            <div class="tiles-grid">
              {#each sortedFolders as folder (folder.id)}
                <FolderTile
                  {folder}
                  on:open={() => openFolder(folder)}
                  on:select={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                />
              {/each}
            </div>
          </div>
        {/if}

        <!-- File list -->
        {#if sortedFiles.length > 0 || sortedFolders.length === 0}
          <FileListSvelte
            files={sortedFilesAny}
            {selectionContext}
            favoriteFileIds={favoriteFileIds}
            onRename={handleRenameFile}
            showEncryptionBadge={true}
            on:preview={(e) => { previewFile = sortedFiles.find((f) => f.id === (e.detail?.id ?? e.detail)) || null; previewOpen = !!previewFile; }}
            on:download={(e) => { const id = e.detail?.id ?? e.detail; const f = sortedFiles.find((x) => x.id === id); if (f) downloadFile(f); }}
            on:delete={(e) => {
              const id = e.detail?.id ?? e.detail;
              const f = sortedFiles.find((file) => file.id === id);
              if (f) promptDelete('file', f.id, f.decrypted_name);
            }}
            on:upload={handleFabUpload}
          />
        {/if}

        {#if sortedFiles.length === 0 && sortedFolders.length === 0}
          <div class="empty-state">
            <HexShield size={72} color="var(--text-disabled, #616161)">
              <FolderSimple size={28} weight="regular" color="var(--text-disabled, #616161)" />
            </HexShield>
            <p class="empty-heading">Your vault is empty</p>
            <p class="empty-sub">Upload files to start.</p>
            <button class="btn btn-primary btn-sm" on:click={handleFabUpload}>Upload files</button>
          </div>
        {/if}
      {/if}

    {:else if view === 'photos'}
      <ByoPhotoTimeline loadFileData={loadFileData} />

    {:else if view === 'favorites'}
      <!-- Favorites view -->
      {#if favoriteFolders.length === 0 && favoriteFiles.length === 0}
        <div class="empty-state">
          <HexShield size={72} color="var(--text-disabled, #616161)">
            <Star size={28} weight="fill" color="var(--accent-warm, #E0A320)" opacity="0.55" />
          </HexShield>
          <p class="empty-heading">Nothing starred yet</p>
          <p class="empty-sub">Star files and folders for quick access.</p>
        </div>
      {:else}
        {#if favoriteFolders.length > 0}
          <div class="folder-section">
            <div class="tiles-grid">
              {#each favoriteFolders as folder (folder.id)}
                <FolderTile
                  {folder}
                  isFavorite={true}
                  on:open={() => { openFolder(folder); view = 'files'; }}
                  on:select={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                />
              {/each}
            </div>
          </div>
        {/if}
        {#if favoriteFiles.length > 0}
          <FileListSvelte
            files={favoriteFilesAny}
            {selectionContext}
            favoriteFileIds={favoriteFileIds}
            onRename={handleRenameFile}
            showEncryptionBadge={true}
            on:preview={(e) => { previewFile = favoriteFiles.find((f) => f.id === (e.detail?.id ?? e.detail)) || null; previewOpen = !!previewFile; }}
            on:download={(e) => { const id = e.detail?.id ?? e.detail; const f = favoriteFiles.find((x) => x.id === id); if (f) downloadFile(f); }}
            on:delete={(e) => {
              const id = e.detail?.id ?? e.detail;
              const f = favoriteFiles.find((file) => file.id === id);
              if (f) promptDelete('file', f.id, f.decrypted_name);
            }}
            on:upload={handleFabUpload}
          />
        {/if}
      {/if}
    {/if}
  </PullToRefresh>

  <!-- Bottom nav -->
  <div class="bottom-nav-wrap" class:nav-hidden={$byoSelectionMode} aria-hidden={$byoSelectionMode}>
    <BottomNav
      activeView={view}
      on:navigate={(e) => {
        handleNavigate(e.detail?.view ?? e.detail);
      }}
    />
  </div>

  <!-- FAB (disabled when active provider is offline).
       Photos view: tap uploads directly — no speed-dial menu since
       folder concepts don't apply to the flat photo timeline. -->
  {#if view === 'photos'}
    <FAB
      showMenu={false}
      disabled={!canWrite}
      on:toggle={() => { if (canWrite) handleFabUpload(); }}
    />
  {:else if view === 'files'}
    <FAB
      showMenu={showFabMenu && canWrite}
      disabled={!canWrite}
      on:toggle={() => { if (canWrite) showFabMenu = !showFabMenu; }}
      on:upload={() => { if (canWrite) handleFabUpload(); }}
      on:uploadFolder={() => { if (canWrite) handleFabUploadFolder(); }}
      on:newFolder={() => { if (canWrite) { showFabMenu = false; showNewFolderModal = true; } }}
    />
  {/if}

  <!-- Hidden folder input for folder upload -->
  <input
    type="file"
    bind:this={folderInput}
    on:change={onFolderSelected}
    {...{'webkitdirectory': true}}
    multiple
    style="display: none;"
  />

  <!-- Drawer -->
  <Drawer
    open={drawerOpen}
    showLogout={false}
    on:close={() => drawerOpen = false}
    storageUsedBytes={storageUsed}
    storageQuotaBytes={storageQuota ?? 0}
    on:trash={onTrash}
    on:settings={onSettings}
    on:lock={onLock}
  >
    <FolderTree
      folders={byoFoldersAny}
      selected={currentFolderId ?? undefined}
      onRename={handleRenameFolder}
      onDelete={handleDeleteFolder}
      on:select={(e) => {
        const folderId = e.detail;
        const folder = $byoFolders.find((f) => f.id === folderId);
        if (folder) openFolder(folder);
      }}
    />
  </Drawer>

  <!-- New folder modal -->
  {#if showNewFolderModal}
    <ConfirmModal
      isOpen={showNewFolderModal}
      title="New Folder"
      confirmText={creatingFolder ? 'Creating…' : 'Create'}
      loading={creatingFolder}
      on:confirm={handleCreateFolder}
      on:cancel={() => { showNewFolderModal = false; newFolderName = ''; }}
    >
      <input
        type="text"
        bind:value={newFolderName}
        placeholder="Folder name"
        class="input"
        on:keydown={(e) => e.key === 'Enter' && handleCreateFolder()}
      />
    </ConfirmModal>
  {/if}

  <!-- Delete confirmation -->
  <ConfirmModal
    isOpen={showDeleteModal}
    title="Move to Trash"
    confirmText="Move to Trash"
    confirmClass="btn-danger"
    loading={deleteLoading}
    on:confirm={confirmDelete}
    on:cancel={() => { showDeleteModal = false; deleteTarget = null; }}
  >
    {#if deleteTarget}
      <p>Move <strong>{deleteTarget.name}</strong> to trash?</p>
      <p class="modal-note">You can restore it from trash within 30 days.</p>
    {/if}
  </ConfirmModal>

  <!-- File preview -->
  {#if previewOpen && previewFile}
    <FilePreview
      file={previewFileAny}
      isOpen={previewOpen}
      {loadFileData}
      onClose={() => { previewOpen = false; previewFile = null; }}
    />
  {/if}

  <!-- Move/copy dialog (scoped to active provider's folders only) -->
  <MoveCopyDialog
    open={showMoveCopyDialog}
    mode={moveCopyMode}
    itemType="files"
    selectedItemCount={$byoSelectedFiles.size}
    allFolders={activeFoldersAny}
    onCreateFolder={createFolderAny}
    on:confirm={handleMoveCopyConfirm}
    on:cancel={() => showMoveCopyDialog = false}
  />

  <!-- File details modal -->
  <ByoFileDetails
    file={detailsFile}
    isOpen={showDetailsModal}
    isFavorite={detailsFile ? favoriteFileIds.has(detailsFile.id) : false}
    folders={detailsFolders}
    onClose={() => { showDetailsModal = false; detailsFile = null; }}
  />

  <!-- Share link sheet -->
  {#if showShareSheet && shareFile !== null}
    <ShareLinkSheet
      file={shareFile}
      on:close={() => { showShareSheet = false; shareFile = null; }}
    />
  {/if}

  <!-- Drag overlay -->
  {#if isDragOver}
    <div class="drag-overlay" aria-hidden="true">
      <p>Drop files to upload</p>
    </div>
  {/if}

  <!-- Add provider sheet -->
  {#if showAddProvider}
    <AddProviderSheet
      on:added={onProviderAdded}
      on:close={() => showAddProvider = false}
    />
  {/if}

  {#if contextSheetProvider}
    <ProviderContextSheet
      provider={contextSheetProvider}
      isOnlyProvider={$vaultStore.providers.length <= 1}
      on:close={() => contextSheetProvider = null}
      on:change={() => { contextSheetProvider = null; }}
    />
  {/if}

  <!-- Selection ripple (§29.3.4) — plays once when entering selection mode. -->
  {#if rippleKey > 0 && rippleX !== null && rippleY !== null}
    {#key rippleKey}
      <span
        class="selection-ripple"
        style:left="{rippleX}px"
        style:top="{rippleY}px"
        aria-hidden="true"
      ></span>
    {/key}
  {/if}

  <!-- Cross-provider move sheet -->
  <ProviderMoveSheet
    open={showProviderMoveSheet}
    fileCount={$byoSelectedFiles.size}
    currentProviderId={$vaultStore.activeProviderId ?? ''}
    providers={$vaultStore.providers}
    progress={crossMoveProgress}
    fileErrors={crossMoveErrors}
    succeededCount={crossMoveSucceeded}
    on:confirm={(e) => handleCrossProviderMove(e.detail.destProviderId)}
    on:retry={handleMoveRetry}
    on:skipErrors={handleMoveSkipErrors}
    on:close={() => { if (!crossMoveProgress) { showProviderMoveSheet = false; crossMoveSucceeded = null; crossMoveErrors = []; } }}
  />
</div>

<style>
  .byo-dashboard {
    display: flex;
    flex-direction: column;
    height: 100dvh;
    overflow: hidden;
    position: relative;
    background: var(--bg-base, #121212);
    /* Clear the fixed DashboardHeader (§9.3/§9.4 + §31.5). */
    padding-top: var(--header-height, 56px);
    box-sizing: border-box;
  }

  /* BottomNav wrapper — slides down + fades when selection mode is active.
     Translate distance matches floating nav height + 12dp inset + safe area
     so the nav fully clears the viewport. */
  .bottom-nav-wrap {
    transition: transform 200ms ease-in, opacity 200ms ease-in;
  }
  .bottom-nav-wrap.nav-hidden {
    transform: translateY(calc(var(--bottom-nav-height, 56px) + 12px + env(safe-area-inset-bottom, 0px)));
    opacity: 0;
    pointer-events: none;
  }
  @media (prefers-reduced-motion: reduce) {
    .bottom-nav-wrap { transition: none; }
    .bottom-nav-wrap.nav-hidden { transform: none; opacity: 0; }
  }

  .status-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-sm, 8px);
    min-height: 32px;
    padding: var(--sp-xs, 4px) var(--sp-md, 16px);
    border-bottom: 1px solid var(--border, #2E2E2E);
    flex-shrink: 0;
  }

  .status-pills {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex: 1;
  }

  .status-bar .provider-switcher {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .status-bar .provider-chip {
    /* Compact chip in the status bar — still keeps tap target ≥ 36dp. */
    min-height: 36px;
    padding: 0 var(--sp-sm, 8px);
    font-size: var(--t-label-size, 0.75rem);
  }

  .status-bar .provider-chip-name {
    max-width: 80px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .status-pill {
    /* §31.8 performance budget: content-layer pills shouldn't blur.
       Opaque surface tone keeps GPU headroom for chrome. */
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: 2px var(--sp-sm, 8px);
    border-radius: var(--r-pill, 9999px);
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    font-size: var(--t-label-size, 0.75rem);
  }

  .status-offline { color: var(--danger, #D64545); }
  .status-saving { color: var(--text-disabled, #616161); }
  .status-dirty { color: var(--accent-warm, #E0A320); }
  .status-saved { color: var(--accent-text, #5FDB8A); }

  /* ── Provider switcher (P9) ─────────────────────────────────────────────── */

  .provider-switcher {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-xs, 4px) var(--sp-md, 16px);
    overflow-x: auto;
    scrollbar-width: none;
  }

  .provider-switcher::-webkit-scrollbar { display: none; }

  .provider-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0 var(--sp-md, 16px);
    /* §25: tap targets ≥ 44dp. */
    min-height: 44px;
    border-radius: var(--r-pill, 9999px);
    background: var(--bg-surface-raised, #1E1E1E);
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-secondary, #999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    white-space: nowrap;
    cursor: pointer;
    transition: background 150ms, color 150ms, border-color 150ms;
  }

  .provider-chip:hover {
    background: var(--surface-2, #222);
    color: var(--text-primary, #ededed);
  }

  .provider-chip.active {
    background: var(--accent-muted, rgba(46, 184, 96, 0.15));
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .provider-chip-icon {
    font-size: 0.7rem;
    font-weight: 700;
    width: 18px;
    height: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
    background: var(--glass-bg, rgba(255,255,255,0.06));
    flex-shrink: 0;
  }

  .provider-chip-name {
    max-width: 80px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .chip-status {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .chip-syncing {
    background: var(--accent, #2EB860);
    animation: pulse 1.2s ease-in-out infinite;
  }

  .chip-error { background: var(--danger, #D64545); }
  .chip-offline { background: var(--danger, #D64545); }

  .chip-is-offline {
    border-color: var(--danger, #D64545);
    color: var(--danger, #D64545);
  }

  .chip-is-offline .provider-chip-icon {
    background: color-mix(in srgb, var(--danger, #D64545) 20%, transparent);
  }

  .offline-global-pill {
    margin-left: auto;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.35; }
  }

  .provider-chip-add {
    color: var(--text-secondary, #999);
    font-size: 1rem;
    padding: 0 var(--sp-sm, 8px);
    flex-shrink: 0;
  }

  /* ── End provider switcher ──────────────────────────────────────────────── */

  .queue-area {
    padding: 0 var(--sp-md, 16px);
  }

  /* :global so the padding reaches PullToRefresh's inner div (which owns
     its own component scope). Flex + overflow-y now live in PullToRefresh. */
  :global(.byo-main-content) {
    /* Bottom: clear floating bottom nav (12dp inset + safe-area + 56dp nav + 16dp FAB gap + breathing room). */
    padding: var(--sp-sm, 8px) var(--sp-md, 16px)
             calc(12px + env(safe-area-inset-bottom, 0px) + var(--bottom-nav-height, 56px) + var(--sp-xl, 32px));
  }

  @media (min-width: 600px) {
    :global(.byo-main-content) {
      /* Desktop has no floating bottom nav (§9.3) — just a FAB inset. */
      padding-bottom: calc(24px + var(--fab-size, 56px) + var(--sp-md, 16px));
    }
  }

  .breadcrumb-pill {
    /* Breadcrumb lives inside .main-content — nothing scrolls behind it,
       so glass blur would burn GPU for no payoff (§31.8). Opaque surface. */
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px) var(--sp-xs, 4px) var(--sp-xs, 4px);
    margin-bottom: var(--sp-sm, 8px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    overflow-x: auto;
    scrollbar-width: none;
    max-width: 100%;
  }
  .breadcrumb-pill::-webkit-scrollbar { display: none; }

  .breadcrumb-home {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background-color: var(--accent-muted, #1B3627);
    color: var(--accent, #2EB860);
    border: none;
    cursor: pointer;
    flex-shrink: 0;
    transition: background-color 200ms ease;
  }
  .breadcrumb-home:hover {
    background-color: var(--accent, #2EB860);
    color: var(--text-inverse, #0A0A0A);
  }

  .breadcrumb-pill :global(.breadcrumb-chevron) {
    color: var(--text-disabled, #616161);
    flex-shrink: 0;
  }

  .breadcrumb-item {
    display: flex;
    align-items: center;
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    background: transparent;
    border: none;
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    cursor: pointer;
    white-space: nowrap;
    transition: all 200ms ease;
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-family: var(--font-sans);
  }
  .breadcrumb-item:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }

  .breadcrumb-current {
    color: var(--accent-text, var(--text-primary, #EDEDED));
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 200px;
    padding: 0 var(--sp-xs, 4px);
  }

  .toolbar-row {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    margin-bottom: var(--sp-sm, 8px);
  }

  .new-folder-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
  }

  .folder-section {
    margin-bottom: var(--sp-md, 16px);
  }

  .tiles-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: var(--sp-sm, 8px);
  }

  @media (max-width: 480px) {
    .tiles-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  .loading-state {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--sp-2xl, 48px);
  }

  .spinner {
    width: 36px;
    height: 36px;
    border: 3px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .error-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-2xl, 48px);
    text-align: center;
    color: var(--danger, #D64545);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px);
    text-align: center;
    color: var(--text-secondary, #999999);
  }
  .empty-heading {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  /* Selection ripple (§29.3.4) — sonar ping from press point. */
  .selection-ripple {
    position: fixed;
    pointer-events: none;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    transform: translate(-50%, -50%);
    background: transparent;
    border: 2px solid var(--accent, #2EB860);
    opacity: 0.35;
    z-index: var(--z-toast, 60);
    animation: selectionPing 320ms ease-out forwards;
  }

  @keyframes selectionPing {
    0%   { width: 12px; height: 12px; opacity: 0.4; }
    100% { width: 80px; height: 80px; opacity: 0;   }
  }

  @media (prefers-reduced-motion: reduce) {
    .selection-ripple { display: none; }
  }
  .empty-sub {
    margin: 0;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
  }

  .modal-note {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
  }

  .placeholder-text {
    color: var(--text-disabled, #616161);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .drag-overlay {
    position: absolute;
    inset: 0;
    background: rgba(46, 184, 96, 0.12);
    border: 3px dashed var(--accent, #2EB860);
    border-radius: var(--r-card, 16px);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none;
    z-index: 100;
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--accent-text, #5FDB8A);
  }

  /* ── Move-revoked snackbar ──────────────────────────────────────────────── */
  /* §20 toast spec: pill, --bg-surface-raised, no border. */
  .move-revoke-toast {
    position: fixed;
    bottom: calc(12px + env(safe-area-inset-bottom, 0px) + var(--bottom-nav-height, 56px) + 16px);
    left: 50%;
    transform: translateX(-50%);
    z-index: var(--z-toast, 60);
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    min-height: 48px;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--glass-bg, rgba(28, 28, 28, 0.82));
    backdrop-filter: var(--glass-blur-light, blur(12px));
    -webkit-backdrop-filter: var(--glass-blur-light, blur(12px));
    border: var(--glass-border, 1px solid rgba(255, 255, 255, 0.08));
    border-radius: var(--r-pill, 9999px);
    box-shadow: var(--glass-shadow, 0 8px 32px rgba(0, 0, 0, 0.4));
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    max-width: calc(100vw - 32px);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  @supports not (backdrop-filter: blur(1px)) {
    .move-revoke-toast { background: var(--bg-surface-raised, #262626); }
  }
  .move-revoke-icon {
    flex-shrink: 0;
    color: var(--accent-text, #5FDB8A);
  }
  .move-revoke-dismiss {
    flex-shrink: 0;
    margin-left: var(--sp-xs, 4px);
    background: none;
    border: none;
    color: var(--text-secondary, #999);
    cursor: pointer;
    font-size: 0.85rem;
    padding: 2px 4px;
    min-height: 28px;
    display: flex;
    align-items: center;
  }
  .move-revoke-dismiss:hover { color: var(--text-primary, #EDEDED); }
</style>
