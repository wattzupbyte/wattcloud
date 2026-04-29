<script lang="ts">

  /**
   * ByoDashboard — BYO mode file manager dashboard.
   *
   * Feature-parity with managed Dashboard. Reuses managed components where
   * possible; injects BYO callbacks for store-coupled components.
   *
   * Gets DataProvider from Svelte context ('byo:dataProvider') set by ByoApp.
   */
  import { onMount, onDestroy, getContext } from 'svelte';
  import { get } from 'svelte/store';
  import type { DataProvider, FileEntry, FolderEntry, CollectionEntry } from '../../byo/DataProvider';
  import { byoFolders, byoSelectedFiles, byoSelectedFolders, byoSelectionMode, toggleByoFileSelection, toggleByoFolderSelection, clearByoSelection, resetByoFileStores } from '../../byo/stores/byoFileStore';
  import { byoUploadQueue } from '../../byo/stores/byoUploadQueue';
  import { byoDownloadQueue } from '../../byo/stores/byoDownloadQueue';
  import { setByoSearchDataProvider, clearByoSearch, byoSearchQuery, byoSearchResults, byoSearchFolderResults, hasByoActiveFilters, setByoSearchQuery, setByoFileTypeFilter } from '../../byo/stores/byoSearch';
  import { setByoPhotosDataProvider, resetByoPhotos, byoPhotoTimeline, loadByoPhotoTimeline } from '../../byo/stores/byoPhotos';
  import {
    byoCollections,
    loadByoCollections,
    createByoCollection,
    addByoFilesToCollection,
  } from '../../byo/stores/byoCollections';
  import { vaultStore, canOperate } from '../../byo/stores/vaultStore';
  import { storageUsage } from '../../stores/storageUsage';
  import type { ProviderMeta } from '../../byo/stores/vaultStore';
  import AddProviderSheet from './AddProviderSheet.svelte';
  import { OfflineDetector } from '../../byo/OfflineDetector';
  import { getProviders, getPrimaryProviderId } from '../../byo/VaultLifecycle';
  import House from 'phosphor-svelte/lib/House';
  import CaretRight from 'phosphor-svelte/lib/CaretRight';
  import Star from 'phosphor-svelte/lib/Star';
  import CloudSlash from 'phosphor-svelte/lib/CloudSlash';
  import Stack from 'phosphor-svelte/lib/Stack';
  import Rows from 'phosphor-svelte/lib/Rows';
  import SquaresFour from 'phosphor-svelte/lib/SquaresFour';
  import OfflineBanner from './OfflineBanner.svelte';
  import {
    streamToDisk,
    bufferStreamToFile,
    shareFilesViaOS,
    WebShareUnsupportedError,
    WebShareUnsupportedForFilesError,
  } from '../../byo/streamToDisk';
  import {
    isIOSDevice,
    bufferForIOSSave,
    pickIosPath,
    iosBlockMessage,
    iosWarnMessage,
    type IOSPathDecision,
  } from '../../byo/iosSave';
  import { byoToast } from '../../byo/stores/byoToasts';
  import { byoCapabilities } from '../../byo/stores/byoCapabilities';
  import { recordEvent } from '@wattcloud/sdk';

  // Reused managed components
  import DashboardHeader from '../DashboardHeader.svelte';
  import FAB from '../FAB.svelte';
  import SelectionToolbar from '../SelectionToolbar.svelte';
  import SortControl from '../SortControl.svelte';
  import type { SortBy as SortByT, SortDirection as SortDirT } from '../../stores/sorting';
  import FolderTile from '../FolderTile.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import MoveCopyDialog from '../MoveCopyDialog.svelte';
  import ShareReceiveSheet from './ShareReceiveSheet.svelte';
  import ShareUnsupportedSheet from './ShareUnsupportedSheet.svelte';

  // Components with BYO callbacks
  import FileListSvelte from '../FileList.svelte';
  import FilePreview from '../FilePreview.svelte';

  import PullToRefresh from './PullToRefresh.svelte';

  // BYO-specific components
  import ByoUploadQueue from './ByoUploadQueue.svelte';
  import ByoDownloadQueue from './ByoDownloadQueue.svelte';
  import ShareLinkSheet from './ShareLinkSheet.svelte';
  import ByoPhotoTimeline from './ByoPhotoTimeline.svelte';
  import ByoFileDetails from './ByoFileDetails.svelte';
  import ProviderMoveSheet from './ProviderMoveSheet.svelte';

  
  interface Props {
    /** Bound by ByoApp so the shared Drawer can highlight the right link
      and navigation from Settings → Dashboard lands on the chosen tab. */
    view?: 'files' | 'photos' | 'favorites';
    /** Set when the user landed on /share-receive and tapped "Open
     *  Wattcloud". The dashboard pops a destination-picker sheet on
     *  mount, then notifies the parent via `onShareReceiveConsumed`
     *  so the URL is cleaned up. */
    shareReceiveSessionId?: string | null;
    onShareReceiveConsumed?: (() => void) | null;
  }

  let {
    view = $bindable('files'),
    shareReceiveSessionId = null,
    onShareReceiveConsumed = null,
  }: Props = $props();


  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;

  // iOS Safari can't stream Service Worker downloads (truncates at the
  // first buffered slice), so every owner download branches here into
  // the buffered-save path. Capturing once at script init: it's a UA
  // check, not something that changes during a session.
  const iosDevice = isIOSDevice();

  let loading = $state(false);
  let error = $state('');
  let moveRevokedMsg = $state('');
  let moveRevokedTimer: ReturnType<typeof setTimeout> | null = null;
  let showSearch = $state(false);
  let sortBy: 'name' | 'date' | 'size' = 'name';
  let sortDir: 'asc' | 'desc' = $state('asc');

  // Folder navigation stack
  let folderStack: Array<{ id: number | null; name: string }> = $state([{ id: null, name: 'Home' }]);

  // ── View mode (list / grid) ───────────────────────────────────────────────
  // Persisted per-folder in localStorage, keyed by vault id. When a folder
  // has no recorded override the vault's last-picked default is used. The
  // vault id may briefly be null during unlock — the helpers below no-op in
  // that case so nothing is written under a placeholder key.
  type FilesViewMode = 'list' | 'grid';
  const VIEW_MODE_STORAGE_PREFIX = 'wc:fileView:';
  const FOLDER_STRIP_THRESHOLD = 8;

  let filesViewMode: FilesViewMode = $state('list');
  /** When `true` in grid mode, a tall folder count is expanded into the
      full tile grid instead of the horizontal scroll strip. Resets on
      folder navigation so long lists re-collapse when the user enters
      another folder with many subfolders. */
  let folderStripExpanded = $state(false);

  function readViewMode(vaultId: string | null, folderId: number | null): FilesViewMode {
    if (!vaultId || typeof localStorage === 'undefined') return 'list';
    const raw = localStorage.getItem(VIEW_MODE_STORAGE_PREFIX + vaultId);
    if (!raw) return 'list';
    try {
      const parsed = JSON.parse(raw) as { default?: FilesViewMode; overrides?: Record<string, FilesViewMode> };
      const key = folderId == null ? 'root' : String(folderId);
      const override = parsed.overrides?.[key];
      if (override === 'list' || override === 'grid') return override;
      if (parsed.default === 'list' || parsed.default === 'grid') return parsed.default;
    } catch { /* fall through to default */ }
    return 'list';
  }

  function writeViewMode(vaultId: string | null, folderId: number | null, mode: FilesViewMode) {
    if (!vaultId || typeof localStorage === 'undefined') return;
    const key = folderId == null ? 'root' : String(folderId);
    let data: { default: FilesViewMode; overrides: Record<string, FilesViewMode> } =
      { default: mode, overrides: {} };
    const raw = localStorage.getItem(VIEW_MODE_STORAGE_PREFIX + vaultId);
    if (raw) {
      try {
        const parsed = JSON.parse(raw) as { default?: FilesViewMode; overrides?: Record<string, FilesViewMode> };
        data = {
          default: mode,
          overrides: { ...(parsed.overrides ?? {}) },
        };
      } catch { /* rewrite fresh */ }
    }
    data.overrides[key] = mode;
    localStorage.setItem(VIEW_MODE_STORAGE_PREFIX + vaultId, JSON.stringify(data));
  }

  function onViewModeChange(next: FilesViewMode) {
    if (filesViewMode === next) return;
    filesViewMode = next;
    folderStripExpanded = false;
    writeViewMode($vaultStore.vaultId, currentFolderId, next);
  }


  // Modals
  let showNewFolderModal = $state(false);
  let newFolderName = $state('');
  let creatingFolder = $state(false);

  let showDeleteModal = $state(false);
  let deleteTarget: { type: 'file' | 'folder'; id: number; name: string } | null = $state(null);
  let deleteLoading = $state(false);

  let showMoveCopyDialog = $state(false);
  let moveCopyMode: 'move' | 'copy' = $state('move');

  // Inbound Web Share Target sheet — opened automatically when ByoApp
  // hands us a `shareReceiveSessionId` after the vault has unlocked.
  // The reactive open trigger flips once we observe a non-null id; the
  // `onShareReceiveConsumed` callback fires when the sheet closes so
  // ByoApp can clear the URL param and not re-open on a future mount.
  let shareReceiveSheetOpen = $state(false);
  $effect(() => {
    if (shareReceiveSessionId && !shareReceiveSheetOpen) {
      shareReceiveSheetOpen = true;
    }
  });

  // OS-share unsupported explainer — opened from handleSendToOS when
  // navigator.share is missing or canShare({files}) refuses the payload.
  // The "Send to..." button is shown unconditionally; this sheet does
  // the educating instead of hiding the affordance.
  let shareUnsupportedOpen = $state(false);
  let shareUnsupportedReason = $state<'missing-api' | 'files-rejected'>('missing-api');
  function handleShareReceiveClosed() {
    shareReceiveSheetOpen = false;
    onShareReceiveConsumed?.();
    // The sheet drops uploaded files into byoUploadQueue, which may
    // already have completed by now if the share was small. Refresh the
    // current folder either way so freshly-uploaded inbound files
    // appear if the user happened to land on the matching folder.
    void loadCurrentFolder();
  }
  /** Flat list of every folder in the active provider — sourced from
      listAllFolders() and refreshed before opening the MoveCopyDialog so
      the tree isn't empty (the $byoFolders store only holds the *current*
      folder's children). */
  let moveCopyFolders: FolderEntry[] = $state([]);
  async function refreshMoveCopyFolders() {
    try { moveCopyFolders = await dataProvider.listAllFolders(); }
    catch { moveCopyFolders = []; }
  }

  // Add-to-collection dialog (photos view)
  let showAddToCollection = $state(false);
  let addToCollectionNewName = $state('');
  let addingToCollection = $state(false);

  // Cross-provider move
  let showProviderMoveSheet = $state(false);
  let crossMoveProgress: { done: number; total: number } | null = $state(null);
  let crossMoveErrors: { fileId: number; fileName: string; error: string }[] = $state([]);
  let crossMoveSucceeded: number | null = $state(null);
  let crossMoveDestProviderId = '';

  let previewFile: FileEntry | null = $state(null);
  let previewOpen = $state(false);

  let showFabMenu = $state(false);
  let folderInput: HTMLInputElement | null = $state(null);

  // File details modal — also serves folder details (ByoFileDetails branches
  // on whichever of `file`/`folder` is non-null).
  let showDetailsModal = $state(false);
  let detailsFile: FileEntry | null = $state(null);
  let detailsFolder: FolderEntry | null = $state(null);

  // Share link sheet
  let showShareSheet = $state(false);
  type ShareSheetSource =
    | { kind: 'file'; file: FileEntry }
    | { kind: 'folder'; folder: FolderEntry }
    | { kind: 'collection'; collection: CollectionEntry }
    | { kind: 'files'; files: FileEntry[] }
    | { kind: 'mixed'; folders: FolderEntry[]; files: FileEntry[] };
  let shareSource: ShareSheetSource | null = $state(null);

  // Favorites
  let favoriteFileIds: Set<number> = $state(new Set());
  let favoriteFolderIds: Set<number> = $state(new Set());
  let favoriteFiles: FileEntry[] = $state([]);
  let favoriteFolders: FolderEntry[] = $state([]);

  // Services
  let offlineDetector: OfflineDetector | null = null;

  // ── Selection ripple (§29.3.4) ─────────────────────────────────────────
  // Record the last pointerdown inside .main-content so we can burst a ring
  // from that spot when long-press enters selection mode.
  let rippleX: number | null = $state(null);
  let rippleY: number | null = $state(null);
  let rippleKey = $state(0);
  let lastSelectionMode = $state(false);
  const reducedMotion = typeof window !== 'undefined'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function onMainPointerDown(e: PointerEvent) {
    rippleX = e.clientX;
    rippleY = e.clientY;
  }

  // DashboardHeader uses plural tokens ('images', 'documents'…) matching
  // the managed search. BYO's DataProvider expects singular ('image',
  // 'document'…). Map once at the boundary. 'folder' is the sentinel
  // byoSearch's performByoSearch reads — it suppresses file results and
  // populates byoSearchFolderResults instead.
  const FILE_TYPE_MAP: Record<string, string | null> = {
    '': null,
    images: 'image',
    documents: 'document',
    videos: 'video',
    archives: 'archive',
    audio: 'audio',
    code: 'code',
    folders: 'folder',
  };
  function normalizeFileType(v: string | undefined | null): string | null {
    if (!v) return null;
    return FILE_TYPE_MAP[v] ?? null;
  }



  // Retry ping for active provider
  let retrying = $state(false);
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


  // Files/folders for current folder
  let currentFiles: FileEntry[] = $state([]);
  let currentFolders: FolderEntry[] = $state([]);


  function onSortByChange(by: SortByT) { sortBy = by; }
  function onToggleSortDir() { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }


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

  async function openAddToCollection() {
    await loadByoCollections();
    showAddToCollection = true;
  }

  async function handleAddToCollection(collectionId: number) {
    if (addingToCollection) return;
    addingToCollection = true;
    try {
      const fileIds = [...get(byoSelectedFiles)];
      if (fileIds.length === 0) { showAddToCollection = false; return; }
      await addByoFilesToCollection(collectionId, fileIds);
      clearByoSelection();
      showAddToCollection = false;
    } finally {
      addingToCollection = false;
    }
  }

  async function handleCreateAndAddCollection() {
    const name = addToCollectionNewName.trim();
    if (!name || addingToCollection) return;
    addingToCollection = true;
    try {
      await createByoCollection(name);
      // The freshly-created collection will be first in the store (createByoCollection reloads).
      const created = get(byoCollections)[0];
      if (created) {
        const fileIds = [...get(byoSelectedFiles)];
        if (fileIds.length > 0) {
          await addByoFilesToCollection(created.id, fileIds);
        }
      }
      addToCollectionNewName = '';
      clearByoSelection();
      showAddToCollection = false;
    } finally {
      addingToCollection = false;
    }
  }

  async function loadStorageUsage() {
    try {
      const usage = await dataProvider.getStorageUsage();
      storageUsage.set({ used: usage.used, quota: usage.quota });
    } catch { /* ignore */ }
  }

  // ── Navigation ─────────────────────────────────────────────────────────────

  function openFolder(folder: FolderEntry) {
    // Folder hits surfaced by search aren't necessarily children of the
    // current breadcrumb. Detect the search-result case (folder isn't in
    // the current folder's children) and jump to it from Home; otherwise
    // append to the breadcrumb stack as usual.
    const isCurrentChild = currentFolders.some((f) => f.id === folder.id);
    if (!isCurrentChild) {
      if (get(hasByoActiveFilters)) {
        showSearch = false;
        clearByoSearch();
      }
      folderStack = [
        { id: null, name: 'Home' },
        { id: folder.id, name: folder.decrypted_name },
      ];
      return;
    }
    folderStack = [...folderStack, { id: folder.id, name: folder.decrypted_name }];
  }

  function navigateToBreadcrumb(index: number) {
    folderStack = folderStack.slice(0, index + 1);
  }


  // ── File operations ────────────────────────────────────────────────────────

  async function handleRenameFile(fileId: number, newName: string) {
    await dataProvider.renameFile(fileId, newName);
    await loadCurrentFolder();
  }

  // ── Rename UI plumbing ────────────────────────────────────────────────────
  // FileList accepts a `bind:renameFileId` — when set, it enters inline rename
  // mode for that file (its own $effect resets the prop to null after consuming).
  // FolderTile uses an `isRenaming` flag + bound `renameValue` + keydown/blur
  // callbacks; ByoDashboard owns the state because it controls the toolbar.
  let renameFileId: number | null = $state(null);
  let renamingFolderId: number | null = $state(null);
  let folderRenameValue = $state('');

  function findFolderForRename(folderId: number) {
    return currentFolders.find((f) => f.id === folderId)
      ?? favoriteFolders.find((f) => f.id === folderId)
      ?? null;
  }

  function startFolderRename(folderId: number) {
    const folder = findFolderForRename(folderId);
    if (!folder) return;
    folderRenameValue = (folder as any).decrypted_name || folder.name;
    renamingFolderId = folderId;
  }

  async function commitFolderRename() {
    if (renamingFolderId === null) return;
    const id = renamingFolderId;
    const newName = folderRenameValue.trim();
    renamingFolderId = null;
    folderRenameValue = '';
    if (!newName) return;
    try {
      await dataProvider.renameFolder(id, newName);
      // Refresh both views — favorites list mirrors the folder rows, and
      // the file/folder list relies on currentFolders for sortedFolders.
      await Promise.all([loadCurrentFolder(), loadFavorites().catch(() => {})]);
    } catch (e: any) {
      error = e?.message ?? 'Failed to rename folder';
    }
  }

  function cancelFolderRename() {
    renamingFolderId = null;
    folderRenameValue = '';
  }

  function handleFolderRenameKeydown(payload: { event: KeyboardEvent }) {
    if (payload.event.key === 'Enter') {
      payload.event.preventDefault();
      commitFolderRename();
    } else if (payload.event.key === 'Escape') {
      payload.event.preventDefault();
      cancelFolderRename();
    }
  }

  function handleFolderRenameBlur() {
    // Commit on blur — matches the file-rename UX in FileList.
    if (renamingFolderId !== null) commitFolderRename();
  }

  function triggerRenameFromToolbar() {
    // Single-selection invariant guaranteed by SelectionToolbar.canRename.
    if ($byoSelectedFiles.size === 1 && $byoSelectedFolders.size === 0) {
      const [fileId] = [...$byoSelectedFiles];
      renameFileId = fileId; // FileList's $effect picks this up
      clearByoSelection();
      return;
    }
    if ($byoSelectedFolders.size === 1 && $byoSelectedFiles.size === 0) {
      const [folderId] = [...$byoSelectedFolders];
      startFolderRename(folderId);
      clearByoSelection();
    }
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
          if (view === 'photos') await loadByoPhotoTimeline();
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
      detailsFolder = null;
      showDetailsModal = true;
    }
  }

  function openFolderDetails(folderId: number) {
    const folder = currentFolders.find((x) => x.id === folderId)
      ?? favoriteFolders.find((x) => x.id === folderId);
    if (folder) {
      detailsFolder = folder;
      detailsFile = null;
      showDetailsModal = true;
    }
  }

  function openShareSheet(fileId: number) {
    const f = sortedFiles.find((x) => x.id === fileId) ?? currentFiles.find((x) => x.id === fileId);
    if (f) { shareSource = { kind: 'file', file: f }; showShareSheet = true; }
  }

  function openFolderShareSheet(folderId: number) {
    const folder = currentFolders.find((x) => x.id === folderId)
      ?? favoriteFolders.find((x) => x.id === folderId);
    if (folder) { shareSource = { kind: 'folder', folder }; showShareSheet = true; }
  }

  function openCollectionShareSheet(collection: CollectionEntry) {
    shareSource = { kind: 'collection', collection };
    showShareSheet = true;
  }

  function openFilesShareSheet(fileIds: number[]) {
    const lookup = new Map<number, FileEntry>();
    for (const f of sortedFiles) lookup.set(f.id, f);
    for (const f of currentFiles) if (!lookup.has(f.id)) lookup.set(f.id, f);
    for (const f of favoriteFiles) if (!lookup.has(f.id)) lookup.set(f.id, f);
    const resolved: FileEntry[] = [];
    for (const id of fileIds) {
      const f = lookup.get(id);
      if (f) resolved.push(f);
    }
    if (resolved.length < 2) return;
    shareSource = { kind: 'files', files: resolved };
    showShareSheet = true;
  }

  /** Open the share sheet for any mixed selection: multiple folders, or
   *  folders + loose files. Single-file / single-folder go through their
   *  dedicated openers so the recipient title stays specific. */
  function openMixedShareSheet(folderIds: number[], fileIds: number[]) {
    const folderLookup = new Map<number, FolderEntry>();
    for (const f of currentFolders) folderLookup.set(f.id, f);
    for (const f of favoriteFolders) if (!folderLookup.has(f.id)) folderLookup.set(f.id, f);
    const folders: FolderEntry[] = [];
    for (const id of folderIds) {
      const f = folderLookup.get(id);
      if (f) folders.push(f);
    }
    const fileLookup = new Map<number, FileEntry>();
    for (const f of sortedFiles) fileLookup.set(f.id, f);
    for (const f of currentFiles) if (!fileLookup.has(f.id)) fileLookup.set(f.id, f);
    for (const f of favoriteFiles) if (!fileLookup.has(f.id)) fileLookup.set(f.id, f);
    const files: FileEntry[] = [];
    for (const id of fileIds) {
      const f = fileLookup.get(id);
      if (f) files.push(f);
    }
    if (folders.length + files.length === 0) return;
    shareSource = { kind: 'mixed', folders, files };
    showShareSheet = true;
  }

  // ── Download ───────────────────────────────────────────────────────────────

  async function downloadFile(
    file: FileEntry,
    opts: { skipIosGate?: boolean; iosPath?: IOSPathDecision } = {},
  ) {
    const totalBytes = file.size > 0 ? file.size : 0;
    // iOS gate — pickIosPath returns the tier (RAM vs OPFS) and the
    // block/warn flags sized for that tier. handleDownloadSelection
    // passes skipIosGate + its own decision when it's already gated
    // the selection as a whole; single-file actions from FileList /
    // favorites land here without the flag and run the probe inline.
    let iosPath: IOSPathDecision | undefined = opts.iosPath;
    if (iosDevice && !opts.skipIosGate) {
      iosPath = await pickIosPath(totalBytes);
      if (iosPath.block) {
        byoToast.show(iosBlockMessage(totalBytes, 'owner', 'file', iosPath.path), {
          icon: 'danger',
        });
        return;
      }
      if (iosPath.warn) {
        const ok = window.confirm(
          `${iosWarnMessage(totalBytes, 'owner', 'file', iosPath.path)}\n\nContinue anyway?`,
        );
        if (!ok) return;
      }
    }
    const itemId = byoDownloadQueue.addFile(file.id, file.decrypted_name, totalBytes);

    const runDownload = async () => {
      byoDownloadQueue.setStatus(itemId, 'downloading');
      const ctrl = byoDownloadQueue.getPauseSignal(itemId);
      const abortCtrl = new AbortController();
      try {
        const source = await dataProvider.downloadFile(file.id);
        // Pause/cancel gate: transforms each chunk through the pause signal
        // before passing it on to streamToDisk. On cancel we abort the
        // signal so the writer (File System Access API or SW) tears down
        // cleanly.
        const gated = source.pipeThrough(
          new TransformStream<Uint8Array, Uint8Array>({
            async transform(chunk, controller) {
              if (ctrl?.isCancelled()) {
                abortCtrl.abort();
                throw new DOMException('Cancelled', 'AbortError');
              }
              if (ctrl?.isPaused()) await ctrl.wait();
              if (ctrl?.isCancelled()) {
                abortCtrl.abort();
                throw new DOMException('Cancelled', 'AbortError');
              }
              controller.enqueue(chunk);
            },
          }),
        );
        if (iosDevice) {
          // iOS: buffer via the tier pickIosPath chose (OPFS when the
          // quota probe passes on iOS 16.4+, RAM otherwise). The queue
          // UI renders a Save button as soon as the handle is set.
          const handle = await bufferForIOSSave(
            gated,
            file.decrypted_name,
            file.mime_type || 'application/octet-stream',
            {
              path: iosPath?.path ?? 'ram',
              sizeHint: totalBytes,
              signal: abortCtrl.signal,
              onProgress: (bytes) =>
                byoDownloadQueue.updateBytesDownloaded(itemId, bytes, totalBytes),
            },
          );
          byoDownloadQueue.setIOSSaveHandle(itemId, handle);
          return;
        }
        await streamToDisk(
          gated,
          file.decrypted_name,
          file.mime_type || 'application/octet-stream',
          {
            sizeHint: totalBytes,
            signal: abortCtrl.signal,
            onProgress: (bytes) =>
              byoDownloadQueue.updateBytesDownloaded(itemId, bytes, totalBytes),
          },
        );
        byoDownloadQueue.setStatus(itemId, 'completed');
      } catch (e: any) {
        if (e?.name === 'AbortError' && ctrl?.isCancelled()) {
          byoDownloadQueue.setStatus(itemId, 'cancelled');
        } else {
          byoDownloadQueue.setStatus(itemId, 'error', e?.message || 'Download failed');
        }
      }
    };

    byoDownloadQueue.registerRetry(itemId, runDownload);
    runDownload();
  }

  /**
   * Single-path for selection-driven downloads. Folders always zip
   * (recursive + structure-preserving); a plain file selection zips
   * when >9 items are picked, otherwise falls back to per-file
   * downloads so small selections land as separate files in the
   * Downloads folder like the user expects.
   */
  async function handleDownloadSelection() {
    const folderIds = [...get(byoSelectedFolders)];
    const fileIds = [...get(byoSelectedFiles)];

    // iOS gate — block/warn based on the total plaintext the tab will
    // need to buffer. Loose-file bytes are summable up front; folder
    // contents aren't walked here, so folder zips only get the hard
    // block check inside runZipDownload (by then the stream itself
    // counts bytes). We run the probe once per user action rather
    // than re-running per folder / per zip.
    let iosPath: IOSPathDecision | undefined;
    if (iosDevice) {
      const fileBytes = fileIds.reduce((acc, id) => {
        const f = currentFiles.find((x) => x.id === id) ?? sortedFiles.find((x) => x.id === id);
        return acc + (f?.size ?? 0);
      }, 0);
      iosPath = await pickIosPath(fileBytes);
      if (iosPath.block) {
        byoToast.show(
          iosBlockMessage(
            fileBytes,
            'owner',
            fileIds.length > 1 ? 'archive' : 'file',
            iosPath.path,
          ),
          { icon: 'danger' },
        );
        return;
      }
      if (iosPath.warn) {
        const kind: 'archive' | 'file' = fileIds.length > 9 ? 'archive' : 'file';
        const ok = window.confirm(
          `${iosWarnMessage(fileBytes, 'owner', kind, iosPath.path)}\n\nContinue anyway?`,
        );
        if (!ok) return;
      }
    }

    // Folders: one zip per folder, tree preserved.
    for (const fid of folderIds) {
      try {
        const { stream, filename } = await dataProvider.downloadFolderAsZip(fid);
        await runZipDownload(stream, filename, [], [fid], iosPath);
      } catch (e: any) {
        moveRevokedMsg = e?.message || 'Folder zip failed';
      }
    }

    // Loose files: ≤9 = individual, >9 = single zip.
    if (fileIds.length > 9) {
      const filename = `wattcloud-${fileIds.length}-files.zip`;
      try {
        const stream = await dataProvider.downloadFilesAsZip(fileIds, filename);
        await runZipDownload(stream, filename, fileIds, [], iosPath);
      } catch (e: any) {
        moveRevokedMsg = e?.message || 'Zip download failed';
      }
    } else {
      for (const id of fileIds) {
        const f = currentFiles.find((x) => x.id === id) ?? sortedFiles.find((x) => x.id === id);
        // The iOS gate ran once at the top of this function against the
        // selection's total size; skip the per-file re-prompt and
        // forward the chosen tier so every file in the selection uses
        // the same path (RAM or OPFS).
        if (f) downloadFile(f, { skipIosGate: true, iosPath });
      }
    }
  }

  /** Outbound OS share-sheet invocation. Single ceiling enforced before
   *  any decrypt: 20 files OR 200 MB total plaintext. Folder selections
   *  are rejected (use the share-link flow for those). On success, an
   *  `outbound` row is recorded in `share_audit` per file. The OS does
   *  not disclose the receiving app, so `counterparty_hint` stays null. */
  const SHARE_OS_FILE_CEILING = 20;
  const SHARE_OS_BYTES_CEILING = 200 * 1024 * 1024;

  async function handleSendToOS(explicitFileIds?: number[]) {
    const folderIds = [...get(byoSelectedFolders)];
    if (folderIds.length > 0 && !explicitFileIds) {
      byoToast.show('Folder shares use the link option, not the OS share sheet.', { icon: 'warn' });
      return;
    }
    const fileIds = explicitFileIds ?? [...get(byoSelectedFiles)];
    if (fileIds.length === 0) return;

    if (!get(byoCapabilities).webShareFiles) {
      // Button is shown unconditionally so self-hosters with hardened
      // browsers (RFP, fingerprint protection, ad-blocker overrides) get
      // a discoverable affordance — open the explainer sheet instead of
      // a one-line toast that points nowhere.
      shareUnsupportedReason = 'missing-api';
      shareUnsupportedOpen = true;
      return;
    }

    const rows = fileIds
      .map((id) => currentFiles.find((x) => x.id === id) ?? sortedFiles.find((x) => x.id === id))
      .filter((r): r is FileEntry => !!r);
    if (rows.length === 0) return;

    if (rows.length > SHARE_OS_FILE_CEILING) {
      byoToast.show(`Send up to ${SHARE_OS_FILE_CEILING} files or 200 MB at a time.`, { icon: 'warn' });
      return;
    }
    const totalBytes = rows.reduce((acc, f) => acc + (f.size ?? 0), 0);
    if (totalBytes > SHARE_OS_BYTES_CEILING) {
      byoToast.show(`Send up to ${SHARE_OS_FILE_CEILING} files or 200 MB at a time.`, { icon: 'warn' });
      return;
    }

    // Preparing the payload (download + decrypt + buffer) takes O(seconds)
    // for non-trivial files; without a cue the user is staring at a frozen
    // toolbar between the click and the OS sheet popping. Persist a toast
    // for the duration and update its body per file for multi-selects.
    const total = rows.length;
    const prepLabel = (idx: number) =>
      total === 1 ? 'Preparing file…' : `Preparing ${idx + 1} of ${total}…`;
    byoToast.show(prepLabel(0), { icon: 'info', durationMs: Infinity });

    let files: File[] = [];
    try {
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (i > 0) byoToast.show(prepLabel(i), { icon: 'info', durationMs: Infinity });
        const stream = await dataProvider.downloadFile(row.id);
        const filename = (row as any).decrypted_name || row.name || `file_${row.id}`;
        const mime = (row as any).mime_type || 'application/octet-stream';
        const file = await bufferStreamToFile(stream, filename, mime);
        files.push(file);
      }
    } catch (err: any) {
      console.warn('[share-os] decrypt failed', err);
      byoToast.show(`Couldn’t prepare files to share: ${err?.message ?? 'unknown error'}`, { icon: 'danger' });
      files = [];
      return;
    }
    // Hand off to the OS — dismiss the prep toast; the native share sheet
    // is the visual feedback from here on.
    byoToast.dismiss();

    const title = files.length === 1 ? files[0].name : `${files.length} files from Wattcloud`;
    let shared = false;
    try {
      await shareFilesViaOS(files, { title, text: '' });
      shared = true;
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        // User dismissed the OS sheet — silent.
        return;
      }
      if (err instanceof WebShareUnsupportedForFilesError) {
        shareUnsupportedReason = 'files-rejected';
        shareUnsupportedOpen = true;
        return;
      }
      if (err instanceof WebShareUnsupportedError) {
        shareUnsupportedReason = 'missing-api';
        shareUnsupportedOpen = true;
        return;
      }
      console.warn('[share-os] share failed', err);
      byoToast.show(`Share failed: ${err?.message ?? 'unknown error'}`, { icon: 'danger' });
      return;
    } finally {
      // Drop our refs to the buffered Files so the GC can reclaim the
      // plaintext. The OS sheet has already taken its own reference.
      files.length = 0;
    }

    if (shared) {
      // Audit each share, fire-and-forget. A failure here doesn't
      // affect the user-visible outcome — the share already happened.
      void recordOutboundAudit(rows.map((r) => r.id));
      // One stats event per share gesture, regardless of file count.
      // We don't disclose the picked target app (navigator.share doesn't
      // tell us) or the file count (would leak vault topology).
      recordEvent('share_os_outbound');
    }
  }

  async function recordOutboundAudit(fileIds: number[]) {
    try {
      for (const id of fileIds) {
        await dataProvider.recordShareAudit('outbound', String(id), null);
      }
    } catch (err) {
      console.warn('[share-os] audit emit failed', err);
    }
  }

  /**
   * Pipe a pre-built zip ReadableStream to disk through the download
   * queue, so pause / cancel / progress stay consistent with the
   * per-file download path.
   */
  async function runZipDownload(
    stream: ReadableStream<Uint8Array>,
    filename: string,
    fileIds: number[],
    _folderIds: number[],
    iosPath?: IOSPathDecision,
  ) {
    const itemId = byoDownloadQueue.addBulk(fileIds, filename);
    const ctrl = byoDownloadQueue.getPauseSignal(itemId);
    const abortCtrl = new AbortController();
    byoDownloadQueue.setStatus(itemId, 'downloading');
    try {
      const gated = stream.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          async transform(chunk, controller) {
            if (ctrl?.isCancelled()) {
              abortCtrl.abort();
              throw new DOMException('Cancelled', 'AbortError');
            }
            if (ctrl?.isPaused()) await ctrl.wait();
            if (ctrl?.isCancelled()) {
              abortCtrl.abort();
              throw new DOMException('Cancelled', 'AbortError');
            }
            controller.enqueue(chunk);
          },
        }),
      );
      if (iosDevice) {
        const handle = await bufferForIOSSave(gated, filename, 'application/zip', {
          path: iosPath?.path ?? 'ram',
          signal: abortCtrl.signal,
          onProgress: (bytes) =>
            byoDownloadQueue.updateBytesDownloaded(itemId, bytes, 0),
        });
        byoDownloadQueue.setIOSSaveHandle(itemId, handle);
        return;
      }
      await streamToDisk(gated, filename, 'application/zip', {
        signal: abortCtrl.signal,
        onProgress: (bytes) => byoDownloadQueue.updateBytesDownloaded(itemId, bytes, 0),
      });
      byoDownloadQueue.setStatus(itemId, 'completed');
    } catch (e: any) {
      if (e?.name === 'AbortError' && ctrl?.isCancelled()) {
        byoDownloadQueue.setStatus(itemId, 'cancelled');
      } else {
        byoDownloadQueue.setStatus(itemId, 'error', e?.message || 'Zip download failed');
      }
    }
  }

  // ── File preview ───────────────────────────────────────────────────────────

  /** Previews must materialise as a Blob to feed <img>/<video>/<audio>. Guard
   * against multi-GB files OOMing the tab: FilePreview handles the throw by
   * rendering the error string in place of the preview. */
  const PREVIEW_MAX_BYTES = 200 * 1024 * 1024;

  async function loadFileData(fileId: number): Promise<Blob> {
    const file = currentFiles.find((f) => f.id === fileId);
    if (file && file.size > PREVIEW_MAX_BYTES) {
      throw new Error('Too large to preview. Download to view.');
    }
    const stream = await dataProvider.downloadFile(fileId);
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const mime = file?.mime_type || 'application/octet-stream';
    return new Blob(chunks as unknown as BlobPart[], { type: mime });
  }

  // ── Move/copy ──────────────────────────────────────────────────────────────

  async function handleMoveCopyConfirm(event: { destinationId: number | null; mode: 'move' | 'copy' }) {
    const { destinationId, mode } = event;
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
        console.error('[crossProviderMove]', { fileId, fileName, error: e, message: e?.message, code: e?.code });
        const isHmac = /hmac|integrity/i.test(e.message ?? '');
        const isOom = e?.code === 'UNSUPPORTED';
        errors.push({
          fileId,
          fileName,
          error: isHmac
            ? 'Integrity check failed — not copied'
            : isOom
              ? 'File too large (>512 MiB)'
              : (e?.message || (e?.name ? `${e.name}` : String(e)) || 'Move failed'),
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
      // Sheet stays open at 100% until the user dismisses via Done /
      // backdrop click (handled by onClose). No auto-dismiss.
    }
  }

  function handleMoveRetry(e: { fileIds: number[] }) {
    handleCrossProviderMove(crossMoveDestProviderId, e.fileIds);
  }

  function handleMoveSkipErrors(e: { fileId: number }) {
    crossMoveErrors = crossMoveErrors.filter(err => err.fileId !== e.fileId);
    if (crossMoveErrors.length === 0) {
      if (crossMoveSucceeded !== null && crossMoveSucceeded > 0) {
        loadCurrentFolder();
      }
      showProviderMoveSheet = false;
      crossMoveSucceeded = null;
    }
  }

  // ── Provider switching ─────────────────────────────────────────────────────
  // Switching now happens through the Drawer's Providers section (Drawer.svelte),
  // which writes to vaultStore.activeProviderId. We react reactively below to
  // reset the folder stack and reload — same effect the old chip handler had,
  // just sourced from store changes instead of a chip click.

  let showAddProvider = $state(false);

  let _activeIdLastSeen: string | null = null;
  $effect(() => {
    const id = $vaultStore.activeProviderId;
    if (_activeIdLastSeen === null) {
      // First read after mount — onMount's loadCurrentFolder() handles the
      // initial load, so we just record the baseline.
      _activeIdLastSeen = id;
      return;
    }
    if (id === _activeIdLastSeen) return;
    _activeIdLastSeen = id;
    (dataProvider as any).setActiveProviderId?.(id);
    folderStack = [{ id: null, name: 'Home' }];
    loadCurrentFolder().catch(() => {/* surfaced via byoToast inside */});
    // Favorites are now provider-scoped — reload so the Favorites view
    // (and the star indicators on file rows) reflect the new provider.
    loadFavorites().catch(() => {/* non-fatal */});
  });

  async function onProviderAdded(e: { providerId?: string }) {
    showAddProvider = false;
    if (e.providerId) {
      // The $effect above will pick up the activeProviderId change and
      // reload the folder list automatically.
      vaultStore.setActiveProviderId(e.providerId);
    }
  }

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

  let isDragOver = $state(false);

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

  // Selection is screen-local — switching from Photos to Files (or
  // vice-versa) carries over stale selections that reference items the
  // user can't see, and the selection toolbar would then act on photos
  // from another screen. Clear on every view change; the initial fire
  // is a no-op against the already-empty store.
  $effect(() => {
    view;
    clearByoSelection();
  });
  let currentFolderId = $derived(folderStack[folderStack.length - 1].id);
  // Re-read the preferred view whenever the active folder (or vault) changes.
  // Keeping this reactive means opening a deeply-nested folder that the user
  // previously set to grid restores that choice without any extra wiring.
  $effect(() => {
    const vid = $vaultStore.vaultId;
    const fid = currentFolderId;
    filesViewMode = readViewMode(vid, fid);
    folderStripExpanded = false;
  });
  $effect(() => {
    const now = $byoSelectionMode;
    if (now && !lastSelectionMode && rippleX !== null && rippleY !== null && !reducedMotion) {
      rippleKey++; // force re-render of the ripple element
    }
    lastSelectionMode = now;
  });
  // Per-provider offline state
  let activeProvider = $derived($vaultStore.providers.find(p => p.providerId === $vaultStore.activeProviderId) ?? null);
  let activeProviderOffline = $derived(activeProvider?.status === 'offline' || activeProvider?.status === 'error' || activeProvider?.status === 'unauthorized');
  let offlineProviderCount = $derived($vaultStore.providers.filter(p => p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized').length);
  let canWrite = $derived(!activeProviderOffline && $canOperate);
  // Derived selection state for FileList selectionContext.
  // `toggle` must also flip selection mode on (matching managed-mode behavior
  // in FileList.handleMenuClick) — without this, clicking the three-dots
  // button on a file silently adds it to the selection set but the UI never
  // enters selection mode, so nothing visible happens.
  let selectionContext = $derived({
    isSelectionMode: $byoSelectionMode,
    selectedFiles: $byoSelectedFiles,
    toggle: (id: number) => {
      if (!get(byoSelectionMode)) byoSelectionMode.set(true);
      toggleByoFileSelection(id);
    },
    selectAll: (ids: number[]) => {
      byoSelectionMode.set(true);
      byoSelectedFiles.set(new Set(ids));
    },
    clear: clearByoSelection,
  });
  // Reference sortBy + sortDir in the reactive expression so Svelte's static
  // dependency tracker picks them up. Without an explicit read here the
  // scheduler only re-runs sortEntries when the input array changes, and
  // clicking the sort pills silently leaves the list untouched.
  let sortedFiles = $derived(((_by: SortByT, _dir: 'asc' | 'desc') =>
    sortEntries(
      view === 'favorites'
        ? favoriteFiles
        : $hasByoActiveFilters ? ($byoSearchResults as unknown as FileEntry[]) : currentFiles,
    ))(sortBy as SortByT, sortDir));
  // When search is active, folders come from byoSearchFolderResults instead
  // of being hidden — the chip filter "Folders" sets fileType=folder which
  // suppresses file results, and a free-text query also surfaces matching
  // folder names so the user can navigate by name from the search bar.
  let sortedFolders = $derived(((_by: SortByT, _dir: 'asc' | 'desc') =>
    view === 'favorites'
      ? sortFolders(favoriteFolders)
      : $hasByoActiveFilters
        ? sortFolders($byoSearchFolderResults as unknown as FolderEntry[])
        : sortFolders(currentFolders))(sortBy as SortByT, sortDir));
  // Sorting state for SortControl
  let sortingState = $derived({ by: sortBy as SortByT, direction: (sortDir === 'asc' ? 'up' : 'down') as SortDirT });
  // Typed aliases for template use (Svelte 4 / Acorn doesn't support `as` casts in templates)
  let sortedFilesAny = $derived(sortedFiles as unknown as any[]);
  // Scoped folder list for MoveCopyDialog — only folders belonging to the active provider.
  let activeFolders = $derived(moveCopyFolders.filter(
    (f) => !f.provider_id || f.provider_id === ($vaultStore.activeProviderId ?? ''),
  ));
  let activeFoldersAny = $derived(activeFolders as unknown as any[]);
  let previewFileAny = $derived(previewFile as unknown as any);
  let favoriteFilesAny = $derived(favoriteFiles as unknown as any[]);
  let detailsFolders = $derived([...currentFolders, ...($byoFolders as unknown as FolderEntry[])]);
  let createFolderAny = $derived(handleByoCreateFolder as any);
  $effect(() => {
    // Reload when current folder changes
    if (typeof currentFolderId !== 'undefined') {
      loadCurrentFolder();
    }
  });
</script>

<div
  class="byo-dashboard"
  ondragover={handleDragOver}
  ondragleave={handleDragLeave}
  ondrop={handleDrop}
  role="main"
>
  <!-- Header — drawer controls drive the shared `stores/drawer` stores
       directly, so no prop wiring here; we only plumb search through
       because it's dashboard-scoped. Maps DashboardHeader's plural
       file-type tokens to BYO's singular enum so both search UXes
       collapse to one. -->
  <DashboardHeader
    {showSearch}
    showSearchPanel={true}
    searchQuery={$byoSearchQuery}
    currentView={view}
    hideSearch={view === 'photos'}
    onToggleSearch={() => { showSearch = !showSearch; if (!showSearch) clearByoSearch(); }}
    onCloseSearch={() => { showSearch = false; clearByoSearch(); }}
    onSearchChange={(e) => {
      setByoSearchQuery(e.query ?? '');
      setByoFileTypeFilter(normalizeFileType(e.fileType));
    }}
  />

  <!-- Multi-provider status pill — shown when one or more secondary
       providers are offline, regardless of which provider is active.
       The provider switcher itself moved into the Drawer (above the
       Storage section); this row exists only for the offline notice. -->
  {#if offlineProviderCount > 0}
  <div class="status-bar">
    <div class="status-pills">
      <span class="status-pill status-offline offline-global-pill">
        <CloudSlash size={12} />
        {offlineProviderCount === 1 ? '1 provider offline' : `${offlineProviderCount} providers offline`}
      </span>
    </div>
  </div>
  {/if}

  <!-- Per-provider offline banner (shown when active tab's provider is offline) -->
  {#if activeProviderOffline && activeProvider}
    <OfflineBanner
      providerName={activeProvider.displayName}
      {retrying}
      onRetry={retryActiveProvider}
    />
  {/if}

  <!-- Share-revoked snackbar toast -->
  {#if moveRevokedMsg}
    <div class="move-revoke-toast" role="status" aria-live="polite">
      <span class="move-revoke-icon" aria-hidden="true">ℹ</span>
      <span>{moveRevokedMsg}</span>
      <button class="move-revoke-dismiss" onclick={() => { moveRevokedMsg = ''; }} aria-label="Dismiss">✕</button>
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
    <!-- canShare: anything except an empty selection. Single-file/single-
         folder still go through their dedicated flows for clearer
         recipient titles; everything else funnels through the mixed
         bundle path. -->
    {@const canShareSelection = ($byoSelectedFiles.size + $byoSelectedFolders.size) > 0}
    {@const canRenameSelection =
      ($byoSelectedFiles.size === 1 && $byoSelectedFolders.size === 0) ||
      ($byoSelectedFolders.size === 1 && $byoSelectedFiles.size === 0)}
    {@const canSendToOSSelection =
      $byoSelectedFiles.size > 0 &&
      $byoSelectedFolders.size === 0}
    <SelectionToolbar
      selectedCount={totalSel}
      canDetails={true}
      canShare={canShareSelection}
      canSendToOS={canSendToOSSelection}
      canRename={canRenameSelection}
      canAddToCollection={view === 'photos' && $byoSelectedFiles.size > 0}
      canMoveToProvider={$vaultStore.providers.length > 1 && $byoSelectedFiles.size > 0 && $byoSelectedFolders.size === 0}
      favoriteState={favCount === 0 ? 'none' : favCount === totalSel ? 'all' : 'mixed'}
      onClear={clearByoSelection}
      onRename={triggerRenameFromToolbar}
      onMove={async () => { moveCopyMode = 'move'; await refreshMoveCopyFolders(); showMoveCopyDialog = true; }}
      onCopy={async () => { moveCopyMode = 'copy'; await refreshMoveCopyFolders(); showMoveCopyDialog = true; }}
      onMoveToProvider={() => { showProviderMoveSheet = true; }}
      onFavorite={() => bulkToggleFavorite(true)}
      onUnfavorite={() => bulkToggleFavorite(false)}
      onDownload={() => handleDownloadSelection()}
      onDetails={() => {
        const fileIds = [...get(byoSelectedFiles)];
        const folderIds = [...get(byoSelectedFolders)];
        if (fileIds.length === 1 && folderIds.length === 0) {
          openDetails(fileIds[0]);
        } else if (folderIds.length === 1 && fileIds.length === 0) {
          openFolderDetails(folderIds[0]);
        }
      }}
      onShare={() => {
        const fileIds = [...get(byoSelectedFiles)];
        const folderIds = [...get(byoSelectedFolders)];
        if (fileIds.length === 1 && folderIds.length === 0) {
          openShareSheet(fileIds[0]);
        } else if (folderIds.length === 1 && fileIds.length === 0) {
          openFolderShareSheet(folderIds[0]);
        } else if (fileIds.length >= 2 && folderIds.length === 0) {
          // Multi-file selection (no folders) — flat bundle. Recipient gets
          // every file at the zip root with " (n)" dedup on collisions.
          openFilesShareSheet(fileIds);
        } else {
          // Mixed (folders + files) or multi-folder. The bundle preserves
          // each folder's tree and lays loose files at the root.
          openMixedShareSheet(folderIds, fileIds);
        }
      }}
      onSendToOS={() => handleSendToOS()}
      onDelete={() => {
        const ids = [...get(byoSelectedFiles)];
        if (ids.length > 0) promptDelete('file', ids[0], `${ids.length} file${ids.length !== 1 ? 's' : ''}`);
      }}
      onAddToCollection={openAddToCollection}
    />
  {/if}

  <!-- Main content (pull-to-refresh per §29.3.5) -->
  <PullToRefresh
    class="byo-main-content"
    onRefresh={view === 'favorites' ? loadFavorites : loadCurrentFolder}
    disabled={view === 'photos'}
    onpointerdown={onMainPointerDown}>
    {#if view === 'files'}
      <!-- Breadcrumb pill -->
      <nav class="breadcrumb-pill" aria-label="Folder navigation">
        <button class="breadcrumb-home" onclick={() => navigateToBreadcrumb(0)} aria-label="Home">
          <House size={16} weight="fill" />
        </button>
        {#each folderStack.slice(1) as crumb, i}
          <CaretRight size={12} class="breadcrumb-chevron" />
          {#if i === folderStack.length - 2}
            <span class="breadcrumb-current" title={crumb.name}>{crumb.name}</span>
          {:else}
            <button class="breadcrumb-item" onclick={() => navigateToBreadcrumb(i + 1)}>{crumb.name}</button>
          {/if}
        {/each}
      </nav>

      <!-- Sort controls + view toggle. View toggle persists per-folder to
           localStorage (see readViewMode/writeViewMode above) so a folder
           the user prefers in grid mode stays that way between visits. -->
      <div class="byo-toolbar-row">
        <SortControl
          sorting={sortingState}
          onByChange={onSortByChange}
          onToggleDirection={onToggleSortDir}
        />
        <div class="view-toggle" role="radiogroup" aria-label="View mode">
          <button
            class="view-toggle-btn"
            class:active={filesViewMode === 'list'}
            role="radio"
            aria-checked={filesViewMode === 'list'}
            aria-label="List view"
            title="List view"
            onclick={() => onViewModeChange('list')}
          >
            <Rows size={16} />
          </button>
          <button
            class="view-toggle-btn"
            class:active={filesViewMode === 'grid'}
            role="radio"
            aria-checked={filesViewMode === 'grid'}
            aria-label="Grid view"
            title="Grid view"
            onclick={() => onViewModeChange('grid')}
          >
            <SquaresFour size={16} />
          </button>
        </div>
      </div>

      {#if loading}
        <div class="loading-state">
          <div class="spinner"></div>
        </div>
      {:else if error}
        <div class="error-state">
          <p>{error}</p>
          <button class="btn btn-secondary btn-sm" onclick={loadCurrentFolder}>Retry</button>
        </div>
      {:else}
        <!-- Folders.
             - List mode: rendered as 64dp list rows, unified with the file
               list below it (no optical mismatch between folder tiles and
               thin file rows).
             - Grid mode with ≤ FOLDER_STRIP_THRESHOLD folders: tile grid.
             - Grid mode with many folders: horizontal scroll strip so the
               tiles don't push the file list off-screen. User can expand to
               the full grid via the "Show all" control. -->
        {#if sortedFolders.length > 0}
          {#if filesViewMode === 'list'}
            <div class="folder-section">
              <div class="file-list" role="list">
                {#each sortedFolders as folder (folder.id)}
                  <FolderTile
                    {folder}
                    isSelected={$byoSelectedFolders.has(folder.id)}
                    isSelectionMode={$byoSelectionMode}
                    isFavorite={favoriteFolderIds.has(folder.id)}
                    viewMode="list"
                    onClick={() => {
                      if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                      else { openFolder(folder); }
                    }}
                    onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                    onToggle={() => toggleByoFolderSelection(folder.id)}
                    isRenaming={renamingFolderId === folder.id}
                    bind:renameValue={folderRenameValue}
                    onRenameKeydown={handleFolderRenameKeydown}
                    onRenameBlur={handleFolderRenameBlur}
                  />
                {/each}
              </div>
            </div>
          {:else if sortedFolders.length > FOLDER_STRIP_THRESHOLD && !folderStripExpanded}
            <div class="folder-section">
              <div class="folder-strip-header">
                <span class="folder-strip-label">{sortedFolders.length} folders</span>
                <button
                  class="folder-strip-expand"
                  onclick={() => { folderStripExpanded = true; }}
                >
                  Show all
                </button>
              </div>
              <div class="folder-strip" role="list">
                {#each sortedFolders as folder (folder.id)}
                  <div class="folder-strip-item">
                    <FolderTile
                      {folder}
                      isSelected={$byoSelectedFolders.has(folder.id)}
                      isSelectionMode={$byoSelectionMode}
                      isFavorite={favoriteFolderIds.has(folder.id)}
                      viewMode="grid"
                      onClick={() => {
                        if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                        else { openFolder(folder); }
                      }}
                      onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                      onToggle={() => toggleByoFolderSelection(folder.id)}
                      isRenaming={renamingFolderId === folder.id}
                      bind:renameValue={folderRenameValue}
                      onRenameKeydown={handleFolderRenameKeydown}
                      onRenameBlur={handleFolderRenameBlur}
                    />
                  </div>
                {/each}
              </div>
            </div>
          {:else}
            <div class="folder-section">
              <div class="tiles-grid">
                {#each sortedFolders as folder (folder.id)}
                  <FolderTile
                    {folder}
                    isSelected={$byoSelectedFolders.has(folder.id)}
                    isSelectionMode={$byoSelectionMode}
                    isFavorite={favoriteFolderIds.has(folder.id)}
                    viewMode="grid"
                    onClick={() => {
                      if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                      else { openFolder(folder); }
                    }}
                    onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                    onToggle={() => toggleByoFolderSelection(folder.id)}
                    isRenaming={renamingFolderId === folder.id}
                    bind:renameValue={folderRenameValue}
                    onRenameKeydown={handleFolderRenameKeydown}
                    onRenameBlur={handleFolderRenameBlur}
                  />
                {/each}
              </div>
            </div>
          {/if}
        {/if}

        <!-- File list — same underlying component, driven into grid or list
             by filesViewMode. At ≥600px FileList renders the list view with
             table columns (Name / Modified / Size / Actions). -->
        {#if sortedFiles.length > 0 || sortedFolders.length === 0}
          <FileListSvelte
            files={sortedFilesAny}
            viewMode={filesViewMode}
            {selectionContext}
            favoriteFileIds={favoriteFileIds}
            bind:renameFileId
            onRename={handleRenameFile}
            onPreview={(file) => { previewFile = file; previewOpen = !!previewFile; }}
            onUpload={handleFabUpload}
          />
        {/if}

      {/if}

    {:else if view === 'photos'}
      <ByoPhotoTimeline
        loadFileData={loadFileData}
        bind:sortDir
        {selectionContext}
        onUpload={() => { if (canWrite) handleFabUpload(); }}
        onShareCollection={(e) => {
          const col = $byoCollections.find((c) => c.id === e.collectionId);
          if (col) openCollectionShareSheet(col);
        }}
      />

    {:else if view === 'favorites'}
      <!-- Favorites view. Same folder+file shape as the Files view, so
           reuse the same toolbar + folder-strip + view-toggle pattern. -->
      {#if favoriteFolders.length === 0 && favoriteFiles.length === 0}
        <div class="empty-state">
          <Star size={56} weight="light" color="var(--accent-warm, #E0A320)" opacity="0.55" />
          <p class="empty-heading">Nothing starred yet</p>
          <p class="empty-sub">Star files and folders for quick access.</p>
        </div>
      {:else}
        <div class="byo-toolbar-row">
          <SortControl
            sorting={sortingState}
            onByChange={onSortByChange}
            onToggleDirection={onToggleSortDir}
          />
          <div class="view-toggle" role="radiogroup" aria-label="View mode">
            <button
              class="view-toggle-btn"
              class:active={filesViewMode === 'list'}
              role="radio"
              aria-checked={filesViewMode === 'list'}
              aria-label="List view"
              title="List view"
              onclick={() => onViewModeChange('list')}
            >
              <Rows size={16} />
            </button>
            <button
              class="view-toggle-btn"
              class:active={filesViewMode === 'grid'}
              role="radio"
              aria-checked={filesViewMode === 'grid'}
              aria-label="Grid view"
              title="Grid view"
              onclick={() => onViewModeChange('grid')}
            >
              <SquaresFour size={16} />
            </button>
          </div>
        </div>
        {#if favoriteFolders.length > 0}
          {#if filesViewMode === 'list'}
            <div class="folder-section">
              <div class="file-list" role="list">
                {#each favoriteFolders as folder (folder.id)}
                  <FolderTile
                    {folder}
                    isFavorite={true}
                    isSelected={$byoSelectedFolders.has(folder.id)}
                    isSelectionMode={$byoSelectionMode}
                    viewMode="list"
                    onClick={() => {
                      if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                      else { openFolder(folder); view = 'files'; }
                    }}
                    onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                    onToggle={() => toggleByoFolderSelection(folder.id)}
                    isRenaming={renamingFolderId === folder.id}
                    bind:renameValue={folderRenameValue}
                    onRenameKeydown={handleFolderRenameKeydown}
                    onRenameBlur={handleFolderRenameBlur}
                  />
                {/each}
              </div>
            </div>
          {:else if favoriteFolders.length > FOLDER_STRIP_THRESHOLD && !folderStripExpanded}
            <div class="folder-section">
              <div class="folder-strip-header">
                <span class="folder-strip-label">{favoriteFolders.length} folders</span>
                <button
                  class="folder-strip-expand"
                  onclick={() => { folderStripExpanded = true; }}
                >
                  Show all
                </button>
              </div>
              <div class="folder-strip" role="list">
                {#each favoriteFolders as folder (folder.id)}
                  <div class="folder-strip-item">
                    <FolderTile
                      {folder}
                      isFavorite={true}
                      isSelected={$byoSelectedFolders.has(folder.id)}
                      isSelectionMode={$byoSelectionMode}
                      viewMode="grid"
                      onClick={() => {
                        if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                        else { openFolder(folder); view = 'files'; }
                      }}
                      onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                      onToggle={() => toggleByoFolderSelection(folder.id)}
                      isRenaming={renamingFolderId === folder.id}
                      bind:renameValue={folderRenameValue}
                      onRenameKeydown={handleFolderRenameKeydown}
                      onRenameBlur={handleFolderRenameBlur}
                    />
                  </div>
                {/each}
              </div>
            </div>
          {:else}
            <div class="folder-section">
              <div class="tiles-grid">
                {#each favoriteFolders as folder (folder.id)}
                  <FolderTile
                    {folder}
                    isFavorite={true}
                    isSelected={$byoSelectedFolders.has(folder.id)}
                    isSelectionMode={$byoSelectionMode}
                    viewMode="grid"
                    onClick={() => {
                      if ($byoSelectionMode) { toggleByoFolderSelection(folder.id); }
                      else { openFolder(folder); view = 'files'; }
                    }}
                    onSelect={() => { toggleByoFolderSelection(folder.id); byoSelectionMode.set(true); }}
                    onToggle={() => toggleByoFolderSelection(folder.id)}
                    isRenaming={renamingFolderId === folder.id}
                    bind:renameValue={folderRenameValue}
                    onRenameKeydown={handleFolderRenameKeydown}
                    onRenameBlur={handleFolderRenameBlur}
                  />
                {/each}
              </div>
            </div>
          {/if}
        {/if}
        {#if favoriteFiles.length > 0}
          <FileListSvelte
            files={favoriteFilesAny}
            viewMode={filesViewMode}
            {selectionContext}
            favoriteFileIds={favoriteFileIds}
            bind:renameFileId
            onRename={handleRenameFile}
            onPreview={(file) => { previewFile = file; previewOpen = !!previewFile; }}
            onUpload={handleFabUpload}
          />
        {/if}
      {/if}
    {/if}
  </PullToRefresh>

  <!-- Bottom nav lives at the ByoApp level so it persists across
       dashboard / settings / trash without a re-mount. -->

  <!-- FAB (disabled when active provider is offline).
       Photos view: tap uploads directly — no speed-dial menu since
       folder concepts don't apply to the flat photo timeline. Hide
       entirely on empty photos since the in-view upload CTA is the
       clearer affordance there. -->
  {#if view === 'photos' && $byoPhotoTimeline.length > 0}
    <FAB
      showMenu={false}
      disabled={!canWrite}
      onToggle={() => { if (canWrite) handleFabUpload(); }}
    />
  {:else if view === 'files'}
    <FAB
      showMenu={showFabMenu && canWrite}
      disabled={!canWrite}
      onToggle={() => { if (canWrite) showFabMenu = !showFabMenu; }}
      onUpload={() => { if (canWrite) handleFabUpload(); }}
      onUploadFolder={() => { if (canWrite) handleFabUploadFolder(); }}
      onNewFolder={() => { if (canWrite) { showFabMenu = false; showNewFolderModal = true; } }}
    />
  {/if}

  <!-- Hidden folder input for folder upload -->
  <input
    type="file"
    bind:this={folderInput}
    onchange={onFolderSelected}
    {...{'webkitdirectory': true}}
    multiple
    style="display: none;"
  />

  <!-- Drawer is rendered once at the ByoApp level (shared across
       dashboard/settings/trash) so it doesn't unmount when switching
       screens. -->

  <!-- New folder modal -->
  {#if showNewFolderModal}
    <ConfirmModal
      isOpen={showNewFolderModal}
      title="New Folder"
      confirmText={creatingFolder ? 'Creating…' : 'Create'}
      loading={creatingFolder}
      onConfirm={handleCreateFolder}
      onCancel={() => { showNewFolderModal = false; newFolderName = ''; }}
    >
      <input
        type="text"
        bind:value={newFolderName}
        placeholder="Folder name"
        class="input"
        onkeydown={(e) => e.key === 'Enter' && handleCreateFolder()}
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
    onConfirm={confirmDelete}
    onCancel={() => { showDeleteModal = false; deleteTarget = null; }}
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
      onSendToOS={previewFile
        ? () => handleSendToOS([previewFile!.id])
        : null}
    />
  {/if}

  <!-- Web Share Target inbound sheet — opens once per inbound session
       after the vault is unlocked, reads the OPFS staging, lets the
       user pick a destination, and drops uploads into byoUploadQueue. -->
  <ShareReceiveSheet
    open={shareReceiveSheetOpen}
    sessionId={shareReceiveSessionId}
    dataProvider={dataProvider}
    onClose={handleShareReceiveClosed}
  />

  <!-- "Send to…" failure explainer (Web Share API missing or
       canShare({files}) refused the selection). Shown instead of a
       toast so self-hosters with hardened browsers get actionable
       remediation steps rather than a dead-end message. -->
  <ShareUnsupportedSheet
    open={shareUnsupportedOpen}
    reason={shareUnsupportedReason}
    onClose={() => { shareUnsupportedOpen = false; }}
  />

  <!-- Move/copy dialog (scoped to active provider's folders only) -->
  <MoveCopyDialog
    open={showMoveCopyDialog}
    mode={moveCopyMode}
    itemType="files"
    selectedItemCount={$byoSelectedFiles.size}
    allFolders={activeFoldersAny}
    onCreateFolder={createFolderAny}
    onConfirm={handleMoveCopyConfirm}
    onCancel={() => showMoveCopyDialog = false}
  />

  <!-- File / folder details modal — ByoFileDetails branches on `file`/`folder`. -->
  <ByoFileDetails
    file={detailsFile}
    folder={detailsFolder}
    isOpen={showDetailsModal}
    isFavorite={detailsFile
      ? favoriteFileIds.has(detailsFile.id)
      : detailsFolder
        ? favoriteFolderIds.has(detailsFolder.id)
        : false}
    folders={detailsFolders}
    onClose={() => { showDetailsModal = false; detailsFile = null; detailsFolder = null; }}
  />

  <!-- Share link sheet -->
  {#if showShareSheet && shareSource !== null}
    <ShareLinkSheet
      source={shareSource}
      onClose={() => { showShareSheet = false; shareSource = null; }}
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
      onAdded={onProviderAdded}
      onClose={() => showAddProvider = false}
    />
  {/if}

  <!-- Add-to-collection picker -->
  {#if showAddToCollection}
    <div class="atc-overlay" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) showAddToCollection = false; }} onkeydown={() => {}}>
      <div class="atc-sheet" role="dialog" aria-label="Add photos to collection" aria-modal="true">
        <header class="atc-header">
          <h3 class="atc-title">Add to collection</h3>
          <p class="atc-subtitle">{$byoSelectedFiles.size} photo{$byoSelectedFiles.size === 1 ? '' : 's'} selected</p>
        </header>

        {#if $byoCollections.length > 0}
          <section class="atc-section">
            <h4 class="atc-section-label">Existing collections</h4>
            <div class="atc-list">
              {#each $byoCollections as c (c.id)}
                <button
                  class="atc-row"
                  onclick={() => handleAddToCollection(c.id)}
                  disabled={addingToCollection}
                >
                  <Stack size={18} weight="regular" />
                  <span class="atc-row-name">{c.decrypted_name}</span>
                  <span class="atc-row-count">{c.photo_count}</span>
                </button>
              {/each}
            </div>
          </section>
        {/if}

        <section class="atc-section">
          <h4 class="atc-section-label">New collection</h4>
          <form class="atc-new" onsubmit={(e) => { e.preventDefault(); handleCreateAndAddCollection(); }}>
            <!-- svelte-ignore a11y_autofocus -->
            <input
              type="text"
              class="input atc-new-input"
              placeholder="Collection name"
              bind:value={addToCollectionNewName}
              disabled={addingToCollection}
              autofocus
            />
            <button
              type="submit"
              class="btn btn-primary"
              disabled={addingToCollection || !addToCollectionNewName.trim()}
            >Create &amp; add</button>
          </form>
        </section>

        <footer class="atc-footer">
          <button class="btn btn-ghost" onclick={() => (showAddToCollection = false)} disabled={addingToCollection}>Cancel</button>
        </footer>
      </div>
    </div>
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
    onConfirm={(e) => handleCrossProviderMove(e.destProviderId)}
    onRetry={handleMoveRetry}
    onSkipErrors={handleMoveSkipErrors}
    onClose={() => { if (!crossMoveProgress) { showProviderMoveSheet = false; crossMoveSucceeded = null; crossMoveErrors = []; } }}
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

  /* Desktop: shift main content right of the fixed drawer sidebar so
     content no longer renders underneath it (tracks drawer collapse). */
  @media (min-width: 600px) {
    .byo-dashboard {
      padding-left: var(--drawer-current-width, var(--drawer-width));
      transition: padding-left 0.2s ease;
    }
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

  /* Add-to-collection action lives inside the SelectionToolbar now —
     see the `canAddToCollection` prop pass-through above. No separate
     floating button. */

  /* ── Add-to-collection picker ─────────────────────────────────────── */
  .atc-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    backdrop-filter: blur(2px);
    -webkit-backdrop-filter: blur(2px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: var(--sp-md);
  }
  .atc-sheet {
    background: var(--bg-surface-raised);
    border: 1px solid var(--border);
    border-radius: var(--r-card);
    width: 100%;
    max-width: 440px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--glass-shadow);
  }
  .atc-header {
    padding: var(--sp-lg) var(--sp-lg) var(--sp-sm);
    border-bottom: 1px solid var(--border);
  }
  .atc-title {
    margin: 0;
    font-size: 1.125rem;
    font-weight: 600;
    color: var(--text-primary);
  }
  .atc-subtitle {
    margin: 4px 0 0;
    font-size: var(--t-body-sm-size);
    color: var(--text-secondary);
  }

  .atc-section {
    padding: var(--sp-md) var(--sp-lg);
    border-bottom: 1px solid var(--border);
  }
  .atc-section:last-of-type { border-bottom: none; }
  .atc-section-label {
    margin: 0 0 var(--sp-sm);
    font-size: var(--t-label-size);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .atc-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    overflow-y: auto;
    max-height: 260px;
  }
  .atc-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    padding: 10px var(--sp-md);
    background: var(--bg-surface);
    border: 1px solid transparent;
    border-radius: var(--r-input);
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
    transition: background-color 120ms ease, border-color 120ms ease;
    font-size: var(--t-body-sm-size);
  }
  .atc-row:hover:not([disabled]) {
    background: var(--bg-surface-hover);
    border-color: color-mix(in srgb, var(--accent) 35%, var(--border));
  }
  .atc-row[disabled] { opacity: 0.6; cursor: not-allowed; }
  .atc-row-name { flex: 1; font-weight: 500; }
  .atc-row-count {
    font-size: var(--t-label-size);
    color: var(--text-secondary);
    padding: 2px 8px;
    border-radius: var(--r-pill);
    background: var(--bg-surface-raised);
    min-width: 28px;
    text-align: center;
  }

  .atc-new {
    display: flex;
    gap: var(--sp-sm);
  }
  .atc-new-input { flex: 1; height: 36px; }

  .atc-footer {
    padding: var(--sp-sm) var(--sp-lg);
    display: flex;
    justify-content: flex-end;
    border-top: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .status-pills {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex: 1;
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

  /* Provider chips moved to the Drawer's Providers section. The only
     leftover from this row is the offline pill below. */
  .offline-global-pill {
    margin-left: auto;
  }

  /* ── End provider switcher ──────────────────────────────────────────────── */

  .queue-area {
    padding: 0 var(--sp-md, 16px);
  }

  /* :global so the padding reaches PullToRefresh's inner div (which owns
     its own component scope). Flex + overflow-y now live in PullToRefresh. */
  :global(.byo-main-content) {
    /* Pull the scroll viewport up under the floating DashboardHeader so
       content scrolls behind the (transparent) header rather than getting
       clipped at its lower edge. The negative margin overrides the
       parent's padding-top: var(--header-height) for this element only;
       internal padding-top keeps the first row visible below the icons
       at scrollTop=0. */
    margin-top: calc(-1 * var(--header-height, 56px));
    /* Bottom: clear floating bottom nav (12dp inset + safe-area + 56dp nav + 16dp FAB gap + breathing room). */
    padding: calc(var(--header-height, 56px) + var(--sp-sm, 8px))
             var(--sp-md, 16px)
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

  /* Sort + view-toggle cluster. Right-aligned so it balances against the
     breadcrumb pill on the left. Gap matches the in-pill gap of
     SortControl so the two pills feel like a unit. */
  .byo-toolbar-row {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--sp-sm, 8px);
    margin-bottom: var(--sp-sm, 8px);
    flex-wrap: wrap;
  }

  /* View toggle — DESIGN.md §14.3. Two icon buttons in a shared pill
     container. Active button picks up --accent; inactive stays
     --text-secondary so the resting state reads as "sort-and-view
     controls" not "interactive options fighting for attention". */
  .view-toggle {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: var(--sp-xs, 4px);
    height: 36px;
    background-color: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--r-pill, 9999px);
  }
  .view-toggle-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: transparent;
    border: none;
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999);
    cursor: pointer;
    padding: 0;
    transition: background-color var(--duration-fast, 150ms) ease, color var(--duration-fast, 150ms) ease;
  }
  .view-toggle-btn:hover {
    background-color: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }
  .view-toggle-btn.active {
    background-color: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
  }
  .view-toggle-btn:focus-visible {
    outline: 2px solid var(--accent, #2EB860);
    outline-offset: 2px;
  }

  /* Folder strip — shown when grid-mode folder count exceeds
     FOLDER_STRIP_THRESHOLD. Horizontal scroll so the file list below
     stays in view. Mobile scroll-snap keeps swipes aligned to tile
     boundaries. "Show all" expands back to the full tile grid. */
  .folder-strip-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--sp-xs, 6px);
  }
  .folder-strip-label {
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    letter-spacing: var(--t-label-ls, 0.03em);
    text-transform: uppercase;
    color: var(--text-secondary, #999);
  }
  .folder-strip-expand {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--accent-text, #5FDB8A);
    background: transparent;
    border: none;
    padding: 4px 8px;
    border-radius: var(--r-pill, 9999px);
    cursor: pointer;
    transition: background-color var(--duration-fast, 150ms) ease;
  }
  .folder-strip-expand:hover,
  .folder-strip-expand:focus-visible {
    background-color: var(--bg-surface-hover, #2E2E2E);
    outline: none;
  }
  .folder-strip {
    display: flex;
    gap: var(--sp-sm, 8px);
    overflow-x: auto;
    overflow-y: hidden;
    scroll-snap-type: x proximity;
    -webkit-overflow-scrolling: touch;
    /* Negative side padding + matching margin lets the strip's tiles bleed
       to the screen edge on mobile without clipping the edge tile's
       focus ring. The padding stays inside the overflow so dragging the
       scroll starts from the very first tile's left edge. */
    padding: 2px 4px;
    margin: 0 -4px;
    scrollbar-width: thin;
  }
  .folder-strip::-webkit-scrollbar { height: 6px; }
  .folder-strip::-webkit-scrollbar-thumb {
    background: var(--border, #2E2E2E);
    border-radius: 3px;
  }
  .folder-strip-item {
    flex: 0 0 auto;
    width: 120px;
    scroll-snap-align: start;
  }
  @media (min-width: 600px) {
    .folder-strip-item { width: 140px; }
  }

  .photo-sort {
    display: flex;
    justify-content: flex-end;
    margin-bottom: var(--sp-sm, 8px);
  }

  .photo-sort-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    height: 28px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all var(--duration-fast, 150ms) ease;
  }

  .photo-sort-btn:hover {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }

  .new-folder-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
  }

  .folder-section {
    margin-top: var(--sp-md, 16px);
    margin-bottom: var(--sp-md, 16px);
  }

  .tiles-grid {
    display: grid;
    /* Tighter tile size — folders were rendering ~200px square; that's too
       dominant when the list below it has thin row items. 110–140px keeps
       the tile scannable without eating vertical space. */
    grid-template-columns: repeat(auto-fill, minmax(110px, 140px));
    gap: var(--sp-sm, 8px);
    justify-content: start;
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
