<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import type { FileRecord } from '../stores/files';
  import { selectionMode, toggleFileSelection, selectedFiles, selectAllFiles, clearFileSelection } from '../stores/files';

  // ── BYO dual-mode extension ──────────────────────────────────────────────
  // When provided, replaces the managed-mode selection stores.
  // BYO mode passes its own selection state; managed mode leaves this null.
  export let selectionContext: {
    isSelectionMode: boolean;
    selectedFiles: Set<number>;
    toggle: (id: number) => void;
    selectAll: (ids: number[]) => void;
    clear: () => void;
  } | null = null;

  // When provided (BYO), replaces managed api.renameFile + encryptFilename.
  // Called with (fileId, plaintextName).
  export let onRename: ((fileId: number, plaintextName: string) => Promise<void>) | null = null;
  // When provided (managed), handles encrypt + API rename with the decrypted file key.
  export let managedRename: ((fileId: number, newName: string, fileKey: Uint8Array) => Promise<void>) | null = null;
  // When provided (managed), decrypts an encrypted filename using the file key.
  export let decryptName: ((encryptedName: string, key: Uint8Array) => Promise<string>) | null = null;
  // ─────────────────────────────────────────────────────────────────────────
  import CloudEncBadge from './CloudEncBadge.svelte';

  // Phosphor icons (v2.x imports)
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import File from 'phosphor-svelte/lib/File';
  import FileText from 'phosphor-svelte/lib/FileText';
  import Image from 'phosphor-svelte/lib/Image';
  import VideoCamera from 'phosphor-svelte/lib/VideoCamera';
  import MusicNote from 'phosphor-svelte/lib/MusicNote';
  import FileZip from 'phosphor-svelte/lib/FileZip';
  import FileCode from 'phosphor-svelte/lib/FileCode';
  import Table from 'phosphor-svelte/lib/Table';
  import DotsThree from 'phosphor-svelte/lib/DotsThree';
  import UploadSimple from 'phosphor-svelte/lib/UploadSimple';
  import Check from 'phosphor-svelte/lib/Check';

  export let files: FileRecord[] = [];
  export let fileDecryptedKeys: Record<number, Uint8Array> = {};
  export let renameFileId: number | null = null;
  export let favoriteFileIds: Set<number> = new Set();
  export let showFolderContext: boolean = false;
  export let folderNames: Record<number, string> = {};
  export let viewMode: 'list' | 'grid' = 'list';
  /** BYO mode: show encryption badge on all file thumbnails (§29.1). */
  export let showEncryptionBadge: boolean = false;

  const dispatch = createEventDispatcher();

  let isDragging = false;
  let draggedFileId: number | null = null;
  let showSelectionMode = false;
  let longPressTimer: ReturnType<typeof setTimeout> | null = null;
  let touchStartPos = { x: 0, y: 0 };
  const LONG_PRESS_DURATION = 500;

  // Rename state
  let renamingFileId: number | null = null;
  let fileRenameValue = '';

  // Use selectionContext when provided (BYO mode), else fall back to managed stores.
  $: showSelectionMode = selectionContext ? selectionContext.isSelectionMode : $selectionMode;
  $: activeSelectedFiles = selectionContext ? selectionContext.selectedFiles : $selectedFiles;

  $: if (renameFileId !== null) {
    startFileRename(renameFileId);
    renameFileId = null;
  }

  onMount(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.target instanceof HTMLInputElement ||
          event.target instanceof HTMLTextAreaElement) {
        return;
      }

      if (event.key === 'Escape') {
        event.preventDefault();
        if (selectionContext) selectionContext.clear();
        else { clearFileSelection(); selectionMode.set(false); }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  });

  function formatSize(bytes: number): string {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  }

  function formatDate(dateStr: string): string {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  // Desktop-column date formatter — drops the time-of-day so the Modified
  // column stays compact in the 140px slot. Items within the last 24 h
  // show relative ("3h ago") since "Apr 24" is ambiguous on the same day.
  function formatDateShort(dateStr: string): string {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return '';
    const now = Date.now();
    const age = now - d.getTime();
    if (age < 60 * 60 * 1000) {
      const m = Math.max(1, Math.floor(age / 60000));
      return `${m}m ago`;
    }
    if (age < 24 * 60 * 60 * 1000) {
      return `${Math.floor(age / (60 * 60 * 1000))}h ago`;
    }
    if (d.getFullYear() === new Date().getFullYear()) {
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  type FileIconType = 'folder' | 'image' | 'video' | 'pdf' | 'document' | 'spreadsheet' | 'archive' | 'audio' | 'code' | 'unknown';

  function getFileIconType(filename: string): FileIconType {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const iconMap: Record<string, FileIconType> = {
      jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', bmp: 'image', svg: 'image', webp: 'image', ico: 'image',
      pdf: 'pdf',
      doc: 'document', docx: 'document', txt: 'document', md: 'document', rtf: 'document', odt: 'document',
      xls: 'spreadsheet', xlsx: 'spreadsheet', csv: 'spreadsheet', ods: 'spreadsheet',
      js: 'code', ts: 'code', jsx: 'code', tsx: 'code', py: 'code', rs: 'code', java: 'code',
      cpp: 'code', c: 'code', h: 'code', html: 'code', css: 'code', json: 'code', xml: 'code', go: 'code', rb: 'code', php: 'code',
      zip: 'archive', tar: 'archive', gz: 'archive', rar: 'archive', '7z': 'archive', bz2: 'archive',
      mp4: 'video', avi: 'video', mkv: 'video', mov: 'video', wmv: 'video', flv: 'video', webm: 'video',
      mp3: 'audio', wav: 'audio', flac: 'audio', aac: 'audio', ogg: 'audio', m4a: 'audio', wma: 'audio'
    };
    return iconMap[ext] || 'unknown';
  }

  function getFileIconClass(type: FileIconType): string {
    const classMap: Record<FileIconType, string> = {
      folder: 'file-icon-folder',
      image: 'file-icon-image',
      video: 'file-icon-video',
      pdf: 'file-icon-pdf',
      document: 'file-icon-document',
      spreadsheet: 'file-icon-spreadsheet',
      archive: 'file-icon-archive',
      audio: 'file-icon-audio',
      code: 'file-icon-code',
      unknown: 'file-icon-unknown'
    };
    return classMap[type];
  }

  function getDecryptedFileName(file: FileRecord): string {
    return file.decrypted_name || file.name;
  }

  // Menu handlers - triggers selection mode
  function handleMenuClick(event: MouseEvent | TouchEvent, fileId: number) {
    event.stopPropagation();
    if (selectionContext) {
      selectionContext.toggle(fileId);
    } else {
      if (!showSelectionMode) selectionMode.set(true);
      toggleFileSelection(fileId);
    }
  }

  // Rename handlers
  async function startFileRename(fileId: number) {
    const file = files.find(f => f.id === fileId);
    if (!file) return;

    if (file.decrypted_name) {
      fileRenameValue = file.decrypted_name;
    } else {
      const fileKey = fileDecryptedKeys[fileId];
      if (fileKey) {
        try {
          fileRenameValue = decryptName ? await decryptName(file.name, fileKey) : file.name;
        } catch {
          fileRenameValue = file.name;
        }
      } else {
        fileRenameValue = file.name;
      }
    }

    renamingFileId = fileId;
  }

  async function submitFileRename() {
    if (!renamingFileId || !fileRenameValue.trim()) {
      renamingFileId = null;
      fileRenameValue = '';
      return;
    }

    const fileKey = fileDecryptedKeys[renamingFileId];
    // Managed path requires the decrypted file key; BYO delegates to onRename.
    if (!onRename && !fileKey) {
      renamingFileId = null;
      fileRenameValue = '';
      return;
    }

    try {
      if (onRename) {
        // BYO mode: caller handles encryption
        await onRename(renamingFileId, fileRenameValue.trim());
      } else if (managedRename && fileKey) {
        // Managed mode: caller handles encrypt + API
        await managedRename(renamingFileId, fileRenameValue.trim(), fileKey);
      }
      renamingFileId = null;
      fileRenameValue = '';
      dispatch('refresh');
    } catch (e: any) {
      console.error('Failed to rename file:', e);
      renamingFileId = null;
      fileRenameValue = '';
    }
  }

  function cancelFileRename() {
    renamingFileId = null;
    fileRenameValue = '';
  }

  function handleFileRenameKeydown(event: KeyboardEvent) {
    if (event.key === 'Enter') submitFileRename();
    else if (event.key === 'Escape') cancelFileRename();
  }

  function download(file: FileRecord) {
    dispatch('download', file);
  }

  function deleteFile(file: FileRecord) {
    dispatch('delete', file);
  }

  function isPreviewable(filename: string): boolean {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'];
    return imageExts.includes(ext) || ext === 'pdf';
  }

  function handleFileClick(event: MouseEvent | KeyboardEvent, file: FileRecord) {
    if (showSelectionMode) {
      event.preventDefault();
      event.stopPropagation();
      if (selectionContext) selectionContext.toggle(file.id);
      else toggleFileSelection(file.id);
    } else {
      const decryptedName = file.decrypted_name || file.name;
      if (isPreviewable(decryptedName)) {
        dispatch('preview', file);
      }
    }
  }

  function handleCheckboxClick(event: MouseEvent, file: FileRecord) {
    event.stopPropagation();
    if (selectionContext) selectionContext.toggle(file.id);
    else toggleFileSelection(file.id);
  }

  function isSelected(fileId: number): boolean {
    return activeSelectedFiles.has(fileId);
  }

  function selectAll() {
    if (selectionContext) selectionContext.selectAll(files.map(f => f.id));
    else selectAllFiles(files.map(f => f.id));
  }

  function clearSelection() {
    if (selectionContext) selectionContext.clear();
    else { clearFileSelection(); selectionMode.set(false); }
  }

  // Long-press detection
  function handleTouchStart(event: TouchEvent, file: FileRecord) {
    const touch = event.touches[0];
    touchStartPos = { x: touch.clientX, y: touch.clientY };
    touchFile = file;

    longPressTimer = setTimeout(() => {
      longPressTimer = null;
      if (!showSelectionMode) {
        if (selectionContext) selectionContext.toggle(file.id);
        else { selectionMode.set(true); toggleFileSelection(file.id); }
        if (navigator.vibrate) navigator.vibrate(50);
      }
    }, LONG_PRESS_DURATION);
  }

  function handleTouchMove(event: TouchEvent) {
    if (!longPressTimer) return;

    const touch = event.touches[0];
    const dx = Math.abs(touch.clientX - touchStartPos.x);
    const dy = Math.abs(touch.clientY - touchStartPos.y);

    if (dx > 10 || dy > 10) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  }

  let touchFile: FileRecord | null = null;
  let touchHandledSelection = false;

  function handleTouchEnd(event: TouchEvent) {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
    // In selection mode, toggle on any short tap
    if (showSelectionMode && touchFile) {
      event.preventDefault(); // Prevent subsequent click event
      if (selectionContext) selectionContext.toggle(touchFile.id);
      else toggleFileSelection(touchFile.id);
      touchHandledSelection = true;
    }
    touchFile = null;
  }

  function handleTouchCancel() {
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    }
  }

  // Drag and drop handlers
  function handleDragStart(event: DragEvent, file: FileRecord) {
    if (showSelectionMode) return;

    draggedFileId = file.id;
    if (event.dataTransfer) {
      const selectedFileIds = activeSelectedFiles.size > 0
        ? Array.from(activeSelectedFiles)
        : [file.id];

      event.dataTransfer.setData('application/json', JSON.stringify({
        type: 'file',
        ids: selectedFileIds,
        name: file.name
      }));
      event.dataTransfer.effectAllowed = 'move';
    }
  }

  function handleDragEnd() {
    draggedFileId = null;
  }

  function handleUploadClick() {
    dispatch('upload');
  }
</script>

{#if files.length === 0}
  <!-- Empty state per DESIGN.md §21 / §29.5 — plain Phosphor icon (no cloud wrap). -->
  <div class="empty-state">
    <div class="empty-state-icon">
      <FolderSimple size={56} weight="light" color="var(--text-disabled)" />
    </div>
    <h3 class="empty-state-heading">Your vault is empty</h3>
    <p class="empty-state-text">Upload files to start.</p>
    <button class="btn btn-primary" on:click={handleUploadClick}>
      <UploadSimple size={20} />
      Upload
    </button>
  </div>
{:else if viewMode === 'list'}
  <!-- List View per DESIGN.md 14.1. At ≥600px the rows collapse into a
       proper table (Name | Modified | Size | actions) via CSS grid; below
       600px each row stays as the stacked icon + name + inline meta
       layout. The header row below is hidden on mobile via CSS. -->
  {#if files.length > 0}
    <div class="file-list-header" aria-hidden="true">
      <span class="file-list-header-icon"></span>
      <span class="file-list-header-cell">Name</span>
      <span class="file-list-header-cell file-list-header-cell-right">Modified</span>
      <span class="file-list-header-cell file-list-header-cell-right">Size</span>
      <span class="file-list-header-actions"></span>
    </div>
  {/if}
  <div class="file-list" role="list">
    {#each files as file, i (file.id)}
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions a11y-no-noninteractive-tabindex -->
      <div
        class="list-item"
        class:item-selected={activeSelectedFiles.has(file.id)}
        class:item-favorite={favoriteFileIds.has(file.id)}
        class:dragging={draggedFileId === file.id}
        role="listitem"
        tabindex="0"
        draggable={!showSelectionMode}
        on:dragstart={(e) => handleDragStart(e, file)}
        on:dragend={handleDragEnd}
        on:click={(e) => handleFileClick(e, file)}
        on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && handleFileClick(e, file)}
        on:touchstart={(e) => handleTouchStart(e, file)}
        on:touchmove={handleTouchMove}
        on:touchend={handleTouchEnd}
        on:touchcancel={handleTouchCancel}
      >
        <div class="file-icon-wrap">
          <div class="file-icon {getFileIconClass(getFileIconType(getDecryptedFileName(file)))}">
            {#if getFileIconType(getDecryptedFileName(file)) === 'image'}
              <Image size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'video'}
              <VideoCamera size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'pdf'}
              <FileText size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'document'}
              <FileText size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'spreadsheet'}
              <Table size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'archive'}
              <FileZip size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'audio'}
              <MusicNote size={20} color="var(--text-primary)" />
            {:else if getFileIconType(getDecryptedFileName(file)) === 'code'}
              <FileCode size={20} color="var(--text-primary)" />
            {:else}
              <File size={20} color="var(--text-primary)" />
            {/if}
          </div>
          {#if showEncryptionBadge}
            <span class="enc-badge"><CloudEncBadge size={14} /></span>
          {/if}
        </div>

        {#if renamingFileId === file.id}
          <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
          <div class="rename-form" on:click|stopPropagation on:keydown|stopPropagation role="presentation">
            <!-- svelte-ignore a11y-autofocus -->
            <input
              type="text"
              bind:value={fileRenameValue}
              on:keydown={handleFileRenameKeydown}
              on:blur={submitFileRename}
              class="input"
              autofocus
            />
          </div>
        {:else}
          <div class="list-item-content">
            <span class="list-item-name" title={getDecryptedFileName(file)}>
              {getDecryptedFileName(file)}
            </span>
            <span class="list-item-meta">
              {formatSize(file.size)}
              {#if file.created_at}
                <span class="meta-dot"> &middot; </span>{formatDate(file.created_at)}
              {/if}
              {#if showFolderContext && file.folder_id && folderNames[file.folder_id]}
                <span class="meta-dot"> &middot; </span>
                <span class="folder-context-inline">
                  <FolderSimple size={12} />
                  {folderNames[file.folder_id]}
                </span>
              {/if}
            </span>
          </div>
          <!-- Column cells — hidden on mobile via CSS; at ≥600px they fill
               the Modified / Size slots of the row grid. Rendered
               unconditionally so the grid columns always line up. -->
          <span class="list-item-col list-item-col-date">
            {file.created_at ? formatDateShort(file.created_at) : ''}
          </span>
          <span class="list-item-col list-item-col-size">{formatSize(file.size)}</span>
        {/if}

        {#if renamingFileId !== file.id}
          <button
            class="file-action-btn"
            class:checked={showSelectionMode && activeSelectedFiles.has(file.id)}
            class:favorite={!showSelectionMode && favoriteFileIds.has(file.id)}
            on:click={(e) => showSelectionMode ? handleCheckboxClick(e, file) : handleMenuClick(e, file.id)}
            aria-label={showSelectionMode ? (activeSelectedFiles.has(file.id) ? 'Deselect file' : 'Select file') : 'Select file'}
          >
            {#if showSelectionMode}
              {#if activeSelectedFiles.has(file.id)}
                <Check size={14} color="white" weight="bold" />
              {/if}
            {:else}
              <DotsThree size={20} />
            {/if}
          </button>
        {/if}
      </div>
    {/each}
  </div>
{:else}
  <!-- Grid View per DESIGN.md 14.2 -->
  <div class="file-grid" role="list">
    {#each files as file (file.id)}
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions a11y-no-noninteractive-tabindex -->
      <div
        class="grid-item"
        class:item-selected={activeSelectedFiles.has(file.id)}
        class:item-favorite={favoriteFileIds.has(file.id)}
        class:dragging={draggedFileId === file.id}
        role="listitem"
        tabindex="0"
        draggable={!showSelectionMode}
        on:dragstart={(e) => handleDragStart(e, file)}
        on:dragend={handleDragEnd}
        on:click={(e) => handleFileClick(e, file)}
        on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && handleFileClick(e, file)}
        on:touchstart={(e) => handleTouchStart(e, file)}
        on:touchmove={handleTouchMove}
        on:touchend={handleTouchEnd}
        on:touchcancel={handleTouchCancel}
      >
        <div class="grid-item-thumbnail {getFileIconClass(getFileIconType(getDecryptedFileName(file)))}">
          {#if getFileIconType(getDecryptedFileName(file)) === 'image'}
            <Image size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'video'}
            <VideoCamera size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'pdf'}
            <FileText size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'document'}
            <FileText size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'spreadsheet'}
            <Table size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'archive'}
            <FileZip size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'audio'}
            <MusicNote size={32} color="var(--text-primary)" />
          {:else if getFileIconType(getDecryptedFileName(file)) === 'code'}
            <FileCode size={32} color="var(--text-primary)" />
          {:else}
            <File size={32} color="var(--text-primary)" />
          {/if}

          <button
            class="grid-action-btn"
            class:checked={showSelectionMode && activeSelectedFiles.has(file.id)}
            class:favorite={!showSelectionMode && favoriteFileIds.has(file.id)}
            on:click={(e) => showSelectionMode ? handleCheckboxClick(e, file) : handleMenuClick(e, file.id)}
            aria-label={showSelectionMode ? (activeSelectedFiles.has(file.id) ? 'Deselect' : 'Select') : 'Select file'}
          >
            {#if showSelectionMode}
              {#if activeSelectedFiles.has(file.id)}
                <Check size={16} color="white" weight="bold" />
              {/if}
            {:else}
              <DotsThree size={20} />
            {/if}
          </button>
        </div>

        {#if renamingFileId === file.id}
          <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
          <div class="grid-item-info" on:click|stopPropagation on:keydown|stopPropagation role="presentation">
            <!-- svelte-ignore a11y-autofocus -->
            <input
              type="text"
              bind:value={fileRenameValue}
              on:keydown={handleFileRenameKeydown}
              on:blur={submitFileRename}
              class="input grid-rename-input"
              autofocus
            />
          </div>
        {:else}
          <div class="grid-item-info">
            <span class="grid-item-name" title={getDecryptedFileName(file)}>
              {getDecryptedFileName(file)}
            </span>
            <span class="grid-item-size">{formatSize(file.size)}</span>
            {#if showFolderContext && file.folder_id && folderNames[file.folder_id]}
              <span class="grid-folder-context">
                <FolderSimple size={10} />
                {folderNames[file.folder_id]}
              </span>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  /* ── Empty State (branded, DESIGN.md 29.5) ────────────── */
  .empty-state-icon {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 72px;
    height: 72px;
    margin-bottom: var(--sp-md);
  }

  .empty-state-icon-inner {
    position: absolute;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* ── List View ──────────────────────────────────────────── */
  .file-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs);
  }

  .dragging {
    opacity: 0.5;
  }

  /* ── File action button (list) — matches FolderTile ────── */
  .file-action-btn {
    width: 28px;
    height: 28px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: var(--bg-surface-raised);
    border: none;
    border-radius: 50%;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0;
    transition: background-color 150ms ease, color 150ms ease;
  }
  .file-action-btn:hover,
  .file-action-btn:active,
  .list-item:hover .file-action-btn {
    background-color: var(--bg-surface-hover);
    color: var(--text-primary);
  }
  .file-action-btn.favorite {
    color: var(--accent-warm);
  }
  .file-action-btn.checked {
    background-color: var(--accent);
    color: white;
  }

  /* ── Rename form (list) ────────────────────────────────── */
  .rename-form {
    flex: 1;
    min-width: 0;
  }

  .rename-form .input {
    height: 36px;
    font-size: var(--t-body-sm-size);
  }

  /* (menu-btn removed — replaced by .file-action-btn) */

  /* ── Metadata dot separator ────────────────────────────── */
  .meta-dot {
    color: var(--text-disabled);
  }

  .folder-context-inline {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }

  /* ── Grid View overrides ───────────────────────────────── */
  .grid-item {
    position: relative;
    transition: background-color var(--duration-normal) ease;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }

  .grid-item-thumbnail {
    position: relative;
  }

  .grid-action-btn {
    position: absolute;
    top: var(--sp-xs);
    right: var(--sp-xs);
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.5);
    border: none;
    border-radius: 50%;
    color: white;
    cursor: pointer;
    opacity: 0;
    transition: opacity var(--duration-fast) ease;
    padding: 0;
  }

  .grid-action-btn.favorite {
    color: var(--accent-warm);
    opacity: 1;
  }
  .grid-action-btn.checked {
    background: var(--accent);
    opacity: 1;
  }

  .grid-item:hover .grid-action-btn {
    opacity: 1;
  }

  @media (pointer: coarse) {
    .grid-action-btn {
      opacity: 1;
    }
  }

  .grid-rename-input {
    height: 32px;
    font-size: var(--t-body-sm-size);
  }

  .grid-folder-context {
    display: flex;
    align-items: center;
    gap: 2px;
    font-size: var(--t-label-size);
    color: var(--text-disabled);
    margin-top: 2px;
  }
</style>
