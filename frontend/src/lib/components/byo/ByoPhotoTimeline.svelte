<script lang="ts">
  import { onMount, createEventDispatcher, getContext } from 'svelte';
  import type { DataProvider } from '../../byo/DataProvider';
  type DpHolder = { current: DataProvider | null };
  const dpHolder = getContext<DpHolder>('byo:dataProvider');
  import UploadSimple from 'phosphor-svelte/lib/UploadSimple';
  import Images from 'phosphor-svelte/lib/Images';
  import Stack from 'phosphor-svelte/lib/Stack';
  import DotsThree from 'phosphor-svelte/lib/DotsThree';
  import Check from 'phosphor-svelte/lib/Check';
  import Plus from 'phosphor-svelte/lib/Plus';
  import Pencil from 'phosphor-svelte/lib/Pencil';
  import Trash from 'phosphor-svelte/lib/Trash';
  import CaretLeft from 'phosphor-svelte/lib/CaretLeft';
  import ShareNetwork from 'phosphor-svelte/lib/ShareNetwork';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import ArrowUp from 'phosphor-svelte/lib/ArrowUp';
  import ArrowDown from 'phosphor-svelte/lib/ArrowDown';
  import CalendarBlank from 'phosphor-svelte/lib/CalendarBlank';
  import MapPin from 'phosphor-svelte/lib/MapPin';
  import { parseExif } from '../../byo/ExifExtractor';
  import PlaceSearch from '../PlaceSearch.svelte';
  import type { PlaceBounds } from '../../data/placeBounds';
  import {
    byoPhotoTimeline,
    byoPhotosLoading,
    byoThumbnailCache,
    byoPhotoFolderFilter,
    setByoPhotoFolderFilter,
    loadByoPhotoTimeline,
    loadByoThumbnail,
    reextractMissingExif,
  } from '../../byo/stores/byoPhotos';
  import { byoToast } from '../../byo/stores/byoToasts';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import { get } from 'svelte/store';
  import {
    byoCollections,
    byoCollectionsLoading,
    byoSelectedCollectionId,
    byoCollectionFiles,
    loadByoCollections,
    loadByoCollectionFiles,
    createByoCollection,
    renameByoCollection,
    deleteByoCollection,
    removeByoFilesFromCollection,
    moveByoCollection,
  } from '../../byo/stores/byoCollections';
  import type { FileEntry, CollectionEntry, FolderEntry } from '../../byo/DataProvider';
  import FilePreview from '../FilePreview.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import ImageSquare from 'phosphor-svelte/lib/ImageSquare';

  export let loadFileData: ((fileId: number) => Promise<Blob>) | null = null;
  export let sortDir: 'asc' | 'desc' = 'desc';
  /** Selection plumbing — shared with ByoDashboard's byoSelectedFiles store. */
  export let selectionContext: {
    isSelectionMode: boolean;
    selectedFiles: Set<number>;
    toggle: (id: number) => void;
    selectAll: (ids: number[]) => void;
    clear: () => void;
  } | null = null;

  const dispatch = createEventDispatcher<{ upload: void; shareCollection: { collectionId: number } }>();

  $: showSelectionMode = selectionContext?.isSelectionMode ?? false;
  $: activeSelectedFiles = selectionContext?.selectedFiles ?? new Set<number>();

  function toggleSelection(fileId: number) {
    selectionContext?.toggle(fileId);
  }

  function handleTileClick(e: MouseEvent | KeyboardEvent, file: FileEntry) {
    if (showSelectionMode) {
      e.preventDefault();
      e.stopPropagation();
      toggleSelection(file.id);
    } else {
      openPreview(file);
    }
  }

  function handleMenuClick(e: MouseEvent | TouchEvent, file: FileEntry) {
    e.stopPropagation();
    selectionContext?.toggle(file.id);
  }

  // ── Collections state ────────────────────────────────────────────────────
  let newCollectionName = '';
  let showNewCollectionInput = false;
  let creatingCollection = false;
  let renamingCollectionId: number | null = null;
  let renameCollectionValue = '';
  let confirmDeleteCollectionId: number | null = null;
  let deletingCollection = false;

  $: activeCollection = $byoCollections.find((c) => c.id === $byoSelectedCollectionId) ?? null;

  async function handleCreateCollection() {
    const name = newCollectionName.trim();
    if (!name || creatingCollection) return;
    creatingCollection = true;
    try {
      await createByoCollection(name);
      newCollectionName = '';
      showNewCollectionInput = false;
    } finally {
      creatingCollection = false;
    }
  }

  function startRenameCollection(c: CollectionEntry) {
    renamingCollectionId = c.id;
    renameCollectionValue = c.decrypted_name;
  }

  async function submitRenameCollection() {
    const name = renameCollectionValue.trim();
    if (!renamingCollectionId || !name) {
      renamingCollectionId = null;
      return;
    }
    try {
      await renameByoCollection(renamingCollectionId, name);
    } finally {
      renamingCollectionId = null;
      renameCollectionValue = '';
    }
  }

  function handleRenameKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') { e.preventDefault(); submitRenameCollection(); }
    else if (e.key === 'Escape') { renamingCollectionId = null; renameCollectionValue = ''; }
  }

  async function confirmDeleteCollection() {
    if (!confirmDeleteCollectionId || deletingCollection) return;
    deletingCollection = true;
    try {
      await deleteByoCollection(confirmDeleteCollectionId);
      confirmDeleteCollectionId = null;
    } finally {
      deletingCollection = false;
    }
  }

  async function openCollection(id: number) {
    byoSelectedCollectionId.set(id);
    await loadByoCollectionFiles(id);
  }

  function closeCollection() {
    byoSelectedCollectionId.set(null);
    byoCollectionFiles.set([]);
  }

  async function handleRemoveFromCollection(fileId: number) {
    if (!$byoSelectedCollectionId) return;
    await removeByoFilesFromCollection($byoSelectedCollectionId, [fileId]);
  }

  async function handleSetCollectionCover(fileId: number) {
    const cid = $byoSelectedCollectionId;
    if (!cid) return;
    const dp = dpHolder?.current;
    if (!dp) return;
    await dp.setCollectionCover(cid, fileId);
    await loadByoCollections();
  }

  // ── Folder picker (timeline source) ──────────────────────────────────────
  let folderOptions: FolderEntry[] = [];
  let folderPickerOpen = false;

  async function refreshFolderOptions() {
    const dp = dpHolder?.current;
    if (!dp) return;
    try {
      folderOptions = await dp.listAllFolders();
    } catch {
      folderOptions = [];
    }
  }

  onMount(() => { refreshFolderOptions(); });

  async function pickFolder(v: number | null | undefined) {
    folderPickerOpen = false;
    const vId = get(vaultStore).vaultId;
    if (!vId) return;
    setByoPhotoFolderFilter(vId, v);
    await loadByoPhotoTimeline();
  }

  $: currentFolderLabel = (() => {
    const v = $byoPhotoFolderFilter;
    if (v === undefined) return 'All photos';
    if (v === null) return 'Vault root';
    return folderOptions.find((f) => f.id === v)?.decrypted_name ?? 'Folder';
  })();

  // ── Date-range filter ───────────────────────────────────────────────────
  // Session-scoped (no persistence) — narrows the visible timeline to a
  // single year or year+month. null,null = All dates.
  let dateFilterYear: number | null = null;
  let dateFilterMonth: number | null = null;
  let dateFilterOpen = false;

  $: availableYears = (() => {
    const years = new Set<number>();
    for (const g of $byoPhotoTimeline) years.add(g.year);
    return Array.from(years).sort((a, b) => b - a);
  })();

  $: availableMonthsForYear = dateFilterYear == null
    ? []
    : (() => {
        const months = new Set<number>();
        for (const g of $byoPhotoTimeline) if (g.year === dateFilterYear) months.add(g.month);
        return Array.from(months).sort((a, b) => b - a);
      })();

  // Location filter — either:
  //   - `locationOnly` (any GPS), or
  //   - `locationPlace` (GPS inside a selected place bbox).
  // Selecting a place implies locationOnly = true.
  let locationOnly = false;
  let locationPlace: PlaceBounds | null = null;
  let placeSheetOpen = false;

  function fileHasLocation(f: { metadata?: string }): boolean {
    const e = parseExif(f.metadata);
    return typeof e.lat === 'number' && typeof e.lon === 'number';
  }
  function fileInPlace(f: { metadata?: string }, p: PlaceBounds): boolean {
    const e = parseExif(f.metadata);
    if (typeof e.lat !== 'number' || typeof e.lon !== 'number') return false;
    return e.lat >= p.latMin && e.lat <= p.latMax && e.lon >= p.lonMin && e.lon <= p.lonMax;
  }

  function handlePlaceSelect(e: CustomEvent<PlaceBounds>) {
    locationPlace = e.detail;
    placeSheetOpen = false;
  }
  function handlePlaceClear() {
    locationPlace = null;
  }

  // Photos uploaded before the EXIF head-slice was widened (256 KiB → 4 MiB)
  // can have empty lat/lon even when the original JPEG/HEIC carries GPS.
  // This downloads those files, re-extracts EXIF, and writes the metadata
  // back to the vault. Blocking until done — a busy toast keeps the user
  // informed.
  let reextracting = false;
  async function handleReextractExif() {
    if (reextracting) return;
    reextracting = true;
    placeSheetOpen = false;
    byoToast.show('Scanning photos for missing GPS…', { icon: 'info', durationMs: Infinity });
    try {
      const { updated, total } = await reextractMissingExif((done, totalN) => {
        byoToast.show(`Re-scanning ${done} / ${totalN}…`, { icon: 'info', durationMs: Infinity });
      });
      if (total === 0) {
        byoToast.show('All photos already have GPS metadata.', { icon: 'seal' });
      } else if (updated === 0) {
        byoToast.show(`Scanned ${total} photo${total === 1 ? '' : 's'} — none had recoverable GPS.`, { icon: 'warn' });
      } else {
        byoToast.show(`Added GPS to ${updated} of ${total} photo${total === 1 ? '' : 's'}.`, { icon: 'seal' });
      }
    } catch (e) {
      byoToast.show(`Re-scan failed: ${e instanceof Error ? e.message : String(e)}`, { icon: 'danger' });
    } finally {
      reextracting = false;
    }
  }

  // Overwrite displayTimeline declaration above? Simpler: compute a
  // date-filtered view that the template uses instead.
  $: filteredTimeline = (() => {
    let list = displayTimeline;
    if (dateFilterYear != null) list = list.filter((g) => g.year === dateFilterYear);
    if (dateFilterMonth != null) list = list.filter((g) => g.month === dateFilterMonth);
    if (locationPlace) {
      const p = locationPlace;
      list = list
        .map((g) => ({ ...g, files: g.files.filter((f) => fileInPlace(f, p)) }))
        .filter((g) => g.files.length > 0);
    } else if (locationOnly) {
      list = list
        .map((g) => ({ ...g, files: g.files.filter(fileHasLocation) }))
        .filter((g) => g.files.length > 0);
    }
    return list;
  })();

  $: dateFilterLabel = (() => {
    if (dateFilterYear == null) return 'All dates';
    if (dateFilterMonth == null) return String(dateFilterYear);
    return `${MONTH_SHORT[dateFilterMonth - 1]} ${dateFilterYear}`;
  })();

  function pickDate(year: number | null, month: number | null) {
    dateFilterYear = year;
    dateFilterMonth = month;
    dateFilterOpen = false;
  }

  const DAY_NAMES = ['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'];
  const MONTH_SHORT = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  const MONTH_LONG = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];

  type TabId = 'timeline' | 'collections';
  let activeTab: TabId = 'timeline';

  let previewFile: FileEntry | null = null;
  let previewOpen = false;
  $: previewFileAny = previewFile as unknown as any;

  // Store sorts groups newest-first; when sortDir is 'asc' we reverse so
  // oldest days appear at the top. Reversing a copy keeps the original
  // store untouched (other consumers might rely on its default order).
  $: displayTimeline = sortDir === 'asc'
    ? [...$byoPhotoTimeline].reverse()
    : $byoPhotoTimeline;

  function dayKey(g: { year: number; month: number; day: number }) {
    return `${g.year}-${g.month}-${g.day}`;
  }

  function formatDayHeader(year: number, month: number, day: number): string {
    const date = new Date(year, month - 1, day);
    return `${DAY_NAMES[date.getDay()]}, ${MONTH_SHORT[month - 1]} ${day}, ${year}`;
  }

  async function ensureThumbnail(file: FileEntry) {
    if (!$byoThumbnailCache.has(file.id)) {
      await loadByoThumbnail(file);
    }
  }

  // Photo store + thumbnail cache are app-scoped; ByoDashboard resets
  // them on vault lock. No onDestroy cleanup is needed here — tearing
  // them down on tab-switch unmount wipes state that should survive
  // Photos→Files→Photos and forces a full reload + thumbnail re-download.
  onMount(() => {
    loadByoPhotoTimeline();
  });

  function openPreview(file: FileEntry) {
    previewFile = file as any;
    previewOpen = true;
  }

  /** Flat, view-order list of files shown in the lightbox — used by prev/next. */
  $: previewSiblings = activeCollection
    ? $byoCollectionFiles
    : displayTimeline.flatMap((g) => g.files);

  function previewNavigate(delta: number) {
    if (!previewFile) return;
    const idx = previewSiblings.findIndex((f) => f.id === previewFile!.id);
    if (idx < 0) return;
    const next = idx + delta;
    if (next < 0 || next >= previewSiblings.length) return;
    previewFile = previewSiblings[next] as any;
  }

  $: previewHasPrev = previewFile
    ? previewSiblings.findIndex((f) => f.id === previewFile!.id) > 0
    : false;
  $: previewHasNext = previewFile
    ? (() => {
        const i = previewSiblings.findIndex((f) => f.id === previewFile!.id);
        return i >= 0 && i < previewSiblings.length - 1;
      })()
    : false;

  async function loadPreviewBlob(fileId: number): Promise<Blob> {
    if (loadFileData) return loadFileData(fileId);
    throw new Error('No loadFileData provided');
  }

</script>

<div class="photo-timeline">
  <!-- Toolbar: view toggle + folder source picker (timeline only) -->
  <div class="photo-toolbar">
    <div class="view-toggle" role="tablist" aria-label="Photo view">
      <button
        class="toggle-btn"
        class:active={activeTab === 'timeline'}
        role="tab"
        aria-selected={activeTab === 'timeline'}
        on:click={() => { activeTab = 'timeline'; closeCollection(); }}
        title="Timeline"
      >
        <Images size={16} weight="regular" />
        <span class="toggle-label">Timeline</span>
      </button>
      <button
        class="toggle-btn"
        class:active={activeTab === 'collections'}
        role="tab"
        aria-selected={activeTab === 'collections'}
        on:click={() => { activeTab = 'collections'; if ($byoCollections.length === 0) loadByoCollections(); }}
        title="Collections"
      >
        <Stack size={16} weight="regular" />
        <span class="toggle-label">Collections</span>
      </button>
    </div>

    <div class="toolbar-right">
      {#if activeTab === 'timeline'}
        <!-- Filter bar — SortControl-style unified pill container: bg-input
             pill with transparent segments inside, trailing direction toggle.
             Each filter keeps its own dropdown anchored to the chip button.
             Labels collapse to icon-only <600px unless a filter is active. -->
        <div class="filter-bar">
          <div class="folder-picker" class:open={folderPickerOpen}>
            <button
              class="filter-chip"
              class:has-filter={$byoPhotoFolderFilter !== undefined}
              on:click={() => { folderPickerOpen = !folderPickerOpen; if (folderPickerOpen) refreshFolderOptions(); }}
              aria-haspopup="listbox"
              aria-expanded={folderPickerOpen}
              title={currentFolderLabel}
            >
              <FolderSimple size={14} />
              <span class="folder-picker-label">{currentFolderLabel}</span>
              <CaretDown size={12} />
            </button>
            {#if folderPickerOpen}
              <div class="folder-picker-menu" role="listbox">
                <button
                  class="folder-picker-item"
                  class:selected={$byoPhotoFolderFilter === undefined}
                  on:click={() => pickFolder(undefined)}
                >All photos</button>
                <button
                  class="folder-picker-item"
                  class:selected={$byoPhotoFolderFilter === null}
                  on:click={() => pickFolder(null)}
                >Vault root</button>
                {#if folderOptions.length > 0}
                  <div class="folder-picker-divider"></div>
                  {#each folderOptions as f (f.id)}
                    <button
                      class="folder-picker-item"
                      class:selected={$byoPhotoFolderFilter === f.id}
                      on:click={() => pickFolder(f.id)}
                    >{f.decrypted_name}</button>
                  {/each}
                {/if}
              </div>
            {/if}
          </div>

          {#if availableYears.length > 0}
            <div class="folder-picker" class:open={dateFilterOpen}>
              <button
                class="filter-chip"
                class:has-filter={dateFilterYear != null}
                on:click={() => (dateFilterOpen = !dateFilterOpen)}
                aria-haspopup="listbox"
                aria-expanded={dateFilterOpen}
                title={dateFilterLabel}
              >
                <CalendarBlank size={14} />
                <span class="folder-picker-label">{dateFilterLabel}</span>
                <CaretDown size={12} />
              </button>
              {#if dateFilterOpen}
                <div class="folder-picker-menu" role="listbox">
                  <button
                    class="folder-picker-item"
                    class:selected={dateFilterYear == null}
                    on:click={() => pickDate(null, null)}
                  >All dates</button>
                  <div class="folder-picker-divider"></div>
                  {#each availableYears as y (y)}
                    <button
                      class="folder-picker-item"
                      class:selected={dateFilterYear === y && dateFilterMonth == null}
                      on:click={() => pickDate(y, null)}
                    >{y}</button>
                  {/each}
                  {#if availableMonthsForYear.length > 0}
                    <div class="folder-picker-divider"></div>
                    {#each availableMonthsForYear as m (m)}
                      <button
                        class="folder-picker-item sub"
                        class:selected={dateFilterYear != null && dateFilterMonth === m}
                        on:click={() => pickDate(dateFilterYear, m)}
                      >{MONTH_SHORT[m - 1]} {dateFilterYear}</button>
                    {/each}
                  {/if}
                </div>
              {/if}
            </div>
          {/if}

          <div class="folder-picker" class:open={placeSheetOpen}>
            <button
              class="filter-chip"
              class:has-filter={!!locationPlace || locationOnly}
              on:click={() => (placeSheetOpen = !placeSheetOpen)}
              title={locationPlace ? locationPlace.display : (locationOnly ? 'Any location' : 'Filter by location')}
            >
              <MapPin size={14} />
              <span class="folder-picker-label">
                {#if locationPlace}{locationPlace.flag ? `${locationPlace.flag} ` : ''}{locationPlace.display}{:else if locationOnly}Any location{:else}Location{/if}
              </span>
              <CaretDown size={12} />
            </button>
            {#if placeSheetOpen}
              <div class="folder-picker-menu place-menu">
                <button
                  class="folder-picker-item"
                  class:selected={!locationPlace && !locationOnly}
                  on:click={() => { locationPlace = null; locationOnly = false; placeSheetOpen = false; }}
                >Any location</button>
                <button
                  class="folder-picker-item"
                  class:selected={!locationPlace && locationOnly}
                  on:click={() => { locationPlace = null; locationOnly = true; placeSheetOpen = false; }}
                >Located only</button>
                <div class="folder-picker-divider"></div>
                <PlaceSearch
                  selected={locationPlace}
                  on:select={handlePlaceSelect}
                  on:clear={handlePlaceClear}
                />
                <div class="folder-picker-divider"></div>
                <button
                  class="folder-picker-item"
                  on:click={handleReextractExif}
                  disabled={reextracting}
                  title="Re-scan EXIF for photos uploaded before GPS extraction was widened."
                >{reextracting ? 'Scanning…' : 'Re-scan missing GPS'}</button>
              </div>
            {/if}
          </div>

          <button
            class="filter-direction"
            on:click={() => (sortDir = sortDir === 'asc' ? 'desc' : 'asc')}
            aria-label={sortDir === 'desc' ? 'Sorted newest first — click for oldest first' : 'Sorted oldest first — click for newest first'}
            title={sortDir === 'desc' ? 'Newest first' : 'Oldest first'}
          >
            {#if sortDir === 'desc'}<ArrowDown size={14} />{:else}<ArrowUp size={14} />{/if}
          </button>
        </div>
      {:else if !activeCollection}
        <!-- Collections index: primary "new collection" action lives here so
             it's part of the same header bar as the toggle. -->
        {#if showNewCollectionInput}
          <!-- svelte-ignore a11y-autofocus -->
          <input
            type="text"
            class="input collection-name-input"
            bind:value={newCollectionName}
            on:keydown={(e) => {
              if (e.key === 'Enter') { e.preventDefault(); handleCreateCollection(); }
              else if (e.key === 'Escape') { showNewCollectionInput = false; newCollectionName = ''; }
            }}
            on:blur={() => { if (!newCollectionName.trim()) showNewCollectionInput = false; }}
            placeholder="Collection name"
            disabled={creatingCollection}
            autofocus
          />
          <button class="btn btn-primary btn-sm" on:click={handleCreateCollection} disabled={creatingCollection || !newCollectionName.trim()}>
            <Check size={16} weight="bold" />
          </button>
        {:else}
          <button class="btn btn-primary btn-sm" on:click={() => { showNewCollectionInput = true; }}>
            <Plus size={16} weight="bold" />
            New
          </button>
        {/if}
      {/if}
    </div>
  </div>

  {#if activeTab === 'collections'}
    {#if activeCollection}
      <!-- Collection detail view. Back button flanks a stacked title/count
           block; share sits at the far right. No divider — the page's
           background + whitespace provides the separation. -->
      <div class="collection-detail-header">
        <button class="icon-btn" on:click={closeCollection} aria-label="Back to collections" title="Back to collections">
          <CaretLeft size={20} weight="regular" />
        </button>
        <div class="collection-detail-meta">
          <h2 class="collection-title">{activeCollection.decrypted_name}</h2>
          <span class="collection-count">{$byoCollectionFiles.length} photo{$byoCollectionFiles.length === 1 ? '' : 's'}</span>
        </div>
        {#if $byoCollectionFiles.length > 0 && activeCollection}
          <button
            class="icon-btn"
            on:click={() => { if (activeCollection) dispatch('shareCollection', { collectionId: activeCollection.id }); }}
            aria-label="Share collection"
            title="Share collection"
          >
            <ShareNetwork size={20} weight="regular" />
          </button>
        {/if}
      </div>

      {#if $byoCollectionFiles.length === 0}
        <div class="empty">
          <ImageSquare size={48} weight="light" color="var(--text-disabled, #616161)" />
          <p class="empty-heading">Empty collection</p>
          <p class="empty-sub">Select photos in Timeline and use "Add to collection" to populate this album.</p>
        </div>
      {:else}
        <div class="photo-grid collection-grid">
          {#each $byoCollectionFiles as file (file.id)}
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <div
              class="photo-tile"
              class:item-selected={activeSelectedFiles.has(file.id)}
              role="button"
              tabindex="0"
              on:click={(e) => handleTileClick(e, file)}
              on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), handleTileClick(e, file))}
              use:lazyThumbnail={file}
            >
              {#if $byoThumbnailCache.has(file.id)}
                <img src={$byoThumbnailCache.get(file.id)} alt="" class="thumb" />
              {:else}
                <div class="thumb-placeholder"><div class="spinner-sm"></div></div>
              {/if}
              <button
                class="tile-action-btn cover"
                on:click={(e) => { e.stopPropagation(); handleSetCollectionCover(file.id); }}
                class:active={activeCollection && activeCollection.cover_file_id === file.id}
                aria-label={activeCollection && activeCollection.cover_file_id === file.id ? 'Cover photo' : 'Set as cover'}
                title={activeCollection && activeCollection.cover_file_id === file.id ? 'Cover photo' : 'Set as cover'}
              >
                <ImageSquare size={16} weight={activeCollection && activeCollection.cover_file_id === file.id ? 'fill' : 'regular'} />
              </button>
              <button
                class="tile-action-btn trash"
                on:click={(e) => { e.stopPropagation(); handleRemoveFromCollection(file.id); }}
                aria-label="Remove from collection"
                title="Remove from collection"
              >
                <Trash size={16} weight="regular" />
              </button>
            </div>
          {/each}
        </div>
      {/if}
    {:else}
      <!-- Collections index — primary "New collection" action lives in the
           top toolbar so the header bar stays a single row. -->
      <div class="collections-index">
        {#if $byoCollectionsLoading && $byoCollections.length === 0}
          <div class="loading"><div class="spinner"></div><p>Loading collections…</p></div>
        {:else if $byoCollections.length === 0}
          <div class="empty">
            <Stack size={56} weight="light" color="var(--text-disabled, #616161)" />
            <p class="empty-heading">No collections yet</p>
            <p class="empty-sub">Group photos into albums you can share and revisit.</p>
          </div>
        {:else}
          <div class="collections-grid">
            {#each $byoCollections as c (c.id)}
              {#if renamingCollectionId === c.id}
                <div class="collection-card renaming">
                  <!-- svelte-ignore a11y-autofocus -->
                  <input
                    type="text"
                    class="input"
                    bind:value={renameCollectionValue}
                    on:keydown={handleRenameKeydown}
                    on:blur={submitRenameCollection}
                    autofocus
                  />
                </div>
              {:else}
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <div
                  class="collection-card"
                  role="button"
                  tabindex="0"
                  on:click={() => openCollection(c.id)}
                  on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), openCollection(c.id))}
                >
                  <div class="collection-cover">
                    {#if c.cover_file_id && $byoThumbnailCache.has(c.cover_file_id)}
                      <img src={$byoThumbnailCache.get(c.cover_file_id)} alt="" />
                    {:else}
                      <div class="cover-empty"><Stack size={28} weight="light" /></div>
                    {/if}
                  </div>
                  <div class="collection-meta">
                    <span class="collection-name" title={c.decrypted_name}>{c.decrypted_name}</span>
                    <span class="collection-photo-count">{c.photo_count} photo{c.photo_count === 1 ? '' : 's'}</span>
                  </div>
                  <div class="collection-actions">
                    <button
                      class="icon-btn-sm"
                      on:click={(e) => { e.stopPropagation(); moveByoCollection(c.id, -1); }}
                      aria-label="Move up"
                      title="Move up"
                    ><ArrowUp size={14} weight="regular" /></button>
                    <button
                      class="icon-btn-sm"
                      on:click={(e) => { e.stopPropagation(); moveByoCollection(c.id, 1); }}
                      aria-label="Move down"
                      title="Move down"
                    ><ArrowDown size={14} weight="regular" /></button>
                    <button
                      class="icon-btn-sm"
                      on:click={(e) => { e.stopPropagation(); startRenameCollection(c); }}
                      aria-label="Rename collection"
                      title="Rename"
                    ><Pencil size={14} weight="regular" /></button>
                    <button
                      class="icon-btn-sm danger"
                      on:click={(e) => { e.stopPropagation(); confirmDeleteCollectionId = c.id; }}
                      aria-label="Delete collection"
                      title="Delete"
                    ><Trash size={14} weight="regular" /></button>
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        {/if}
      </div>
    {/if}

  {:else if $byoPhotosLoading && $byoPhotoTimeline.length === 0}
    <div class="loading">
      <div class="spinner"></div>
      <p>Loading photos…</p>
    </div>

  {:else if $byoPhotoTimeline.length === 0}
    <div class="empty">
      <ImageSquare size={56} weight="light" color="var(--text-disabled, #616161)" />
      <p class="empty-heading">No memories yet</p>
      <p class="empty-sub">Photos you upload will appear here.</p>
      <button class="btn btn-primary" on:click={() => dispatch('upload')}>
        <UploadSimple size={20} />
        Upload
      </button>
    </div>

  {:else}
    <!-- Day groups. The "All dates" filter pill above already handles
         year/month narrowing; we used to ship a scroll-to-month chip strip
         here, but two UIs for the same thing is churn — dropped 2026-04. -->
    {#each filteredTimeline as group (dayKey(group))}
      <section class="timeline-group">
        <h3 class="group-label">{formatDayHeader(group.year, group.month, group.day)}</h3>
        <div class="photo-grid">
          {#each group.files as file (file.id)}
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <div
              class="photo-tile"
              class:item-selected={activeSelectedFiles.has(file.id)}
              role="button"
              tabindex="0"
              on:click={(e) => handleTileClick(e, file)}
              on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), handleTileClick(e, file))}
              use:lazyThumbnail={file}
            >
              {#if $byoThumbnailCache.has(file.id)}
                <img src={$byoThumbnailCache.get(file.id)} alt="" class="thumb" />
              {:else}
                <div class="thumb-placeholder">
                  <div class="spinner-sm"></div>
                </div>
              {/if}
              <button
                class="tile-action-btn"
                class:checked={showSelectionMode && activeSelectedFiles.has(file.id)}
                on:click={(e) => handleMenuClick(e, file)}
                aria-label={showSelectionMode && activeSelectedFiles.has(file.id) ? 'Deselect photo' : 'Select photo'}
              >
                {#if showSelectionMode && activeSelectedFiles.has(file.id)}
                  <Check size={14} color="white" weight="bold" />
                {:else}
                  <DotsThree size={18} weight="bold" />
                {/if}
              </button>
            </div>
          {/each}
        </div>
      </section>
    {/each}
  {/if}
</div>

{#if confirmDeleteCollectionId !== null}
  <ConfirmModal
    isOpen={true}
    title="Delete collection?"
    message="The collection will be removed. Photos inside it remain in the timeline and are not deleted."
    confirmText={deletingCollection ? 'Deleting…' : 'Delete'}
    loading={deletingCollection}
    on:confirm={confirmDeleteCollection}
    on:cancel={() => { confirmDeleteCollectionId = null; }}
  />
{/if}

<!-- File preview overlay -->
{#if previewOpen && previewFile}
  <FilePreview
    file={previewFileAny}
    isOpen={previewOpen}
    {loadFileData}
    onClose={() => { previewOpen = false; previewFile = null; }}
    onPrev={previewHasPrev ? () => previewNavigate(-1) : null}
    onNext={previewHasNext ? () => previewNavigate(1) : null}
  />
{/if}

<script lang="ts" context="module">
  function lazyThumbnail(node: HTMLElement, file: import('../../byo/DataProvider').FileEntry) {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          import('../../byo/stores/byoPhotos').then(({ loadByoThumbnail }) => {
            loadByoThumbnail(file);
          });
          observer.disconnect();
        }
      },
      { rootMargin: '100px' },
    );
    observer.observe(node);
    return { destroy() { observer.disconnect(); } };
  }
</script>

<style>
  .photo-timeline {
    padding: 0;
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  /* Top toolbar row hosting the view toggle + contextual right-side actions
     (folder picker + sort on Timeline, New collection on Collections).
     No horizontal padding — outer .byo-main-content already insets 16px,
     so adding more here would push the toolbar inward while the photo-grid
     below stays flush. Matching zero keeps view-toggle/filter-bar aligned
     with the thumbnails' left/right edges. */
  .photo-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--sp-md);
    padding: var(--sp-md) 0 var(--sp-sm);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .toolbar-right {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-sm);
    flex-wrap: wrap;
  }
  .toolbar-right .collection-name-input {
    min-width: 180px;
    height: 34px;
  }

  /* Segmented view toggle */
  .view-toggle {
    display: inline-flex;
    padding: 3px;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    flex-shrink: 0;
  }

  /* Filter bar — SortControl-style container that hosts all filter chips
     + the sort-direction toggle as a single unit so the toolbar reads as
     one control, not four scattered pills. */
  .filter-bar {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs);
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    padding: var(--sp-xs);
    height: 36px;
  }

  .folder-picker { position: relative; }
  .filter-chip {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs);
    padding: 0 var(--sp-sm);
    height: 28px;
    border-radius: var(--r-pill);
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: var(--t-body-sm-size);
    font-family: var(--font-sans);
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: all var(--duration-fast) ease;
  }
  .filter-chip:hover {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }
  .filter-chip.has-filter {
    background: var(--accent);
    color: var(--text-inverse);
  }
  .filter-chip.has-filter:hover {
    background: var(--accent-hover);
    color: var(--text-inverse);
  }
  .folder-picker.open .filter-chip {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }
  .folder-picker.open .filter-chip.has-filter {
    background: var(--accent-hover);
    color: var(--text-inverse);
  }

  /* Sort-direction — mirrors SortControl.svelte .sort-direction. Icon-only,
     small, no label regardless of breakpoint. */
  .filter-direction {
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    border-radius: var(--r-pill);
    color: var(--text-secondary);
    cursor: pointer;
    transition: all var(--duration-fast) ease;
    flex-shrink: 0;
  }
  .filter-direction:hover {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }

  .folder-picker-label {
    max-width: 140px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Medium-narrow screens — icon-only filter chips unless the filter is
     active, in which case the value stays visible so the user can see
     what's being narrowed. 899px matches the drawer-open laptop case
     (~1024 − 240 drawer ≈ 784 content) where the full-labeled toolbar
     would wrap. Standard CSS breakpoints hover around 600 (compact) /
     900 (medium) / 1200 (expanded) — 899 is the Material "medium" edge. */
  @media (max-width: 899px) {
    .filter-chip .folder-picker-label { display: none; }
    .filter-chip.has-filter .folder-picker-label { display: inline; }
  }
  .folder-picker-menu {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    min-width: 200px;
    max-height: 320px;
    overflow-y: auto;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border);
    border-radius: var(--r-input);
    box-shadow: var(--shadow-dropdown);
    z-index: 50;
    padding: 4px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .folder-picker-item {
    text-align: left;
    padding: 8px 12px;
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: var(--t-body-sm-size);
    border-radius: 8px;
    cursor: pointer;
    transition: background-color 100ms ease;
  }
  .folder-picker-item:hover { background: var(--bg-surface-hover); }
  .folder-picker-item.selected { background: color-mix(in srgb, var(--accent) 18%, transparent); color: var(--accent-text); }
  .folder-picker-item.sub { padding-left: 24px; font-size: var(--t-label-size); color: var(--text-secondary); }
  .folder-picker-item.sub.selected { color: var(--accent-text); }
  .folder-picker-divider { height: 1px; background: var(--border); margin: 4px 0; }
  .folder-picker-menu.place-menu { min-width: 320px; padding: var(--sp-sm); }

  .toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs);
    background: none;
    border: none;
    padding: 6px 14px;
    font-size: var(--t-body-sm-size);
    font-weight: 500;
    color: var(--text-secondary);
    cursor: pointer;
    border-radius: var(--r-pill);
    transition: background-color 120ms ease, color 120ms ease;
  }

  .toggle-btn:hover {
    color: var(--text-primary);
  }

  .toggle-btn.active {
    background: var(--accent);
    color: var(--text-inverse, #fff);
  }

  /* Collapse view-toggle labels to icons at the same medium breakpoint as
     the filter chips so the toolbar stays on a single row. */
  @media (max-width: 899px) {
    .toggle-btn { padding: 6px 10px; }
    .toggle-label { display: none; }
  }

  /* Collections index — share the same 0 horizontal inset as the photo
     timeline so the cards align with the toolbar's view-toggle and
     filter-bar (outer .byo-main-content already provides the 16px margin). */
  .collections-index {
    padding: var(--sp-md) 0;
    flex: 1;
    overflow-y: auto;
  }

  .collection-name-input {
    flex: 1;
    max-width: 320px;
    height: 36px;
  }

  .collections-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: var(--sp-md);
  }

  .collection-card {
    display: flex;
    flex-direction: column;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border);
    border-radius: var(--r-card);
    padding: var(--sp-sm);
    cursor: pointer;
    gap: var(--sp-sm);
    transition: background-color 120ms ease;
  }

  .collection-card:hover {
    background: var(--bg-surface-hover);
  }

  .collection-cover {
    aspect-ratio: 1;
    border-radius: var(--r-thumbnail);
    overflow: hidden;
    background: var(--bg-surface);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .collection-cover img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
  .cover-empty {
    color: var(--text-disabled);
  }

  .collection-meta {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .collection-name {
    font-size: var(--t-body-sm-size);
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .collection-photo-count {
    font-size: var(--t-label-size);
    color: var(--text-secondary);
  }
  .collection-actions {
    display: flex;
    gap: 4px;
    justify-content: flex-end;
  }
  .icon-btn-sm {
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: var(--bg-surface);
    color: var(--text-secondary);
    border-radius: 50%;
    cursor: pointer;
    transition: background-color 120ms ease, color 120ms ease;
  }
  .icon-btn-sm:hover { background: var(--bg-surface-hover); color: var(--text-primary); }
  .icon-btn-sm.danger:hover { color: var(--danger); }

  .collection-card.renaming {
    padding: var(--sp-sm);
  }

  /* Collection detail header — back button, stacked title/count, share.
     No bottom border; no inner horizontal padding (outer dashboard shell
     already provides the 16px inset). */
  .collection-detail-header {
    display: flex;
    align-items: center;
    gap: var(--sp-md);
    padding: var(--sp-md) 0 var(--sp-sm);
  }
  .collection-detail-meta {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .collection-title {
    margin: 0;
    font-size: var(--t-h2-size);
    font-weight: var(--t-h2-weight);
    line-height: var(--t-h2-lh);
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .collection-count {
    font-size: var(--t-label-size);
    color: var(--text-secondary);
  }
  .icon-btn {
    width: 36px;
    height: 36px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    border-radius: 50%;
    cursor: pointer;
  }
  .icon-btn:hover { background: var(--bg-surface-hover); color: var(--text-primary); }

  /* Three-dots action overlaid on each photo tile */
  .tile-action-btn {
    position: absolute;
    top: 6px;
    right: 6px;
    width: 28px;
    height: 28px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.55);
    border: none;
    color: #fff;
    border-radius: 50%;
    cursor: pointer;
    opacity: 0;
    transition: opacity 120ms ease, background-color 120ms ease;
  }
  .photo-tile:hover .tile-action-btn,
  .photo-tile:focus-within .tile-action-btn {
    opacity: 1;
  }
  .tile-action-btn.checked {
    background: var(--accent);
    opacity: 1;
  }
  .tile-action-btn.active {
    background: var(--accent);
    opacity: 1;
  }
  .tile-action-btn.cover { right: 40px; }
  .tile-action-btn.trash { right: 6px; }
  /* Cover button needs to be discoverable without hover — otherwise users
     can't find how to swap the album cover. Show it at reduced opacity on
     every photo tile; hover/focus bring it to full. The current cover
     (.active) already stays at opacity 1 via the rule above. */
  .tile-action-btn.cover {
    opacity: 0.65;
  }
  .photo-tile:hover .tile-action-btn.cover,
  .photo-tile:focus-within .tile-action-btn.cover {
    opacity: 1;
  }
  @media (pointer: coarse) {
    .tile-action-btn { opacity: 1; }
  }

  /* No outline on selected photo tiles — consistent with file tiles, which
     signal selection only via the checked action-button state. */

  .loading, .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px) var(--sp-md, 16px);
    text-align: center;
    color: var(--text-secondary, #999999);
  }

  .empty-heading {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .empty-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    margin: 0;
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

  /* Day groups */
  .timeline-group {
    margin-bottom: 0;
  }

  .group-label {
    position: sticky;
    top: 0;
    margin: 0;
    padding: var(--sp-sm, 8px) 0;
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    letter-spacing: 0.04em;
    color: var(--text-secondary, #999999);
    background: var(--bg-base, #141414);
    z-index: 2;
  }

  /* Grid — §16.2: 3-col default, 5-col at ≥600px, 2px gap, no border-radius */
  .photo-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    /* Slightly looser gap — rounded corners need breathing room. */
    gap: var(--sp-xs, 4px);
  }

  @media (min-width: 600px) {
    .photo-grid {
      grid-template-columns: repeat(5, 1fr);
    }
  }

  .photo-tile {
    position: relative;
    aspect-ratio: 1;
    overflow: hidden;
    cursor: pointer;
    background: var(--bg-surface-raised, #262626);
    /* Match the standard thumbnail radius used on file/folder tiles. */
    border-radius: var(--r-thumbnail);
  }

  .photo-tile:focus-visible {
    outline: 2px solid var(--accent, #2EB860);
    outline-offset: -2px;
    z-index: 1;
  }

  .thumb {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }

  .thumb-placeholder {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .spinner-sm {
    width: 20px;
    height: 20px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
</style>
