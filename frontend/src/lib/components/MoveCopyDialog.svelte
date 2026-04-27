<script lang="ts">
  import { folders } from '../stores/files';
  import Icon from './Icons.svelte';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import BottomSheet from './BottomSheet.svelte';


  
  
  interface Props {
    open?: boolean;
    mode?: 'move' | 'copy';
    itemType?: 'files' | 'folders' | 'mixed';
    selectedItemCount?: number;
    items?: Array<{ id: number; name: string; type: 'file' | 'folder' }>;
    // When provided, overrides the $folders store for the folder list.
    allFolders?: import('../stores/files').Folder[] | null;
    // Inject create-folder implementation (BYO or managed); handles encrypt + persist.
    onCreateFolder?: ((name: string, parentId: number | null) => Promise<import('../stores/files').Folder>) | null;
  onConfirm?: (...args: any[]) => void;
  onCancel?: (...args: any[]) => void;
  }

  let {
    open = false,
    mode = 'move',
    itemType = 'files',
    selectedItemCount = 0,
    items = [],
    allFolders = null,
    onCreateFolder = null,
    onConfirm,
    onCancel
  }: Props = $props();
// Destination selection: a folder by id OR the vault root. Both dispatch
  // the same `destinationId` (null == vault root), but the UI needs a
  // separate `selectRoot` flag so we can visually distinguish "user
  // picked root" from "user hasn't picked anything yet".
  let selectedDestinationId: number | null = $state(null);
  let selectRoot = $state(false);
  let operationInProgress = $state(false);
  let error = $state('');
  let showNewFolderInput = $state(false);
  let newFolderName = $state('');
  let creatingFolder = $state(false);
  let folderSearch = $state('');
  let activeTab: 'folders' | 'files' = $state('folders');

  let hasSelection = $derived(selectRoot || selectedDestinationId !== null);

  // Use allFolders prop (BYO) or $folders store (managed). Sort by name
  // since the flat browser below relies on alphabetical order — the tree
  // view used to lean on the parent_id chain for ordering, but the flat
  // list has no implicit hierarchy to surface.
  let sourceFolders = $derived(allFolders ?? $folders);
  let filteredFolders = $derived((() => {
    const q = folderSearch.trim().toLowerCase();
    const list = q
      ? sourceFolders.filter((f) => (f.decrypted_name || f.name).toLowerCase().includes(q))
      : sourceFolders.slice();
    return list.sort((a, b) =>
      (a.decrypted_name || a.name).localeCompare(b.decrypted_name || b.name),
    );
  })());

  let fileItems = $derived(items.filter(item => item.type === 'file'));
  let folderItems = $derived(items.filter(item => item.type === 'folder'));

  $effect(() => {
    if (!open) {
      selectedDestinationId = null;
      selectRoot = false;
      error = '';
      operationInProgress = false;
      showNewFolderInput = false;
      newFolderName = '';
      folderSearch = '';
    }
  });

  $effect(() => {
    if (open && itemType === 'folders') {
      activeTab = 'folders';
    } else if (open && itemType === 'files') {
      activeTab = 'files';
    }
  });

  async function handleCreateFolder() {
    if (!newFolderName.trim()) return;

    creatingFolder = true;
    try {
      if (onCreateFolder) {
        await onCreateFolder(newFolderName.trim(), selectedDestinationId);
      }
      newFolderName = '';
      showNewFolderInput = false;
    } catch (e: any) {
      error = 'Failed to create folder: ' + (e.message || 'Unknown error');
      console.error('Folder creation error:', e);
    } finally {
      creatingFolder = false;
    }
  }

  function handleDestinationSelect(id: number) {
    selectedDestinationId = id;
    selectRoot = false;
  }

  function handleRootSelect() {
    selectRoot = true;
    selectedDestinationId = null;
  }

  function handleConfirm() {
    if (!hasSelection) {
      error = 'Please select a destination folder';
      return;
    }

    operationInProgress = true;
    error = '';

    // selectRoot → null destination; any value in selectedDestinationId
    // is already the correct folder id for the non-root path.
    onConfirm?.({
      destinationId: selectRoot ? null : selectedDestinationId,
      mode,
    });
  }

  function handleCancel() {
    onCancel?.();
  }

  function getItemTypeLabel() {
    if (itemType === 'files') return selectedItemCount === 1 ? 'file' : 'files';
    if (itemType === 'folders') return selectedItemCount === 1 ? 'folder' : 'folders';
    return 'items';
  }

  function getOperationLabel() {
    return mode === 'move' ? 'Move' : 'Copy';
  }
</script>

<BottomSheet
  {open}
  title="{getOperationLabel()} {getItemTypeLabel()}"
  subtitle="{getOperationLabel()} {selectedItemCount} {getItemTypeLabel()} to:"
  onClose={handleCancel}
>
  {#if itemType === 'mixed'}
    <div class="tabs">
      <button
        class="tab"
        class:active={activeTab === 'folders'}
        onclick={() => activeTab = 'folders'}
      >
        <Icon name="folder" size={16} />
        Folders ({folderItems.length})
      </button>
      <button
        class="tab"
        class:active={activeTab === 'files'}
        onclick={() => activeTab = 'files'}
      >
        <Icon name="file" size={16} />
        Files ({fileItems.length})
      </button>
    </div>

    <div class="items-preview">
      {#if activeTab === 'folders'}
        {#if folderItems.length === 0}
          <p class="no-items">No folders selected</p>
        {:else}
          <ul class="items-list">
            {#each folderItems as item}
              <li><Icon name="folder" size={14} /> {item.name}</li>
            {/each}
          </ul>
        {/if}
      {:else}
        {#if fileItems.length === 0}
          <p class="no-items">No files selected</p>
        {:else}
          <ul class="items-list">
            {#each fileItems as item}
              <li><Icon name="file" size={14} /> {item.name}</li>
            {/each}
          </ul>
        {/if}
      {/if}
    </div>
  {/if}

  <!-- New Folder Creation -->
  <div class="create-folder-section">
    {#if showNewFolderInput}
      <div class="create-folder-input">
        <input
          type="text"
          placeholder="Folder name"
          bind:value={newFolderName}
          onkeydown={(e) => e.key === 'Enter' && handleCreateFolder()}
          disabled={creatingFolder}
          class="input"
        />
        <button class="btn btn-primary btn-sm" onclick={handleCreateFolder} disabled={creatingFolder || !newFolderName.trim()}>
          {creatingFolder ? 'Creating...' : 'Create'}
        </button>
        <button class="btn btn-ghost btn-sm" onclick={() => { showNewFolderInput = false; newFolderName = ''; }}>
          Cancel
        </button>
      </div>
    {:else}
      <button class="new-folder-btn" onclick={() => showNewFolderInput = true}>
        <Icon name="folderPlus" size={16} />
        New Folder
      </button>
    {/if}
  </div>

  <!-- Folder Search -->
  <div class="folder-search">
    <Icon name="search" size={18} />
    <input
      type="text"
      placeholder="Search folders..."
      bind:value={folderSearch}
    />
    {#if folderSearch}
      <button class="clear-search" onclick={() => folderSearch = ''}>
        <Icon name="close" size={16} />
      </button>
    {/if}
  </div>

  <div class="folder-tree-container">
    <!-- Vault root is a first-class destination (files/folders that live
         at the top level have folder_id = null). Listing it above the
         flat folder list lets the user move/copy items back out of
         nesting. -->
    <button
      type="button"
      class="vault-root-option"
      class:selected={selectRoot}
      onclick={handleRootSelect}
    >
      <Icon name="home" size={16} />
      <span>Vault root</span>
    </button>

    <!-- Flat folder browser. The previous tree view leaned on indenting
         + expand/collapse; with deeper hierarchies that pushed names
         off-screen and made the search filter feel broken because
         matches inside collapsed branches stayed hidden until the user
         expanded each ancestor. A flat list with one row per folder
         skips the tree mechanics entirely — search filters in place,
         every folder is a click away, and the only visual element is
         the folder icon next to the name. -->
    {#if filteredFolders.length === 0}
      <p class="no-folders">No folders match.</p>
    {:else}
      <ul class="flat-folder-list" role="listbox">
        {#each filteredFolders as folder (folder.id)}
          <li>
            <button
              type="button"
              class="flat-folder-item"
              class:selected={!selectRoot && selectedDestinationId === folder.id}
              onclick={() => handleDestinationSelect(folder.id)}
            >
              <FolderSimple
                size={18}
                weight={!selectRoot && selectedDestinationId === folder.id ? 'fill' : 'regular'}
              />
              <span class="flat-folder-name">{folder.decrypted_name || folder.name}</span>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </div>

  {#if error}
    <div class="error-message" role="alert">
      <Icon name="error" size={16} color="var(--danger, #D64545)" />
      <span>{error}</span>
    </div>
  {/if}

  <div class="sheet-actions">
    <button
      class="btn btn-secondary"
      onclick={handleCancel}
      disabled={operationInProgress}
    >
      Cancel
    </button>
    <button
      class="btn btn-primary"
      onclick={handleConfirm}
      disabled={operationInProgress || !hasSelection}
    >
      {#if operationInProgress}
        Processing...
      {:else}
        {getOperationLabel()}
      {/if}
    </button>
  </div>
</BottomSheet>

<style>
  .tabs {
    display: flex;
    gap: var(--sp-sm, 8px);
    margin-bottom: var(--sp-md, 16px);
    border-bottom: 1px solid var(--border, #2E2E2E);
    padding-bottom: var(--sp-sm, 8px);
  }

  .tab {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--text-secondary, #999999);
    cursor: pointer;
    transition: all 100ms ease;
  }

  .tab:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }

  .tab.active {
    background: var(--accent-muted, #1B3627);
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .items-preview {
    margin-bottom: var(--sp-md, 16px);
    padding: var(--sp-sm, 8px);
    background: var(--bg-input, #212121);
    border-radius: var(--r-thumbnail, 8px);
    max-height: 150px;
    overflow-y: auto;
  }

  .no-items {
    color: var(--text-disabled, #616161);
    font-size: var(--t-body-sm-size, 0.8125rem);
    margin: 0;
    text-align: center;
    padding: var(--sp-sm, 8px);
  }

  .items-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .items-list li {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    padding: var(--sp-xs, 4px) 0;
  }

  .create-folder-section {
    margin-bottom: var(--sp-sm, 8px);
  }

  .new-folder-btn {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    width: 100%;
    min-height: 44px;
    padding: 0 var(--sp-md, 16px);
    background: transparent;
    border: 1px dashed var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    font-size: var(--t-button-size, 0.875rem);
    font-weight: var(--t-button-weight, 600);
    cursor: pointer;
    transition: background-color 150ms ease, border-color 150ms ease, color 150ms ease;
    -webkit-tap-highlight-color: transparent;
  }

  .new-folder-btn:hover,
  .new-folder-btn:active {
    background: var(--accent-muted, #1B3627);
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .create-folder-input {
    display: flex;
    gap: var(--sp-sm, 8px);
    align-items: center;
  }

  .create-folder-input .input {
    flex: 1;
    min-height: 44px;
    font-size: var(--t-body-size, 0.9375rem);
    border-radius: var(--r-pill, 9999px);
    padding: 0 var(--sp-md, 16px);
  }

  .folder-search {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-input, #212121);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    margin-bottom: var(--sp-sm, 8px);
    color: var(--text-disabled, #616161);
  }

  .folder-search input {
    flex: 1;
    background: transparent;
    border: none;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    outline: none;
  }

  .folder-search input::placeholder {
    color: var(--text-disabled, #616161);
  }

  .folder-search .clear-search {
    background: none;
    border: none;
    color: var(--text-disabled, #616161);
    cursor: pointer;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .folder-tree-container {
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    padding: var(--sp-sm, 8px);
    max-height: 300px;
    overflow-y: auto;
    background: var(--bg-input, #212121);
    margin-bottom: var(--sp-md, 16px);
  }

  .flat-folder-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .flat-folder-item {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    width: 100%;
    min-height: 40px;
    padding: 0 var(--sp-sm, 8px);
    background: transparent;
    border: none;
    border-radius: var(--r-input, 12px);
    color: var(--text-secondary, #999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    text-align: left;
    transition: background var(--duration-normal, 150ms) ease, color var(--duration-normal, 150ms) ease;
  }
  .flat-folder-item:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }
  .flat-folder-item.selected {
    background: var(--accent-muted, #1B3627);
    color: var(--accent-text, #5FDB8A);
  }
  .flat-folder-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .no-folders {
    margin: 0;
    padding: var(--sp-md, 16px) var(--sp-sm, 8px);
    text-align: center;
    color: var(--text-disabled, #616161);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  /* Vault root option — visually a peer of the FolderTree's top-level
     folders so the user can move items to root via the same click affordance. */
  .vault-root-option {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    width: 100%;
    min-height: 48px;
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    margin-bottom: var(--sp-xs, 4px);
    background: transparent;
    border: none;
    border-radius: var(--r-input, 12px);
    color: var(--text-secondary, #999999);
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 500;
    font-family: var(--font-sans, inherit);
    cursor: pointer;
    text-align: left;
    transition: background var(--duration-normal, 150ms) ease, color var(--duration-normal, 150ms) ease;
  }
  .vault-root-option:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }
  .vault-root-option.selected {
    background: var(--accent-muted, #1B3627);
    color: var(--accent-text, #5FDB8A);
  }

  .error-message {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    margin-bottom: var(--sp-md, 16px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }
</style>
