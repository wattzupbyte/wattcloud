<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import DotsThree from 'phosphor-svelte/lib/DotsThree';
  import Check from 'phosphor-svelte/lib/Check';

  export let folder: { id: number; name: string; decrypted_name?: string; created_at?: string };
  export let isSelected: boolean = false;
  export let isSelectionMode: boolean = false;
  export let isRenaming: boolean = false;
  export let isFavorite: boolean = false;
  export let renameValue: string = '';
  export let viewMode: 'list' | 'grid' = 'grid';

  const dispatch = createEventDispatcher();

  // Compact date for the desktop Modified column — matches FileList's
  // formatDateShort so folder rows and file rows share the column format.
  function formatDateShort(dateStr: string | undefined): string {
    if (!dateStr) return '';
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

  function handleClick(event: MouseEvent) {
    dispatch('click', { id: folder.id, event });
  }

  function handleTouchStart(event: TouchEvent) {
    dispatch('touchstart', { id: folder.id, event });
  }

  function handleTouchMove(event: TouchEvent) {
    dispatch('touchmove', { event });
  }

  function handleTouchEnd(event: TouchEvent) {
    dispatch('touchend', { event });
  }

  function handleMenuClick(event: MouseEvent) {
    event.stopPropagation();
    dispatch('select', { id: folder.id });
  }

  function handleCheckboxClick(event: MouseEvent) {
    event.stopPropagation();
    dispatch('toggle', { id: folder.id });
  }

  function handleRenameKeydown(event: KeyboardEvent) {
    dispatch('renameKeydown', { event });
  }

  function handleRenameBlur() {
    dispatch('renameBlur');
  }
</script>

{#if viewMode === 'list'}
  <!-- List view folder item (DESIGN.md 14.1) -->
  <button
    class="list-item folder-list-item"
    class:item-selected={isSelected}
    class:item-favorite={isFavorite}
    on:click={handleClick}
    on:touchstart={handleTouchStart}
    on:touchmove={handleTouchMove}
    on:touchend={handleTouchEnd}
  >
    <div class="file-icon file-icon-folder">
      <FolderSimple size={20} color="var(--accent-text)" />
    </div>

    {#if isRenaming}
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
      <div class="rename-form" on:click|stopPropagation on:keydown|stopPropagation role="presentation">
        <!-- svelte-ignore a11y-autofocus -->
        <input
          type="text"
          bind:value={renameValue}
          on:keydown={handleRenameKeydown}
          on:blur={handleRenameBlur}
          class="input"
          autofocus
        />
      </div>
    {:else}
      <div class="list-item-content">
        <span class="list-item-name">{folder.decrypted_name || folder.name}</span>
        <span class="list-item-meta">Folder</span>
      </div>
      <!-- Column cells — hidden on mobile, shown at ≥600px to align with
           the file list grid. Folders have no size, so the Size column
           shows an em dash. -->
      <span class="list-item-col list-item-col-date">{formatDateShort(folder.created_at)}</span>
      <span class="list-item-col list-item-col-size">&mdash;</span>
    {/if}

    {#if !isRenaming}
      <button
        class="folder-action-btn"
        class:checked={isSelectionMode && isSelected}
        class:favorite={!isSelectionMode && isFavorite}
        on:click={isSelectionMode ? handleCheckboxClick : handleMenuClick}
        aria-label={isSelectionMode ? (isSelected ? 'Deselect folder' : 'Select folder') : 'Folder actions'}
      >
        {#if isSelectionMode}
          {#if isSelected}
            <Check size={14} color="white" weight="bold" />
          {/if}
        {:else}
          <DotsThree size={20} />
        {/if}
      </button>
    {/if}
  </button>
{:else}
  <!-- Grid view folder item (DESIGN.md 14.2) -->
  <button
    class="grid-item folder-grid-item"
    class:item-selected={isSelected}
    class:item-favorite={isFavorite}
    on:click={handleClick}
    on:touchstart={handleTouchStart}
    on:touchmove={handleTouchMove}
    on:touchend={handleTouchEnd}
  >
    <div class="grid-item-thumbnail file-icon-folder">
      <FolderSimple size={32} color="var(--accent-text)" />

      <button
        class="grid-action-btn"
        class:checked={isSelectionMode && isSelected}
        class:favorite={!isSelectionMode && isFavorite}
        on:click={isSelectionMode ? handleCheckboxClick : handleMenuClick}
        aria-label={isSelectionMode ? (isSelected ? 'Deselect' : 'Select') : 'Folder actions'}
      >
        {#if isSelectionMode}
          {#if isSelected}
            <Check size={14} color="white" weight="bold" />
          {/if}
        {:else}
          <DotsThree size={16} />
        {/if}
      </button>
    </div>

    {#if isRenaming}
      <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
      <div class="grid-item-info" on:click|stopPropagation on:keydown|stopPropagation role="presentation">
        <!-- svelte-ignore a11y-autofocus -->
        <input
          type="text"
          bind:value={renameValue}
          on:keydown={handleRenameKeydown}
          on:blur={handleRenameBlur}
          class="input rename-input"
          autofocus
        />
      </div>
    {:else}
      <div class="grid-item-info">
        <span class="grid-item-name">{folder.decrypted_name || folder.name}</span>
      </div>
    {/if}
  </button>
{/if}

<style>
  /* ── List view folder ────────────────────────────────────── */
  .folder-list-item {
    width: 100%;
    border: none;
    background: none;
    cursor: pointer;
    text-align: left;
    font-family: var(--font-sans);
    -webkit-tap-highlight-color: transparent;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }

  .rename-form {
    flex: 1;
    min-width: 0;
  }

  .rename-form .input {
    height: 36px;
    font-size: var(--t-body-sm-size);
  }

  /* ── List action button ────────────────────────────────── */
  .folder-action-btn {
    width: 28px;
    height: 28px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-surface-raised);
    border: none;
    border-radius: 50%;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0;
    transition: background var(--duration-normal, 150ms) ease, color var(--duration-normal, 150ms) ease;
  }
  .folder-action-btn:hover,
  .folder-action-btn:active,
  .folder-list-item:hover .folder-action-btn {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }
  .folder-action-btn.favorite {
    color: var(--accent-warm);
  }
  .folder-action-btn.checked {
    background: var(--accent);
    color: white;
  }

  /* ── Grid view folder ────────────────────────────────────── */
  .folder-grid-item {
    border: none;
    padding: 0;
    cursor: pointer;
    text-align: left;
    font-family: var(--font-sans);
    -webkit-tap-highlight-color: transparent;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }

  .grid-item-thumbnail {
    position: relative;
    aspect-ratio: 1;
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
  .folder-grid-item:hover .grid-action-btn {
    opacity: 1;
  }
  @media (pointer: coarse) {
    .grid-action-btn {
      opacity: 1;
    }
  }
  .grid-action-btn:hover {
    background-color: var(--bg-surface-hover);
    color: var(--text-primary);
  }

  .rename-input {
    height: 32px;
    font-size: var(--t-body-sm-size);
  }
</style>
