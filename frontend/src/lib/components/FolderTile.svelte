<script lang="ts">
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import DotsThree from 'phosphor-svelte/lib/DotsThree';
  import Check from 'phosphor-svelte/lib/Check';

  interface Props {
    folder: { id: number; name: string; decrypted_name?: string; created_at?: string };
    isSelected?: boolean;
    isSelectionMode?: boolean;
    isRenaming?: boolean;
    isFavorite?: boolean;
    renameValue?: string;
    viewMode?: 'list' | 'grid';
  onClick?: (...args: any[]) => void;
  onTouchstart?: (...args: any[]) => void;
  onTouchmove?: (...args: any[]) => void;
  onTouchend?: (...args: any[]) => void;
  onSelect?: (...args: any[]) => void;
  onToggle?: (...args: any[]) => void;
  onRenameKeydown?: (...args: any[]) => void;
  onRenameBlur?: (...args: any[]) => void;
  }

  let {
    folder,
    isSelected = false,
    isSelectionMode = false,
    isRenaming = false,
    isFavorite = false,
    renameValue = $bindable(''),
    viewMode = 'grid',
    onClick,
    onTouchstart,
    onTouchmove,
    onTouchend,
    onSelect,
    onToggle,
    onRenameKeydown,
    onRenameBlur
  }: Props = $props();
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
    onClick?.({ id: folder.id, event });
  }

  function handleTouchStart(event: TouchEvent) {
    onTouchstart?.({ id: folder.id, event });
  }

  function handleTouchMove(event: TouchEvent) {
    onTouchmove?.({ event });
  }

  function handleTouchEnd(event: TouchEvent) {
    onTouchend?.({ event });
  }

  function handleMenuClick(event: MouseEvent) {
    event.stopPropagation();
    onSelect?.({ id: folder.id });
  }

  function handleCheckboxClick(event: MouseEvent) {
    event.stopPropagation();
    onToggle?.({ id: folder.id });
  }

  function handleRenameKeydown(event: KeyboardEvent) {
    onRenameKeydown?.({ event });
  }

  function handleRenameBlur() {
    onRenameBlur?.();
  }
</script>

{#if viewMode === 'list'}
  <!-- List view folder item (DESIGN.md 14.1) -->
  <div
    class="list-item folder-list-item"
    class:item-selected={isSelected}
    class:item-favorite={isFavorite}
    role="button"
    tabindex="0"
    onclick={handleClick}
    onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleClick(e as unknown as MouseEvent); } }}
    ontouchstart={handleTouchStart}
    ontouchmove={handleTouchMove}
    ontouchend={handleTouchEnd}
  >
    <div class="file-icon file-icon-folder">
      <FolderSimple size={20} color="var(--accent-text)" />
    </div>

    {#if isRenaming}
      <div class="rename-form" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="presentation">
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="text"
          bind:value={renameValue}
          onkeydown={handleRenameKeydown}
          onblur={handleRenameBlur}
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
           is intentionally left empty (an em dash here was visually
           noisy without conveying anything). -->
      <span class="list-item-col list-item-col-date">{formatDateShort(folder.created_at)}</span>
      <span class="list-item-col list-item-col-size"></span>
    {/if}

    {#if !isRenaming}
      <button
        class="folder-action-btn"
        class:checked={isSelectionMode && isSelected}
        class:favorite={!isSelectionMode && isFavorite}
        onclick={isSelectionMode ? handleCheckboxClick : handleMenuClick}
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
  </div>
{:else}
  <!-- Grid view folder item (DESIGN.md 14.2) -->
  <div
    class="grid-item folder-grid-item"
    class:item-selected={isSelected}
    class:item-favorite={isFavorite}
    role="button"
    tabindex="0"
    onclick={handleClick}
    onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleClick(e as unknown as MouseEvent); } }}
    ontouchstart={handleTouchStart}
    ontouchmove={handleTouchMove}
    ontouchend={handleTouchEnd}
  >
    <div class="grid-item-thumbnail file-icon-folder">
      <FolderSimple size={32} color="var(--accent-text)" />

      <button
        class="grid-action-btn"
        class:checked={isSelectionMode && isSelected}
        class:favorite={!isSelectionMode && isFavorite}
        onclick={isSelectionMode ? handleCheckboxClick : handleMenuClick}
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
      <div class="grid-item-info" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="presentation">
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="text"
          bind:value={renameValue}
          onkeydown={handleRenameKeydown}
          onblur={handleRenameBlur}
          class="input rename-input"
          autofocus
        />
      </div>
    {:else}
      <div class="grid-item-info">
        <span class="grid-item-name">{folder.decrypted_name || folder.name}</span>
      </div>
    {/if}
  </div>
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
