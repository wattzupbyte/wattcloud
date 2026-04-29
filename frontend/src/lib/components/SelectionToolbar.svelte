<script lang="ts">
  import { fade, fly } from 'svelte/transition';

  // Phosphor icons (v2.x imports)
  import X from 'phosphor-svelte/lib/X';
  import ShareNetwork from 'phosphor-svelte/lib/ShareNetwork';
  import PaperPlaneTilt from 'phosphor-svelte/lib/PaperPlaneTilt';
  import ArrowRight from 'phosphor-svelte/lib/ArrowRight';
  import ArrowsLeftRight from 'phosphor-svelte/lib/ArrowsLeftRight';
  import Trash from 'phosphor-svelte/lib/Trash';
  import DotsThreeVertical from 'phosphor-svelte/lib/DotsThreeVertical';
  import Copy from 'phosphor-svelte/lib/Copy';
  import Star from 'phosphor-svelte/lib/Star';
  import DownloadSimple from 'phosphor-svelte/lib/DownloadSimple';
  import PencilSimple from 'phosphor-svelte/lib/PencilSimple';
  import Info from 'phosphor-svelte/lib/Info';
  import Stack from 'phosphor-svelte/lib/Stack';

  
  
  
  interface Props {
    selectedCount?: number;
    canMove?: boolean;
    canCopy?: boolean;
    canDelete?: boolean;
    canRename?: boolean;
    canFavorite?: boolean;
    canDownload?: boolean;
    canDetails?: boolean;
    /** Show share link button — only active when exactly one file is selected. */
    canShare?: boolean;
    /** Show "Send to..." (OS share-sheet) button. Files-only; folder
     *  selections hide it. Available for both single and multi-select. */
    canSendToOS?: boolean;
    /** Show "Add to collection" button (Photos view). */
    canAddToCollection?: boolean;
    /** Show "Move to another provider" — only when the open vault has
     *  more than one provider attached (BYO multi-provider mode). */
    canMoveToProvider?: boolean;
    /** 'none' = none are favorites, 'all' = all are favorites, 'mixed' = some are */
    favoriteState?: 'none' | 'all' | 'mixed';
    onClear?: () => void;
    onDetails?: () => void;
    onShare?: () => void;
    onSendToOS?: () => void;
    onRename?: () => void;
    onDownload?: () => void;
    onMove?: () => void;
    onCopy?: () => void;
    onFavorite?: () => void;
    onUnfavorite?: () => void;
    onDelete?: () => void;
    onAddToCollection?: () => void;
    onMoveToProvider?: () => void;
  }

  let {
    selectedCount = 0,
    canMove = true,
    canCopy = true,
    canDelete = true,
    canRename = false,
    canFavorite = true,
    canDownload = true,
    canDetails = false,
    canShare = false,
    canSendToOS = false,
    canAddToCollection = false,
    canMoveToProvider = false,
    favoriteState = 'none',
    onClear,
    onDetails,
    onShare,
    onSendToOS,
    onRename,
    onDownload,
    onMove,
    onCopy,
    onFavorite,
    onUnfavorite,
    onDelete,
    onAddToCollection,
    onMoveToProvider
  }: Props = $props();
let showSheet = $state(false);
  let favBurstActive = $state(false);
  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function emit(event: string) {
    showSheet = false;
    switch (event) {
      case 'clear':            onClear?.(); break;
      case 'details':          onDetails?.(); break;
      case 'share':            onShare?.(); break;
      case 'sendToOS':         onSendToOS?.(); break;
      case 'rename':           onRename?.(); break;
      case 'download':         onDownload?.(); break;
      case 'move':             onMove?.(); break;
      case 'copy':             onCopy?.(); break;
      case 'favorite':         onFavorite?.(); break;
      case 'unfavorite':       onUnfavorite?.(); break;
      case 'delete':           onDelete?.(); break;
      case 'addToCollection':  onAddToCollection?.(); break;
      case 'moveToProvider':   onMoveToProvider?.(); break;
    }
  }

  function handleFavorite() {
    if (favoriteEvent === 'favorite' && !reducedMotion) {
      favBurstActive = true;
      setTimeout(() => { favBurstActive = false; }, 400);
    }
    emit(favoriteEvent);
  }

  let singleSelection = $derived(selectedCount === 1);
  let favoriteLabel = $derived(favoriteState === 'all' ? 'Remove from Favorites' : favoriteState === 'mixed' ? 'Toggle Favorites' : 'Add to Favorites');
  let favoriteEvent = $derived(favoriteState === 'all' ? 'unfavorite' : 'favorite');

  function handleSheetKeydown(e: KeyboardEvent) {
    if (showSheet && e.key === 'Escape') showSheet = false;
  }
</script>

<svelte:window onkeydown={handleSheetKeydown} />

<!-- Desktop: top bar (DESIGN.md 15) -->
<div class="selection-top-bar top-bar top-bar-selection desktop-bar" role="toolbar" aria-label="Selection actions">
  <button class="btn-icon" onclick={() => emit('clear')} aria-label="Exit selection">
    <X size={20} />
  </button>

  <span class="selection-title">{selectedCount} selected</span>

  <div class="selection-actions">
    {#if canDetails && singleSelection}
      <button class="btn-icon" onclick={() => emit('details')} aria-label="Details" title="Details">
        <Info size={20} />
      </button>
    {/if}
    {#if canShare}
      <button class="btn-icon" onclick={() => emit('share')} aria-label="Share link" title="Share link">
        <ShareNetwork size={20} />
      </button>
    {/if}
    {#if canSendToOS}
      <button class="btn-icon" onclick={() => emit('sendToOS')} aria-label="Send to..." title="Send to...">
        <PaperPlaneTilt size={20} />
      </button>
    {/if}
    {#if canRename && singleSelection}
      <button class="btn-icon" onclick={() => emit('rename')} aria-label="Rename" title="Rename">
        <PencilSimple size={20} />
      </button>
    {/if}
    {#if canDownload}
      <button class="btn-icon" onclick={() => emit('download')} aria-label="Download" title="Download">
        <DownloadSimple size={20} />
      </button>
    {/if}
    {#if canMove}
      <button class="btn-icon" onclick={() => emit('move')} aria-label="Move" title="Move">
        <ArrowRight size={20} />
      </button>
    {/if}
    {#if canAddToCollection}
      <button class="btn-icon" onclick={() => emit('addToCollection')} aria-label="Add to collection" title="Add to collection">
        <Stack size={20} />
      </button>
    {/if}
    {#if canDelete}
      <button class="btn-icon action-danger" onclick={() => emit('delete')} aria-label="Delete" title="Delete">
        <Trash size={20} />
      </button>
    {/if}
    <button class="btn-icon" onclick={() => showSheet = true} aria-label="More actions" title="More">
      <DotsThreeVertical size={20} />
    </button>
  </div>
</div>

<!-- Mobile: top bar only (DESIGN.md §15). Actions reach via the More
     button → bottom sheet. The earlier dedicated bottom action bar
     duplicated the desktop top-bar's actions and competed with the
     bottom navigation for space — collapsed in favor of the sheet. -->
<div class="selection-top-bar top-bar top-bar-selection mobile-top" role="toolbar" aria-label="Selection mode">
  <button class="btn-icon" onclick={() => emit('clear')} aria-label="Exit selection">
    <X size={20} />
  </button>
  <span class="selection-title">{selectedCount} selected</span>
  <div class="selection-spacer"></div>
  <button class="btn-icon" onclick={() => showSheet = true} aria-label="More actions" title="More">
    <DotsThreeVertical size={20} />
  </button>
</div>

<!-- Bottom sheet overlay for more actions -->
{#if showSheet}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="sheet-overlay" onclick={() => showSheet = false} role="presentation" transition:fade={{ duration: 150 }}>
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="sheet"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      tabindex="-1"
      transition:fly={{ y: 200, duration: 300 }}
    >
      <div class="sheet-handle"></div>
      <h3 class="sheet-title">{selectedCount} {selectedCount === 1 ? 'item' : 'items'} selected</h3>

      <div class="sheet-action-list">
        {#if canDetails && singleSelection}
          <button class="sheet-option" onclick={() => emit('details')}>
            <span class="sheet-option-icon"><Info size={20} /></span>
            <span>Details</span>
          </button>
        {/if}
        {#if canShare}
          <button class="sheet-option" onclick={() => emit('share')}>
            <span class="sheet-option-icon"><ShareNetwork size={20} /></span>
            <span>Share link</span>
          </button>
        {/if}
        {#if canSendToOS}
          <button class="sheet-option" onclick={() => emit('sendToOS')}>
            <span class="sheet-option-icon"><PaperPlaneTilt size={20} /></span>
            <span>Send to...</span>
          </button>
        {/if}
        {#if canRename && singleSelection}
          <button class="sheet-option" onclick={() => emit('rename')}>
            <span class="sheet-option-icon"><PencilSimple size={20} /></span>
            <span>Rename</span>
          </button>
        {/if}
        {#if canMove}
          <button class="sheet-option" onclick={() => emit('move')}>
            <span class="sheet-option-icon"><ArrowRight size={20} /></span>
            <span>Move</span>
          </button>
        {/if}
        {#if canMoveToProvider}
          <button class="sheet-option" onclick={() => emit('moveToProvider')}>
            <span class="sheet-option-icon"><ArrowsLeftRight size={20} /></span>
            <span>Move to another provider</span>
          </button>
        {/if}
        {#if canCopy}
          <button class="sheet-option" onclick={() => emit('copy')}>
            <span class="sheet-option-icon"><Copy size={20} /></span>
            <span>Copy</span>
          </button>
        {/if}
        {#if canFavorite}
          <button class="sheet-option" onclick={handleFavorite}>
            <span class="sheet-option-icon star">
              <span class="star-wrap" class:bursting={favBurstActive}>
                <Star size={20} weight={favoriteState === 'all' ? 'fill' : 'regular'} />
                {#if favBurstActive}
                  {#each [0, 60, 120, 180, 240, 300] as angle}
                    <span class="burst-dot" style="--angle: {angle}deg"></span>
                  {/each}
                {/if}
              </span>
            </span>
            <span>{favoriteLabel}</span>
          </button>
        {/if}
        {#if canDownload}
          <button class="sheet-option" onclick={() => emit('download')}>
            <span class="sheet-option-icon"><DownloadSimple size={20} /></span>
            <span>Download</span>
          </button>
        {/if}
        {#if canDelete}
          <button class="sheet-option danger" onclick={() => emit('delete')}>
            <span class="sheet-option-icon"><Trash size={20} /></span>
            <span>Delete</span>
          </button>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  /* ── Selection top bar (DESIGN.md 15) ────────────────────── */
  .selection-top-bar {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: var(--z-topbar);
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
  }

  .selection-title {
    font-size: var(--t-body-size);
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
  }

  .selection-spacer {
    flex: 1;
  }

  .selection-actions {
    display: flex;
    align-items: center;
    gap: var(--sp-xs);
    margin-left: auto;
  }

  .action-danger {
    color: var(--danger) !important;
  }

  /* ── Desktop: full top bar with inline actions ─────────── */
  .desktop-bar {
    display: flex;
  }

  @media (min-width: 600px) {
    .desktop-bar {
      left: var(--drawer-current-width, var(--drawer-width));
    }
  }

  .mobile-top {
    display: none;
  }

  /* ── Mobile: top bar only (actions via More → sheet) ───── */
  @media (max-width: 599px) {
    .desktop-bar {
      display: none;
    }

    .mobile-top {
      display: flex;
    }
  }

  /* ── Bottom sheet ────────────────────────────────────────── */
  .sheet-action-list {
    display: flex;
    flex-direction: column;
    margin-top: var(--sp-sm);
  }

  .sheet-option-icon.star {
    background-color: var(--accent-warm-muted);
    color: var(--accent-warm);
  }

  /* ── Favorite star burst (§29.3.3) ──────────────────────── */
  .star-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .star-wrap.bursting :global(svg) {
    animation: starPop 300ms ease-out;
    color: var(--accent-warm, #E0A320);
  }
  .burst-dot {
    position: absolute;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    background: var(--accent-warm, #E0A320);
    animation: dotFly 350ms ease-out forwards;
  }
  @keyframes starPop {
    0%   { transform: scale(1); }
    40%  { transform: scale(1.3); }
    100% { transform: scale(1); }
  }
  @keyframes dotFly {
    0%   { transform: rotate(var(--angle)) translateY(0); opacity: 1; }
    100% { transform: rotate(var(--angle)) translateY(-14px); opacity: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    .star-wrap.bursting :global(svg) { animation: none; }
    .burst-dot { animation: none; opacity: 0; }
  }
</style>
