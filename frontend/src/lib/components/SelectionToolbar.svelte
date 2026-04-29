<script lang="ts">
  import { fade, fly } from 'svelte/transition';

  // Phosphor icons (v2.x imports)
  import X from 'phosphor-svelte/lib/X';
  import ShareNetwork from 'phosphor-svelte/lib/ShareNetwork';
  import PaperPlaneTilt from 'phosphor-svelte/lib/PaperPlaneTilt';
  import ArrowSquareIn from 'phosphor-svelte/lib/ArrowSquareIn';
  import ArrowsLeftRight from 'phosphor-svelte/lib/ArrowsLeftRight';
  import Trash from 'phosphor-svelte/lib/Trash';
  import DotsThreeVertical from 'phosphor-svelte/lib/DotsThreeVertical';
  import Copy from 'phosphor-svelte/lib/Copy';
  import Star from 'phosphor-svelte/lib/Star';
  import DownloadSimple from 'phosphor-svelte/lib/DownloadSimple';
  import PencilSimple from 'phosphor-svelte/lib/PencilSimple';
  import Info from 'phosphor-svelte/lib/Info';
  import Stack from 'phosphor-svelte/lib/Stack';
  // Summary-header file-type icons.
  import Folder from 'phosphor-svelte/lib/Folder';
  import File from 'phosphor-svelte/lib/File';
  import ImageIcon from 'phosphor-svelte/lib/Image';
  import FilmReel from 'phosphor-svelte/lib/FilmReel';
  import MusicNote from 'phosphor-svelte/lib/MusicNote';
  import FileText from 'phosphor-svelte/lib/FileText';
  import FileZip from 'phosphor-svelte/lib/FileZip';

  
  
  
  /** Lightweight preview row for the sheet's summary header. Up to a
   *  few selected items get rendered with their name + a category icon;
   *  anything past the preview window is collapsed into a "+N more" pill. */
  export interface SelectionSummary {
    preview: { name: string; kind: 'file' | 'folder'; fileType?: string }[];
    fileCount: number;
    folderCount: number;
    /** Sum of plaintext sizes for selected files (folders are skipped — their
     *  recursive size is not cheaply known from the toolbar's vantage point). */
    totalBytes: number;
  }

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
    /** Optional rich summary for the sheet header. When omitted, the sheet
     *  falls back to the plain "N items selected" title. */
    summary?: SelectionSummary;
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
    summary,
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

  // Map a file's `file_type` category (or fallback MIME family) to a
  // small icon for the summary preview. Kept narrow on purpose — the
  // intent is "what kind of thing is this?", not full MIME taxonomy.
  // Folder rows always render as Folder regardless of fileType.
  function summaryIcon(kind: 'file' | 'folder', fileType?: string) {
    if (kind === 'folder') return Folder;
    switch (fileType) {
      case 'image': return ImageIcon;
      case 'video': return FilmReel;
      case 'audio': return MusicNote;
      case 'document': return FileText;
      case 'archive': return FileZip;
      default: return File;
    }
  }

  function formatBytes(n: number): string {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    const v = n / Math.pow(1024, i);
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
  }

  let summaryPrimary = $derived.by(() => {
    if (!summary) return null;
    const total = summary.fileCount + summary.folderCount;
    if (total === 1) {
      return { line1: summary.preview[0]?.name ?? '1 item', line2: summary.fileCount === 1 ? formatBytes(summary.totalBytes) : 'Folder' };
    }
    const parts: string[] = [];
    if (summary.fileCount > 0) parts.push(`${summary.fileCount} ${summary.fileCount === 1 ? 'file' : 'files'}`);
    if (summary.folderCount > 0) parts.push(`${summary.folderCount} ${summary.folderCount === 1 ? 'folder' : 'folders'}`);
    const sizeSuffix = summary.totalBytes > 0 ? ` · ${formatBytes(summary.totalBytes)}` : '';
    return { line1: `${total} items selected`, line2: `${parts.join(' · ')}${sizeSuffix}` };
  });
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

<!-- Desktop: top bar (DESIGN.md 15)
     Header carries only the high-frequency actions (Share, Favorite,
     Download) plus a divider-fenced Delete and the More button.
     Send to…, Details, Rename, Move, Copy, Add to collection, and
     Transfer to another provider live in the More sheet below.
     Destructive Delete sits in its own zone past the divider so it
     doesn't share a row with neutral icons. -->
<div class="selection-top-bar top-bar top-bar-selection desktop-bar" role="toolbar" aria-label="Selection actions">
  <button class="btn-icon" onclick={() => emit('clear')} aria-label="Exit selection">
    <X size={20} />
  </button>

  <span class="selection-title">{selectedCount} selected</span>

  <div class="selection-actions">
    {#if canShare}
      <button class="btn-icon" onclick={() => emit('share')} aria-label="Share link" title="Share link">
        <ShareNetwork size={20} />
      </button>
    {/if}
    {#if canFavorite}
      <button
        class="btn-icon"
        onclick={handleFavorite}
        aria-label={favoriteLabel}
        title={favoriteLabel}
        aria-pressed={favoriteState === 'all'}
      >
        <span class="star-wrap" class:bursting={favBurstActive}>
          <Star size={20} weight={favoriteState === 'all' ? 'fill' : 'regular'} />
          {#if favBurstActive}
            {#each [0, 60, 120, 180, 240, 300] as angle}
              <span class="burst-dot" style="--angle: {angle}deg"></span>
            {/each}
          {/if}
        </span>
      </button>
    {/if}
    {#if canDownload}
      <button class="btn-icon" onclick={() => emit('download')} aria-label="Download" title="Download">
        <DownloadSimple size={20} />
      </button>
    {/if}

    {#if canDelete}
      <span class="action-divider" aria-hidden="true"></span>
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

<!-- Bottom sheet overlay for more actions
     Layout follows the iOS share-sheet idiom: a rich summary card at
     the top (icon stack + name + size), then a chip grid of action
     tiles. Each chip is a self-contained square button with the icon
     centered above its label. Replaces the prior flat row list, which
     was harder to scan when the sheet had 10+ entries. -->
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

      <!-- Selection summary card. Shows up to 4 file/folder type-icon
           tiles with the primary item's name (or count) and the total
           plaintext size. Falls back to a plain title if the parent
           didn't pass a `summary` prop. -->
      {#if summary && summaryPrimary}
        <div class="selection-summary">
          <div class="selection-summary-icons" aria-hidden="true">
            {#each summary.preview.slice(0, 4) as item, i}
              {@const Icon = summaryIcon(item.kind, item.fileType)}
              <span class="selection-summary-icon" style:z-index={4 - i}>
                <Icon size={20} weight="duotone" />
              </span>
            {/each}
            {#if summary.fileCount + summary.folderCount > summary.preview.length}
              <span class="selection-summary-overflow">+{summary.fileCount + summary.folderCount - summary.preview.length}</span>
            {/if}
          </div>
          <div class="selection-summary-text">
            <span class="selection-summary-line1">{summaryPrimary.line1}</span>
            <span class="selection-summary-line2">{summaryPrimary.line2}</span>
          </div>
        </div>
      {:else}
        <h3 class="sheet-title">{selectedCount} {selectedCount === 1 ? 'item' : 'items'} selected</h3>
      {/if}

      <!-- iOS-style chip grid. auto-fill keeps the grid responsive: at
           narrow widths it falls to 3 columns, at wider sheets it can
           spread to 5–6. -->
      <div class="chip-grid">
        {#if canDetails && singleSelection}
          <button class="chip" onclick={() => emit('details')}>
            <Info size={26} weight="regular" />
            <span class="chip-label">Details</span>
          </button>
        {/if}
        {#if canShare}
          <button class="chip" onclick={() => emit('share')}>
            <ShareNetwork size={26} weight="regular" />
            <span class="chip-label">Share link</span>
          </button>
        {/if}
        {#if canSendToOS}
          <button class="chip" onclick={() => emit('sendToOS')}>
            <PaperPlaneTilt size={26} weight="regular" />
            <span class="chip-label">Send to…</span>
          </button>
        {/if}
        {#if canRename && singleSelection}
          <button class="chip" onclick={() => emit('rename')}>
            <PencilSimple size={26} weight="regular" />
            <span class="chip-label">Rename</span>
          </button>
        {/if}
        {#if canMove}
          <button class="chip" onclick={() => emit('move')}>
            <ArrowSquareIn size={26} weight="regular" />
            <span class="chip-label">Move</span>
          </button>
        {/if}
        {#if canMoveToProvider}
          <button class="chip" onclick={() => emit('moveToProvider')}>
            <ArrowsLeftRight size={26} weight="regular" />
            <span class="chip-label">Transfer</span>
          </button>
        {/if}
        {#if canCopy}
          <button class="chip" onclick={() => emit('copy')}>
            <Copy size={26} weight="regular" />
            <span class="chip-label">Copy</span>
          </button>
        {/if}
        {#if canAddToCollection}
          <button class="chip" onclick={() => emit('addToCollection')}>
            <Stack size={26} weight="regular" />
            <span class="chip-label">Add to collection</span>
          </button>
        {/if}
        {#if canFavorite}
          <button class="chip" onclick={handleFavorite} aria-pressed={favoriteState === 'all'}>
            <span class="star-wrap" class:bursting={favBurstActive}>
              <Star size={26} weight={favoriteState === 'all' ? 'fill' : 'regular'} />
              {#if favBurstActive}
                {#each [0, 60, 120, 180, 240, 300] as angle}
                  <span class="burst-dot" style="--angle: {angle}deg"></span>
                {/each}
              {/if}
            </span>
            <span class="chip-label">{favoriteState === 'all' ? 'Unfavorite' : 'Favorite'}</span>
          </button>
        {/if}
        {#if canDownload}
          <button class="chip" onclick={() => emit('download')}>
            <DownloadSimple size={26} weight="regular" />
            <span class="chip-label">Download</span>
          </button>
        {/if}
        {#if canDelete}
          <button class="chip chip-danger" onclick={() => emit('delete')}>
            <Trash size={26} weight="regular" />
            <span class="chip-label">Delete</span>
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

  /* Vertical separator that fences Delete off from the neutral
     actions. The 1px border-color line was too quiet against the
     toolbar background; bumped to 2px and using --text-secondary
     so the boundary is legible without becoming a visual noise.
     Vertical padding gives the hit-row a breath of space around the
     line so it doesn't crowd the adjacent icons. */
  .action-divider {
    width: 2px;
    height: 24px;
    background-color: var(--text-secondary);
    opacity: 0.35;
    margin: 0 var(--sp-sm);
    border-radius: 1px;
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

  /* ── Bottom sheet — selection summary card ───────────────── */
  /* Sits above the chip grid; communicates *what* is being acted on
     before the user picks an action. The icon stack uses negative
     margins so a multi-item selection reads as a "stack of items"
     glance rather than a row. */
  .selection-summary {
    display: flex;
    align-items: center;
    gap: var(--sp-md);
    padding: var(--sp-md) 0;
    border-bottom: 1px solid var(--border, #30363d);
    margin-bottom: var(--sp-md);
  }
  .selection-summary-icons {
    position: relative;
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }
  .selection-summary-icon {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border, #30363d);
    color: var(--text-secondary);
  }
  .selection-summary-icon + .selection-summary-icon {
    margin-left: -14px;
  }
  .selection-summary-overflow {
    margin-left: 6px;
    padding: 0 8px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    border-radius: 11px;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border, #30363d);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 600;
  }
  .selection-summary-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    flex: 1;
  }
  .selection-summary-line1 {
    font-size: var(--t-body-size);
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .selection-summary-line2 {
    font-size: var(--t-body-sm-size);
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* ── Bottom sheet — iOS-style chip grid ──────────────────── */
  .chip-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(84px, 1fr));
    gap: 10px;
    padding: 4px 0 var(--sp-md);
  }
  .chip {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 14px 6px;
    min-height: 84px;
    border-radius: 14px;
    background: var(--bg-surface-raised);
    border: 1px solid var(--border, #30363d);
    color: var(--text-primary);
    cursor: pointer;
    transition: background 0.15s, transform 0.08s, border-color 0.15s;
    /* SVG glyphs default to baseline-aligned inline content; line-height: 0
       lets the icon center cleanly inside the chip. */
    line-height: 0;
  }
  .chip:hover {
    background: var(--bg-surface-hover);
    border-color: var(--text-disabled);
  }
  .chip:active {
    transform: scale(0.96);
  }
  .chip-label {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-secondary);
    text-align: center;
    line-height: 1.2;
    /* Two-line cap so long labels (e.g. "Add to collection") wrap
       gracefully instead of overflowing the chip. */
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .chip-danger {
    color: var(--danger);
  }
  .chip-danger:hover {
    background: rgba(214, 69, 69, 0.1);
    border-color: var(--danger);
  }
  .chip-danger .chip-label {
    color: var(--danger);
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
