<script lang="ts">
  import { slide } from 'svelte/transition';
  import List from 'phosphor-svelte/lib/List';
  import ArrowLineLeft from 'phosphor-svelte/lib/ArrowLineLeft';
  import ArrowLineRight from 'phosphor-svelte/lib/ArrowLineRight';
  import MagnifyingGlass from 'phosphor-svelte/lib/MagnifyingGlass';
  import X from 'phosphor-svelte/lib/X';
  import Icon from './Icons.svelte';
  import { drawerCollapsed, drawerOpen } from '../stores/drawer';
  import { vaultStore, isVaultDirty } from '../byo/stores/vaultStore';
  import CloudCheck from 'phosphor-svelte/lib/CloudCheck';
  import CloudArrowUp from 'phosphor-svelte/lib/CloudArrowUp';
  import Warning from 'phosphor-svelte/lib/Warning';

  
  interface Props {
    showSearch?: boolean;
    showSearchPanel?: boolean;
    headerVisible?: boolean;
    searchQuery?: string;
    searchFileType?: string;
    currentView?: string;
    /** Hides the right-side search button (used on screens where search
      doesn't apply, e.g. Settings). */
    hideSearch?: boolean;
  onToggleSearch?: (...args: any[]) => void;
  onCloseSearch?: (...args: any[]) => void;
  onSearchChange?: (...args: any[]) => void;
  onNavigate?: (...args: any[]) => void;
  }

  let {
    showSearch = false,
    showSearchPanel = true,
    headerVisible = true,
    searchQuery = $bindable(''),
    searchFileType = $bindable(''),
    currentView = 'files',
    hideSearch = false,
    onToggleSearch,
    onCloseSearch,
    onSearchChange,
    onNavigate
  }: Props = $props();
const fileTypes = [
    { value: '', label: 'All Types', icon: 'files' },
    { value: 'folders', label: 'Folders', icon: 'folder' },
    { value: 'images', label: 'Images', icon: 'image' },
    { value: 'documents', label: 'Documents', icon: 'document' },
    { value: 'videos', label: 'Videos', icon: 'video' },
    { value: 'audio', label: 'Audio', icon: 'music' },
    { value: 'archives', label: 'Archives', icon: 'archive' },
    { value: 'code', label: 'Code', icon: 'code' },
  ];

  function handleSearchToggle() {
    onToggleSearch?.();
  }

  function handleSearchClose() {
    searchQuery = '';
    searchFileType = '';
    onCloseSearch?.();
    onSearchChange?.({ query: '', fileType: '' });
  }

  function handleSearchInput(event: Event) {
    const value = (event.target as HTMLInputElement).value;
    searchQuery = value;
    // Redirect to Files screen when searching from other screens
    if (value && currentView !== 'files') {
      onNavigate?.({ view: 'files' });
    }
    onSearchChange?.({ query: value, fileType: searchFileType });
  }

  function clearSearch() {
    searchQuery = '';
    onSearchChange?.({ query: '', fileType: searchFileType });
  }

  function handleOpenDrawer() {
    $drawerOpen = true;
  }

  function handleToggleDrawer() {
    $drawerCollapsed = !$drawerCollapsed;
  }
</script>

<header class="header-wrapper" class:hidden={!headerVisible}>
  <!-- ===== DESKTOP: Top Nav Bar (>= 600px) ===== -->
  <div class="top-nav">
    <!-- Wide desktop (≥1024px): collapse/expand toggle. The drawer
         auto-rails at ≤1023px so this control is only meaningful
         above that breakpoint — below it the chevron flipped but the
         drawer stayed put, which read as a broken control.
         Narrow desktop (600-1023px): hamburger that opens the drawer
         as a mobile-style overlay, mirroring the mobile-top-bar's
         "Open menu" button verbatim so the rail-band UX matches the
         mobile UX exactly. -->
    <button class="btn-icon drawer-toggle-btn" onclick={handleToggleDrawer} aria-label="Toggle sidebar">
      {#if $drawerCollapsed}<ArrowLineRight size={20} weight="regular" />{:else}<ArrowLineLeft size={20} weight="regular" />{/if}
    </button>
    <button class="btn-icon drawer-rail-open-btn" onclick={handleOpenDrawer} aria-label="Open menu">
      <List size={24} weight="regular" />
    </button>
    <div class="top-nav-spacer"></div>
    {#if $vaultStore.status === 'saving'}
      <span class="vault-status saving" title="Saving vault">
        <CloudArrowUp size={16} weight="regular" />
        <span class="vault-status-label">Saving…</span>
      </span>
    {:else if $isVaultDirty}
      <span class="vault-status dirty" title="Unsaved changes">
        <Warning size={16} weight="regular" />
        <span class="vault-status-label">Unsaved</span>
      </span>
    {:else if $vaultStore.lastSavedAt}
      <span class="vault-status saved" title="Vault saved">
        <CloudCheck size={16} weight="regular" />
        <span class="vault-status-label">Saved</span>
      </span>
    {/if}
    {#if !hideSearch}
      <button class="btn-icon" onclick={handleSearchToggle} aria-label="Search">
        {#if showSearch}<X size={20} weight="regular" />{:else}<MagnifyingGlass size={20} weight="regular" />{/if}
      </button>
    {/if}
  </div>

  <!-- ===== MOBILE: Top Bar (< 600px) ===== -->
  <div class="top-bar mobile-top-bar">
    <button class="btn-icon" onclick={handleOpenDrawer} aria-label="Open menu">
      <List size={24} weight="regular" />
    </button>
    <div class="top-nav-spacer"></div>
    {#if $vaultStore.status === 'saving'}
      <span class="vault-status-dot saving" title="Saving vault" aria-label="Saving"><CloudArrowUp size={18} weight="regular" /></span>
    {:else if $isVaultDirty}
      <span class="vault-status-dot dirty" title="Unsaved changes" aria-label="Unsaved changes"><Warning size={18} weight="regular" /></span>
    {:else if $vaultStore.lastSavedAt}
      <span class="vault-status-dot saved" title="Vault saved" aria-label="Saved"><CloudCheck size={18} weight="regular" /></span>
    {/if}
    {#if !hideSearch}
      <button class="btn-icon" onclick={handleSearchToggle} aria-label="Search">
        {#if showSearch}<X size={20} weight="regular" />{:else}<MagnifyingGlass size={20} weight="regular" />{/if}
      </button>
    {/if}
  </div>

</header>

<!-- Search overlay (outside fixed header, positioned below it) -->
{#if showSearch && showSearchPanel}
  <div class="search-overlay" onclick={(e) => { if (e.target === e.currentTarget) handleSearchClose(); }} onkeydown={() => {}} role="presentation">
    <div class="search-dropdown" transition:slide={{ duration: 250 }}>
      <div class="search-container">
        <div class="search-input-wrapper">
          <div class="search-icon-left">
            <MagnifyingGlass size={18} color="var(--text-disabled)" />
          </div>
          <input
            type="text"
            placeholder="Search all files and folders..."
            class="search-input"
            value={searchQuery}
            oninput={handleSearchInput}
          />
          {#if searchQuery}
            <button class="search-clear" onclick={clearSearch} aria-label="Clear search" title="Clear search">
              <X size={16} />
            </button>
          {/if}
        </div>

        <div class="search-filters">
          <div class="filter-pills">
            {#each fileTypes as ft}
              <button
                class="filter-pill"
                class:active={searchFileType === ft.value}
                onclick={() => {
                  const newValue = searchFileType === ft.value ? '' : ft.value;
                  searchFileType = newValue;
                  onSearchChange?.({ query: searchQuery, fileType: newValue });
                }}
                title={ft.label}
              >
                <Icon name={ft.icon} size={14} />
                <span class="pill-label">{ft.label}</span>
              </button>
            {/each}
          </div>

        </div>

      </div>
    </div>
  </div>
{/if}

<style>
  .header-wrapper {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: var(--z-topbar);
    transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1),
                opacity 0.4s ease;
  }
  .header-wrapper.hidden {
    transform: translateY(-100%);
    opacity: 0;
  }

  /* Two-button swap at the rail breakpoint:
     - At ≤1023px the drawer auto-rails (Drawer.svelte's viewportNarrow),
       so the collapse/expand toggle is meaningless and gets hidden in
       favor of an "Open menu" hamburger that pops the drawer as a
       mobile-style overlay.
     - At ≥1024px the toggle drives a real expand/collapse and the
       hamburger is hidden.
     Both buttons stay in the same slot so the header layout is stable
     across the breakpoint. */
  @media (max-width: 1023px) {
    .drawer-toggle-btn {
      display: none;
    }
  }
  @media (min-width: 1024px) {
    .drawer-rail-open-btn {
      display: none;
    }
  }

  /* Desktop: offset header for sidebar */
  @media (min-width: 600px) {
    .header-wrapper {
      left: var(--drawer-current-width, var(--drawer-width));
      transition: left 0.2s ease;
    }
  }

  /* ===== Mobile top bar =====
     Floating style — no background fill, no border. The icons hover over
     the content; the scrollable area below tucks underneath without a
     visible seam. */
  .mobile-top-bar {
    display: flex;
    height: var(--header-height);
    align-items: center;
    padding: 0 var(--sp-md);
    gap: var(--sp-sm);
    background: transparent;
    border-bottom: none;
    pointer-events: none;
  }
  .mobile-top-bar > * {
    pointer-events: auto;
  }
  @media (min-width: 600px) {
    .mobile-top-bar { display: none; }
  }

  /* ===== Desktop top nav ===== */
  /* Override global .top-nav (component-classes.css) which sets position:fixed */
  .top-nav {
    display: none;
    position: static !important;
    left: auto !important;
    right: auto !important;
    top: auto !important;
    z-index: auto !important;
  }
  @media (min-width: 600px) {
    .top-nav {
      display: flex !important;
      height: var(--header-height);
      align-items: center;
      padding: 0 var(--sp-lg);
      gap: var(--sp-sm);
      /* Floating — no surface fill or border; icons overlay content. */
      background: transparent !important;
      border-bottom: none !important;
      pointer-events: none;
    }
    .top-nav > * {
      pointer-events: auto;
    }
  }

  .top-nav-spacer {
    flex: 1;
  }

  /* ── btn-icon background inside the floating top nav ─────────────────
     The top-nav itself is transparent and sits above scrollable content,
     so the default `.btn-icon` (transparent bg, surface-hover on hover)
     blends into anything that scrolls past. Give the nav buttons a solid
     raised surface so they read as buttons at rest, not just on hover.
     Scoped to this component so `.btn-icon` elsewhere (dialogs, cards)
     keeps its default appearance. Settings inherits from DashboardHeader
     and picks this up automatically. */
  .top-nav :global(.btn-icon),
  .mobile-top-bar :global(.btn-icon) {
    background-color: var(--bg-surface-raised);
  }
  .top-nav :global(.btn-icon:hover),
  .mobile-top-bar :global(.btn-icon:hover) {
    background-color: var(--bg-surface-hover);
  }

  /* ── Vault status indicator (desktop: labelled pill; mobile: icon dot) ── */
  .vault-status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: var(--r-pill);
    font-size: var(--t-label-size);
    font-weight: 500;
    background: var(--bg-surface-raised);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    white-space: nowrap;
  }
  .vault-status.saved   { color: var(--accent-text); }
  .vault-status.saving  { color: var(--text-disabled); }
  .vault-status.dirty   { color: var(--accent-warm); border-color: color-mix(in srgb, var(--accent-warm) 30%, var(--border)); }

  .vault-status-dot {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border-radius: 50%;
    color: var(--text-secondary);
    flex-shrink: 0;
  }
  .vault-status-dot.saved  { color: var(--accent-text); }
  .vault-status-dot.saving { color: var(--text-disabled); }
  .vault-status-dot.dirty  { color: var(--accent-warm); }

  /* ===== Search overlay ===== */
  .search-overlay {
    position: fixed;
    inset: 0;
    top: var(--header-height);
    z-index: calc(var(--z-topbar, 100) + 10);
    background: rgba(0, 0, 0, 0.3);
  }

  @media (min-width: 600px) {
    .search-overlay {
      left: var(--drawer-current-width, var(--drawer-width));
    }
  }

  .search-dropdown {
    padding: var(--sp-sm) var(--sp-md);
    background: var(--glass-bg-heavy);
    backdrop-filter: var(--glass-blur);
    -webkit-backdrop-filter: var(--glass-blur);
    border-bottom: var(--glass-border);
    box-shadow: var(--glass-shadow);
  }
  @supports not (backdrop-filter: blur(1px)) {
    .search-dropdown {
      background: var(--bg-surface-raised);
      border-bottom: 1px solid var(--border);
      box-shadow: var(--shadow-dropdown);
    }
  }

  .search-container {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm);
  }

  .search-input-wrapper {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    background-color: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    padding: 0 var(--sp-md);
    height: var(--search-height);
    transition: border-color var(--duration-normal) ease;
  }
  .search-input-wrapper:focus-within {
    border-color: var(--accent);
  }

  .search-icon-left {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }

  .search-input {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    font-size: var(--t-body-size);
    color: var(--text-primary);
    font-family: var(--font-sans);
    min-width: 0;
  }
  .search-input::placeholder {
    color: var(--text-disabled);
  }

  .search-clear {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: var(--bg-surface-raised);
    border: none;
    border-radius: var(--r-input);
    color: var(--text-secondary);
    cursor: pointer;
    flex-shrink: 0;
    transition: background-color var(--duration-fast) ease;
  }
  .search-clear:hover {
    background: var(--bg-surface-hover);
    color: var(--text-primary);
  }

  .search-filters {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    flex-wrap: wrap;
  }

  .filter-pills {
    display: flex;
    align-items: center;
    gap: var(--sp-xs);
    flex-wrap: wrap;
  }

  .filter-pill {
    display: flex;
    align-items: center;
    gap: var(--sp-xs);
    padding: var(--sp-xs) var(--sp-sm);
    background-color: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--r-pill);
    font-size: var(--t-body-sm-size);
    color: var(--text-secondary);
    cursor: pointer;
    white-space: nowrap;
    transition: all var(--duration-fast) ease;
  }
  .filter-pill:hover {
    background-color: var(--bg-surface-hover);
    color: var(--text-primary);
  }
  .filter-pill.active {
    background-color: var(--accent);
    border-color: var(--accent);
    color: var(--text-inverse);
  }
  .filter-pill.active:hover {
    background-color: var(--accent-hover);
  }

  .pill-label { display: inline; }



  @media (max-width: 599px) {
    .filter-pill .pill-label { display: none; }
    .filter-pill.active .pill-label { display: inline; }
  }
</style>
