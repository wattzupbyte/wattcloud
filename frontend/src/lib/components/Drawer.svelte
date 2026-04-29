<script lang="ts">
  import { fly, fade } from 'svelte/transition';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import Image from 'phosphor-svelte/lib/Image';
  import Star from 'phosphor-svelte/lib/Star';
  import GearSix from 'phosphor-svelte/lib/GearSix';
  import Shield from 'phosphor-svelte/lib/Shield';
  import Lock from 'phosphor-svelte/lib/Lock';
  import SignOut from 'phosphor-svelte/lib/SignOut';
  import LinkIcon from 'phosphor-svelte/lib/Link';
  import CloudBadge from './CloudBadge.svelte';
  import HardDrives from 'phosphor-svelte/lib/HardDrives';
  import Terminal from 'phosphor-svelte/lib/Terminal';
  import Database from 'phosphor-svelte/lib/Database';
  import GoogleDriveLogo from 'phosphor-svelte/lib/GoogleDriveLogo';
  import DropboxLogo from 'phosphor-svelte/lib/DropboxLogo';
  import Cloud from 'phosphor-svelte/lib/Cloud';
  import Package from 'phosphor-svelte/lib/Package';
  import CloudCheck from 'phosphor-svelte/lib/CloudCheck';
  import type { ComponentType } from 'svelte';

  /** Minimal shape of a provider entry for the switcher — kept loose so this
   *  component doesn't reach into byo store types from the shared Drawer. */
  interface DrawerProviderMeta {
    providerId: string;
    displayName: string;
    type?: string;
    isPrimary?: boolean;
    status?: 'connected' | 'syncing' | 'offline' | 'offline_os' | 'error' | 'unauthorized' | string;
  }

  const PROVIDER_ICONS: Record<string, ComponentType> = {
    sftp: Terminal,
    webdav: HardDrives,
    s3: Database,
    gdrive: GoogleDriveLogo,
    dropbox: DropboxLogo,
    onedrive: Cloud,
    box: Package,
    pcloud: CloudCheck,
  } as unknown as Record<string, ComponentType>;

type NavId = 'files' | 'photos' | 'favorites' | 'settings';

  const navLinks: { id: NavId; label: string; icon: any }[] = [
    { id: 'files', label: 'Files', icon: FolderSimple },
    { id: 'photos', label: 'Photos', icon: Image },
    { id: 'favorites', label: 'Favorites', icon: Star },
    { id: 'settings', label: 'Settings', icon: GearSix },
  ];

  function handleNav(id: NavId) {
    onNavigate?.({ view: id });
    close();
  }

  function handleAdmin() {
    onAdmin?.();
    close();
  }

  function handleLogout() {
    onLogout?.();
    close();
  }

  function handleLockVault() {
    onLockVault?.();
    close();
  }

  function handleSharesClick() {
    onSharesClick?.();
    close();
  }

  function close() {
    onClose?.();
    if (onClose) onClose();
  }

  function handleOverlayClick() {
    close();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') close();
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = bytes / Math.pow(1024, i);
    return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
  }

  interface Props {
    open?: boolean;
    currentView?: string;
    isAdmin?: boolean;
    userName?: string;
    storageUsedBytes?: number;
    storageQuotaBytes?: number;
    /** Shares hosted on the relay for this vault. `null` hides the row. */
    shareCount?: number | null;
    shareBytes?: number | null;
    /** Free bytes on the relay's share filesystem. `null` hides the headroom line. */
    relayHeadroomFreeBytes?: number | null;
    /** All non-tombstoned providers for the open vault, manifest order.
     *  Empty / single-element list hides the switcher entirely. */
    providers?: DrawerProviderMeta[];
    /** providerId currently driving the dashboard. */
    activeProviderId?: string;
    onClose?: (() => void) | undefined;
    collapsed?: boolean;
    showLogout?: boolean;
  onNavigate?: (...args: any[]) => void;
  onAdmin?: (...args: any[]) => void;
  onLogout?: (...args: any[]) => void;
  onLockVault?: (...args: any[]) => void;
  onSharesClick?: (...args: any[]) => void;
  onSelectProvider?: (providerId: string) => void;
  }

  let {
    open = false,
    currentView = 'files',
    isAdmin = false,
    userName = '',
    storageUsedBytes = 0,
    storageQuotaBytes = 0,
    shareCount = null,
    shareBytes = null,
    relayHeadroomFreeBytes = null,
    providers = [],
    activeProviderId = '',
    onClose = undefined,
    collapsed = $bindable(false),
    showLogout = true,
    onNavigate,
    onAdmin,
    onLogout,
    onLockVault,
    onSharesClick,
    onSelectProvider
  }: Props = $props();

  export function toggleCollapse() {
    collapsed = !collapsed;
  }

  // Auto-collapse: at viewport widths below ~1024px the 280px expanded
  // drawer crowds the file list (folder/file names get truncated to
  // single letters). We force rail mode at ≤1023px regardless of the
  // user's explicit `collapsed` choice; their preference is preserved
  // and re-applied once the viewport widens past the threshold.
  // 600px and below is mobile-overlay territory and uses a separate
  // .drawer-mobile element, so this auto-rail only matters between
  // 600px and 1023px.
  let viewportNarrow = $state(false);
  $effect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(max-width: 1023px)');
    const sync = () => { viewportNarrow = mq.matches; };
    sync();
    mq.addEventListener('change', sync);
    return () => mq.removeEventListener('change', sync);
  });
  let effectiveCollapsed = $derived(collapsed || viewportNarrow);

  $effect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.style.setProperty(
        '--drawer-current-width',
        effectiveCollapsed ? 'var(--drawer-collapsed-width)' : 'var(--drawer-width)'
      );
    }
  });

  /** Map provider_id → "P" (primary) or sequential 1, 2, … (secondaries by manifest order).
   *  Stable per render so collapsed labels match the per-provider tooltip. */
  let providerLabels = $derived.by(() => {
    const out = new Map<string, string>();
    let n = 0;
    for (const p of providers) {
      if (p.isPrimary) out.set(p.providerId, 'P');
      else out.set(p.providerId, String(++n));
    }
    return out;
  });
  function providerStatusColor(s?: string): string {
    if (s === 'connected') return 'var(--accent, #2EB860)';
    if (s === 'syncing') return 'var(--accent-warm, #E0A320)';
    if (s === 'error' || s === 'unauthorized') return 'var(--danger, #D64545)';
    return 'var(--text-disabled, #757575)';
  }
  function selectProvider(id: string) {
    if (id === activeProviderId) return;
    onSelectProvider?.(id);
    close();
  }

  let storagePercent = $derived(storageQuotaBytes > 0
    ? Math.min(100, (storageUsedBytes / storageQuotaBytes) * 100)
    : 0);
  let storageBarColor = $derived(storagePercent >= 95 ? 'var(--danger, #D64545)'
    : storagePercent >= 80 ? 'var(--accent-warm, #E0A320)'
    : 'var(--accent, #2EB860)');
  let userInitial = $derived(userName ? userName.charAt(0).toUpperCase() : '?');
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- Desktop: always-visible sidebar -->
<aside
  class="drawer drawer-desktop"
  class:collapsed={effectiveCollapsed}
  role="navigation"
  aria-label="App navigation"
>
  <div class="drawer-inner">
    <!-- Header: Logo + app name -->
    <div class="drawer-header">
      <CloudBadge size={28} variant="outline" />
      {#if !effectiveCollapsed}<span class="drawer-app-name">Secure Cloud</span>{/if}
    </div>

    <!-- User info -->
    {#if userName}
      <div class="drawer-user">
        <div class="drawer-avatar">{userInitial}</div>
        {#if !effectiveCollapsed}<span class="drawer-username">{userName}</span>{/if}
      </div>
    {/if}

    <!-- Nav links -->
    <div class="drawer-section">
      {#each navLinks as link}
        <button
          class="drawer-link"
          class:active={currentView === link.id}
          onclick={() => handleNav(link.id)}
          title={effectiveCollapsed ? link.label : ''}
        >
          <link.icon
            size={20}
            weight={currentView === link.id ? 'fill' : 'regular'}
          />
          {#if !effectiveCollapsed}{link.label}{/if}
        </button>
      {/each}
    </div>

    <!-- Admin link -->
    {#if isAdmin}
      <div class="drawer-section">
        <button class="drawer-link" onclick={handleAdmin} title={effectiveCollapsed ? 'Admin Settings' : ''}>
          <Shield size={20} weight="regular" />
          {#if !effectiveCollapsed}Admin Settings{/if}
        </button>
      </div>
    {/if}

    <!-- Providers — switcher for the active vault's storage backends.
         Expanded mirrors the nav-link visual (type icon + name); collapsed
         drops to a P / 1 / 2 / … badge so the active provider is still
         identifiable at the narrow rail. Hidden when ≤1 provider. -->
    {#if providers.length > 1}
      <div class="drawer-section">
        {#if !effectiveCollapsed}
          <span class="drawer-section-title">Providers</span>
        {/if}
        {#each providers as p (p.providerId)}
          {@const TypeIcon = (p.type && PROVIDER_ICONS[p.type]) || Cloud}
          <button
            class="drawer-link"
            class:active={p.providerId === activeProviderId}
            type="button"
            title={effectiveCollapsed ? p.displayName : ''}
            aria-label="Switch to {p.displayName}"
            aria-pressed={p.providerId === activeProviderId}
            onclick={() => selectProvider(p.providerId)}
          >
            {#if effectiveCollapsed}
              <span class="provider-badge" class:active={p.providerId === activeProviderId}>
                {providerLabels.get(p.providerId) ?? '?'}
              </span>
              {#if p.status && p.status !== 'connected' && p.status !== 'syncing'}
                <span class="provider-link-dot" style:background-color={providerStatusColor(p.status)} aria-hidden="true"></span>
              {/if}
            {:else}
              <TypeIcon size={20} weight={p.providerId === activeProviderId ? 'fill' : 'regular'} />
              <span class="provider-link-name">{p.displayName}</span>
              {#if p.isPrimary}
                <span class="provider-link-badge">Primary</span>
              {/if}
              {#if p.status && p.status !== 'connected' && p.status !== 'syncing'}
                <span class="provider-link-dot" style:background-color={providerStatusColor(p.status)} title={p.status} aria-hidden="true"></span>
              {/if}
            {/if}
          </button>
        {/each}
      </div>
    {/if}

    <!-- Storage consumption — always visible on desktop (even at 0 bytes)
         so a fresh vault still reserves the section. For providers
         without a hard quota (e.g. SFTP) we drop the bar and just show
         the usage figure. Layout mirrors the shares row below: leading
         icon + title/label/bar stack so the two info rows read as a
         consistent pair. -->
    {#if !effectiveCollapsed}
      <div class="drawer-section">
        <div class="drawer-shares drawer-shares-static">
          <span class="drawer-shares-icon" aria-hidden="true"><HardDrives size={16} weight="regular" /></span>
          <span class="drawer-shares-body">
            <span class="drawer-storage-title">Storage</span>
            {#if storageQuotaBytes > 0}
              <div class="storage-bar">
                <div class="storage-bar-fill" style:width="{storagePercent}%" style:background-color={storageBarColor}></div>
              </div>
              <span class="drawer-storage-label">
                {formatBytes(storageUsedBytes)} of {formatBytes(storageQuotaBytes)} used
              </span>
            {:else}
              <span class="drawer-storage-label">{formatBytes(storageUsedBytes)} used</span>
            {/if}
          </span>
        </div>
      </div>
    {/if}

    <!-- Shares (desktop) — tappable, opens Settings → Active shares. -->
    {#if !effectiveCollapsed && shareCount !== null}
      <div class="drawer-section">
        <button class="drawer-shares" onclick={handleSharesClick} title="Manage active shares">
          <span class="drawer-shares-icon" aria-hidden="true"><LinkIcon size={16} weight="regular" /></span>
          <span class="drawer-shares-body">
            <span class="drawer-storage-title">Active shares</span>
            <span class="drawer-storage-label">
              {#if shareCount === 0}None active{:else}{shareCount} {shareCount === 1 ? 'link' : 'links'} · {formatBytes(shareBytes ?? 0)}{/if}
            </span>
            {#if relayHeadroomFreeBytes !== null}
              <span class="drawer-shares-headroom">Relay headroom: {formatBytes(relayHeadroomFreeBytes)}</span>
            {/if}
          </span>
        </button>
      </div>
    {/if}

    <!-- Bottom links -->
    <div class="drawer-section drawer-bottom-links">
      <button class="drawer-link" onclick={handleLockVault} title={effectiveCollapsed ? 'Lock Vault' : ''}>
        <Lock size={20} weight="regular" />
        {#if !effectiveCollapsed}Lock Vault{/if}
      </button>
      {#if showLogout}
        <button class="drawer-link danger" onclick={handleLogout} title={effectiveCollapsed ? 'Log out' : ''}>
          <SignOut size={20} weight="regular" />
          {#if !effectiveCollapsed}Log out{/if}
        </button>
      {/if}
    </div>
  </div>
</aside>

<!-- Mobile: overlay drawer -->
{#if open}
  <div
    class="drawer-overlay-mobile"
    onclick={handleOverlayClick}
    onkeydown={handleKeydown}
    role="button"
    tabindex="-1"
    aria-label="Close drawer"
    transition:fade={{ duration: 200 }}
  ></div>

  <aside
    class="drawer drawer-mobile"
    role="navigation"
    aria-label="App navigation drawer"
    transition:fly={{ x: -280, duration: 250, easing: x => 1 - Math.pow(1 - x, 3) }}
  >
    <div class="drawer-inner">
      <!-- Header: Logo + app name -->
      <div class="drawer-header">
        <CloudBadge size={28} variant="outline" />
        <span class="drawer-app-name">Secure Cloud</span>
      </div>

      <!-- User info -->
      {#if userName}
        <div class="drawer-user">
          <div class="drawer-avatar">{userInitial}</div>
          <span class="drawer-username">{userName}</span>
        </div>
      {/if}

      <!-- Nav links -->
      <div class="drawer-section">
        {#each navLinks as link}
          <button
            class="drawer-link"
            class:active={currentView === link.id}
            onclick={() => handleNav(link.id)}
          >
            <link.icon
              size={20}
              weight={currentView === link.id ? 'fill' : 'regular'}
            />
            {link.label}
          </button>
        {/each}
      </div>

      <!-- Admin link -->
      {#if isAdmin}
        <div class="drawer-section">
          <button class="drawer-link" onclick={handleAdmin}>
            <Shield size={20} weight="regular" />
            Admin Settings
          </button>
        </div>
      {/if}

      <!-- Providers (mobile overlay) — same layout as desktop expanded. -->
      {#if providers.length > 1}
        <div class="drawer-section">
          <span class="drawer-section-title">Providers</span>
          {#each providers as p (p.providerId)}
            {@const TypeIcon = (p.type && PROVIDER_ICONS[p.type]) || Cloud}
            <button
              class="drawer-link"
              class:active={p.providerId === activeProviderId}
              type="button"
              aria-label="Switch to {p.displayName}"
              aria-pressed={p.providerId === activeProviderId}
              onclick={() => selectProvider(p.providerId)}
            >
              <TypeIcon size={20} weight={p.providerId === activeProviderId ? 'fill' : 'regular'} />
              <span class="provider-link-name">{p.displayName}</span>
              {#if p.isPrimary}
                <span class="provider-link-badge">Primary</span>
              {/if}
              {#if p.status && p.status !== 'connected' && p.status !== 'syncing'}
                <span class="provider-link-dot" style:background-color={providerStatusColor(p.status)} title={p.status} aria-hidden="true"></span>
              {/if}
            </button>
          {/each}
        </div>
      {/if}

      <!-- Storage consumption (mobile overlay) — always rendered so the
           section is present even on a fresh vault. Same icon-leading
           layout as the shares row to keep the two info entries aligned. -->
      <div class="drawer-section">
        <div class="drawer-shares drawer-shares-static">
          <span class="drawer-shares-icon" aria-hidden="true"><HardDrives size={16} weight="regular" /></span>
          <span class="drawer-shares-body">
            <span class="drawer-storage-title">Storage</span>
            {#if storageQuotaBytes > 0}
              <div class="storage-bar">
                <div class="storage-bar-fill" style:width="{storagePercent}%" style:background-color={storageBarColor}></div>
              </div>
              <span class="drawer-storage-label">
                {formatBytes(storageUsedBytes)} of {formatBytes(storageQuotaBytes)} used
              </span>
            {:else}
              <span class="drawer-storage-label">{formatBytes(storageUsedBytes)} used</span>
            {/if}
          </span>
        </div>
      </div>

      <!-- Shares (mobile) -->
      {#if shareCount !== null}
        <div class="drawer-section">
          <button class="drawer-shares" onclick={handleSharesClick} title="Manage active shares">
            <span class="drawer-shares-icon" aria-hidden="true"><LinkIcon size={16} weight="regular" /></span>
            <span class="drawer-shares-body">
              <span class="drawer-storage-title">Active shares</span>
              <span class="drawer-storage-label">
                {#if shareCount === 0}None active{:else}{shareCount} {shareCount === 1 ? 'link' : 'links'} · {formatBytes(shareBytes ?? 0)}{/if}
              </span>
              {#if relayHeadroomFreeBytes !== null}
                <span class="drawer-shares-headroom">Relay headroom: {formatBytes(relayHeadroomFreeBytes)}</span>
              {/if}
            </span>
          </button>
        </div>
      {/if}

      <!-- Bottom links -->
      <div class="drawer-section drawer-bottom-links">
        <button class="drawer-link" onclick={handleLockVault}>
          <Lock size={20} weight="regular" />
          Lock Vault
        </button>
        {#if showLogout}
          <button class="drawer-link danger" onclick={handleLogout}>
            <SignOut size={20} weight="regular" />
            Log out
          </button>
        {/if}
      </div>
    </div>
  </aside>
{/if}

<style>
  .drawer-inner {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .drawer-header {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    height: var(--header-height);
    padding: 0 var(--sp-lg);
    flex-shrink: 0;
  }

  .drawer-app-name {
    font-size: var(--t-h2-size);
    font-weight: var(--t-h2-weight);
    color: var(--text-primary);
  }

  .drawer-user {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    padding: var(--sp-sm) var(--sp-lg);
    margin-bottom: var(--sp-lg);
  }

  .drawer-avatar {
    width: 32px;
    height: 32px;
    border-radius: var(--r-avatar, 50%);
    background-color: var(--accent-muted);
    color: var(--accent-text);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: var(--t-body-sm-size);
    font-weight: 600;
    flex-shrink: 0;
  }

  .drawer-username {
    font-size: var(--t-body-size);
    font-weight: 500;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .drawer-storage-title,
  .drawer-section-title {
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-secondary);
  }

  .drawer-storage-label {
    font-size: var(--t-body-sm-size);
    color: var(--text-primary);
  }

  /* ── Provider switcher (drawer) ───────────────────────────────────
   * Reuses the .drawer-link visual so providers feel like nav targets
   * (because they ARE — switching active provider re-routes the file
   * list). Two minor adornments on top: a small "Primary" pill on the
   * primary, and a status dot at the right edge when the provider is
   * NOT 'connected' / 'syncing'.
   * Collapsed mode swaps the type icon for a P / 1 / 2 / … badge so
   * the active provider stays identifiable on the narrow rail. */
  .provider-link-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    /* <button> defaults to text-align:center per UA stylesheet, and that
       inherits into non-flex descendants (the span here is a flex item
       but its text content is regular flow inside the span). Without this
       override the inactive provider name renders horizontally centered
       in the row while nav-link labels — which are bare text flex children,
       not wrapped in a span — render left-aligned. */
    text-align: left;
  }
  .provider-link-badge {
    flex-shrink: 0;
    font-size: var(--t-label-size, 0.75rem);
    padding: 1px 6px;
    border-radius: var(--r-pill, 9999px);
    background: var(--accent-muted, #1B3627);
    border: 1px solid var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }
  .provider-link-dot {
    flex-shrink: 0;
    width: 7px;
    height: 7px;
    border-radius: 50%;
  }
  .provider-badge {
    /* Collapsed (rail) badge — circular initial. Replaces the type
       icon when there's no room for a name. */
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--bg-surface, rgba(255,255,255,0.06));
    color: var(--text-secondary, #999);
    font-size: 0.6875rem;
    font-weight: 700;
    letter-spacing: 0.02em;
  }
  .provider-badge.active {
    background: var(--accent, #2EB860);
    color: #0F0F0F;
  }

  .drawer-shares {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    width: 100%;
    padding: var(--sp-sm) var(--sp-sm);
    border: none;
    background: transparent;
    border-radius: var(--r-input);
    cursor: pointer;
    text-align: left;
    color: inherit;
    transition: background 150ms;
  }

  /* Non-interactive variant — used by the Storage row, which shares the
     icon+body layout but doesn't navigate anywhere. Drop the pointer
     affordances and the hover so it doesn't look tappable. */
  .drawer-shares.drawer-shares-static {
    cursor: default;
  }
  .drawer-shares.drawer-shares-static:hover {
    background: transparent;
  }

  .drawer-shares:not(.drawer-shares-static):hover {
    background: var(--hover-bg, rgba(255, 255, 255, 0.04));
  }

  .drawer-shares-icon {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    /* line-height:0 keeps the SVG from inheriting the surrounding
       text line-box, which was padding the icon downward inside
       the 24px square. */
    line-height: 0;
    color: var(--accent, #2EB860);
  }

  .drawer-shares-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .drawer-shares-headroom {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
    font-variant-numeric: tabular-nums;
  }

  .drawer-bottom-links {
    margin-top: auto;
  }

  /* Desktop sidebar: always visible */
  .drawer-desktop {
    display: none;
  }

  @media (min-width: 600px) {
    .drawer-desktop {
      display: block;
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      width: var(--drawer-width);
      background-color: var(--bg-surface-raised);
      border-right: 1px solid var(--border);
      z-index: var(--z-topbar);
      overflow-y: auto;
      transition: width 0.2s ease;
    }

    .drawer-desktop.collapsed {
      width: var(--drawer-collapsed-width, 64px);
    }

    .drawer-desktop.collapsed .drawer-header {
      justify-content: center;
      padding: 0;
    }

    .drawer-desktop.collapsed .drawer-user {
      justify-content: center;
      padding: var(--sp-sm) 0;
    }

    .drawer-desktop.collapsed .drawer-section {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 0;
    }

    .drawer-desktop.collapsed .drawer-link {
      justify-content: center;
      padding: 0;
      width: 44px;
      min-width: 44px;
      max-width: 44px;
      height: 44px;
      border-radius: var(--r-input, 8px);
      overflow: hidden;
      gap: 0;
    }
  }

  /* Mobile overlay drawer */
  .drawer-overlay-mobile {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: var(--z-overlay);
  }

  .drawer-mobile {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    width: var(--drawer-width);
    max-width: 80vw;
    background: var(--glass-bg-heavy);
    backdrop-filter: var(--glass-blur);
    -webkit-backdrop-filter: var(--glass-blur);
    border-right: var(--glass-border);
    z-index: var(--z-sheet);
    overflow-y: auto;
    overflow-x: hidden;
  }
  .drawer-mobile::before {
    content: '';
    position: absolute;
    inset: 0;
    background: var(--glass-highlight);
    pointer-events: none;
    z-index: 0;
  }
  .drawer-mobile .drawer-inner {
    position: relative;
    z-index: 1;
  }
  @supports not (backdrop-filter: blur(1px)) {
    .drawer-mobile {
      background: var(--bg-surface-raised);
      border-right: 1px solid var(--border);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .drawer-mobile {
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
      background: var(--bg-surface-raised);
    }
  }

  @media (min-width: 600px) {
    .drawer-overlay-mobile,
    .drawer-mobile {
      display: none !important;
    }
  }
</style>
