<script lang="ts">
  import { createEventDispatcher } from 'svelte';
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

  export let open: boolean = false;
  export let currentView: string = 'files';
  export let isAdmin: boolean = false;
  export let userName: string = '';
  export let storageUsedBytes: number = 0;
  export let storageQuotaBytes: number = 0;
  /** Shares hosted on the relay for this vault. `null` hides the row. */
  export let shareCount: number | null = null;
  export let shareBytes: number | null = null;
  /** Free bytes on the relay's share filesystem. `null` hides the headroom line. */
  export let relayHeadroomFreeBytes: number | null = null;

  export let onClose: (() => void) | undefined = undefined;

  const dispatch = createEventDispatcher();

  type NavId = 'files' | 'photos' | 'favorites' | 'settings';

  const navLinks: { id: NavId; label: string; icon: any }[] = [
    { id: 'files', label: 'Files', icon: FolderSimple },
    { id: 'photos', label: 'Photos', icon: Image },
    { id: 'favorites', label: 'Favorites', icon: Star },
    { id: 'settings', label: 'Settings', icon: GearSix },
  ];

  function handleNav(id: NavId) {
    dispatch('navigate', { view: id });
    close();
  }

  function handleAdmin() {
    dispatch('admin');
    close();
  }

  function handleLogout() {
    dispatch('logout');
    close();
  }

  function handleLockVault() {
    dispatch('lock-vault');
    close();
  }

  function handleSharesClick() {
    dispatch('shares-click');
    close();
  }

  function close() {
    dispatch('close');
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

  export let collapsed: boolean = false;
  export let showLogout: boolean = true;

  export function toggleCollapse() {
    collapsed = !collapsed;
  }

  $: if (typeof document !== 'undefined') {
    document.documentElement.style.setProperty(
      '--drawer-current-width',
      collapsed ? 'var(--drawer-collapsed-width)' : 'var(--drawer-width)'
    );
  }

  $: storagePercent = storageQuotaBytes > 0
    ? Math.min(100, (storageUsedBytes / storageQuotaBytes) * 100)
    : 0;
  $: storageBarColor = storagePercent >= 95 ? 'var(--danger, #D64545)'
    : storagePercent >= 80 ? 'var(--accent-warm, #E0A320)'
    : 'var(--accent, #2EB860)';
  $: userInitial = userName ? userName.charAt(0).toUpperCase() : '?';
</script>

<svelte:window on:keydown={handleKeydown} />

<!-- Desktop: always-visible sidebar -->
<aside
  class="drawer drawer-desktop"
  class:collapsed
  role="navigation"
  aria-label="App navigation"
>
  <div class="drawer-inner">
    <!-- Header: Logo + app name -->
    <div class="drawer-header">
      <CloudBadge size={28} variant="outline" />
      {#if !collapsed}<span class="drawer-app-name">Secure Cloud</span>{/if}
    </div>

    <!-- User info -->
    {#if userName}
      <div class="drawer-user">
        <div class="drawer-avatar">{userInitial}</div>
        {#if !collapsed}<span class="drawer-username">{userName}</span>{/if}
      </div>
    {/if}

    <!-- Nav links -->
    <div class="drawer-section">
      {#each navLinks as link}
        <button
          class="drawer-link"
          class:active={currentView === link.id}
          on:click={() => handleNav(link.id)}
          title={collapsed ? link.label : ''}
        >
          <svelte:component
            this={link.icon}
            size={20}
            weight={currentView === link.id ? 'fill' : 'regular'}
          />
          {#if !collapsed}{link.label}{/if}
        </button>
      {/each}
    </div>

    <!-- Admin link -->
    {#if isAdmin}
      <div class="drawer-section">
        <button class="drawer-link" on:click={handleAdmin} title={collapsed ? 'Admin Settings' : ''}>
          <Shield size={20} weight="regular" />
          {#if !collapsed}Admin Settings{/if}
        </button>
      </div>
    {/if}

    <!-- Storage consumption — always visible on desktop (even at 0 bytes)
         so a fresh vault still reserves the section. For providers
         without a hard quota (e.g. SFTP) we drop the bar and just show
         the usage figure. -->
    {#if !collapsed}
      <div class="drawer-section">
        <div class="drawer-storage">
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
        </div>
      </div>
    {/if}

    <!-- Shares (desktop) — tappable, opens Settings → Active shares. -->
    {#if !collapsed && shareCount !== null}
      <div class="drawer-section">
        <button class="drawer-shares" on:click={handleSharesClick} title="Manage active shares">
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
      <button class="drawer-link" on:click={handleLockVault} title={collapsed ? 'Lock Vault' : ''}>
        <Lock size={20} weight="regular" />
        {#if !collapsed}Lock Vault{/if}
      </button>
      {#if showLogout}
        <button class="drawer-link danger" on:click={handleLogout} title={collapsed ? 'Log out' : ''}>
          <SignOut size={20} weight="regular" />
          {#if !collapsed}Log out{/if}
        </button>
      {/if}
    </div>
  </div>
</aside>

<!-- Mobile: overlay drawer -->
{#if open}
  <div
    class="drawer-overlay-mobile"
    on:click={handleOverlayClick}
    on:keydown={handleKeydown}
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
            on:click={() => handleNav(link.id)}
          >
            <svelte:component
              this={link.icon}
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
          <button class="drawer-link" on:click={handleAdmin}>
            <Shield size={20} weight="regular" />
            Admin Settings
          </button>
        </div>
      {/if}

      <!-- Storage consumption (mobile overlay) — always rendered so the
           section is present even on a fresh vault. -->
      <div class="drawer-section">
        <div class="drawer-storage">
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
        </div>
      </div>

      <!-- Shares (mobile) -->
      {#if shareCount !== null}
        <div class="drawer-section">
          <button class="drawer-shares" on:click={handleSharesClick} title="Manage active shares">
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
        <button class="drawer-link" on:click={handleLockVault}>
          <Lock size={20} weight="regular" />
          Lock Vault
        </button>
        {#if showLogout}
          <button class="drawer-link danger" on:click={handleLogout}>
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

  .drawer-storage {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs);
    padding: var(--sp-sm) var(--sp-sm);
    border-radius: var(--r-input);
    justify-content: center;
  }

  .drawer-storage-title {
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

  .drawer-shares {
    display: flex;
    align-items: flex-start;
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

  .drawer-shares:hover {
    background: var(--hover-bg, rgba(255, 255, 255, 0.04));
  }

  .drawer-shares-icon {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent, #2EB860);
    margin-top: 2px;
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
