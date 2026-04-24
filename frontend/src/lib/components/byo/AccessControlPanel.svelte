<script lang="ts">
  /**
   * AccessControlPanel — Settings surface for the restricted-enrollment
   * feature. Rendered inside `ByoSettings` in a collapsible row.
   *
   * What the user sees depends on their role:
   *
   *   - Owner: mode pill + invite list (mint/revoke/one-shot reveal modal)
   *     + enrolled device list (revoke). Matches SPEC.md §Access Control
   *     UI copy.
   *   - Member: a "you're a member" info card plus the mode pill. They
   *     don't have permission to list others so the admin sections stay
   *     hidden.
   *   - Open-mode relay: status pill says "Open" with guidance to flip
   *     the env var. Admin calls are still attempted for the owner list —
   *     everyone is implicitly an owner in Open mode (no device concept),
   *     so the endpoints return an empty list rather than 403.
   *
   * The env-driven mode flag (`WATTCLOUD_ENROLLMENT_MODE`) is intentionally
   * not togglable from the UI — keeping the operator's explicit intent
   * authoritative. This panel reflects whatever the server says.
   */
  import { onMount } from 'svelte';
  import Plus from 'phosphor-svelte/lib/Plus';
  import Copy from 'phosphor-svelte/lib/Copy';
  import ArrowClockwise from 'phosphor-svelte/lib/ArrowClockwise';
  import Trash from 'phosphor-svelte/lib/Trash';
  import SignOut from 'phosphor-svelte/lib/SignOut';
  import Icon from '../Icons.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import { byoToast } from '../../byo/stores/byoToasts';
  import {
    AccessControlError,
    createInvite,
    fetchMe,
    fetchRelayInfo,
    clearEnrolledHint,
    listDevices,
    listInvites,
    revokeDevice,
    revokeInvite,
    signOut,
    type DeviceRow,
    type InviteRow,
    type MeDevice,
    type RelayInfo,
  } from '../../byo/accessControl';

  // ── State ────────────────────────────────────────────────────────────────

  let loading = true;
  let info: RelayInfo | null = null;
  let me: MeDevice | null = null;
  /** Set when the device-list fetch returns 403 — current user is enrolled
   *  but not an owner. Admin sections stay hidden. */
  let notOwner = false;
  let invites: InviteRow[] = [];
  let devices: DeviceRow[] = [];
  let loadError = '';

  // Invite-mint modal state.
  let showMintModal = false;
  let mintLabel = '';
  let mintTtlKey: TtlKey = '24h';
  let mintBusy = false;
  let mintError = '';
  let mintedCode: { code: string; label: string; expiresAt: number } | null = null;

  // Confirm modals.
  let confirmRevokeInvite: InviteRow | null = null;
  let confirmRevokeDevice: DeviceRow | null = null;
  let confirmSignOut = false;
  let signOutBusy = false;
  /** When the sole owner tries to sign out — 409 last_owner from the server.
   *  Render an explicit recovery panel instead of a toast. */
  let soleOwnerBlock = false;

  type TtlKey = '1h' | '24h' | '7d';
  interface TtlOption {
    key: TtlKey;
    label: string;
    seconds: number;
  }
  const TTL_OPTIONS: TtlOption[] = [
    { key: '1h', label: '1 hour', seconds: 60 * 60 },
    { key: '24h', label: '24 hours', seconds: 24 * 60 * 60 },
    { key: '7d', label: '7 days', seconds: 7 * 24 * 60 * 60 },
  ];
  function ttlSeconds(key: TtlKey): number {
    const found = TTL_OPTIONS.find((o) => o.key === key);
    return found ? found.seconds : 24 * 60 * 60;
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  onMount(async () => {
    await reload();
  });

  async function reload() {
    loading = true;
    loadError = '';
    try {
      const infoRes = await fetchRelayInfo();
      info = infoRes;
      const meRes = await fetchMe();
      me = meRes.device;

      if (info.mode === 'open') {
        // Open mode: device concept is inert. Show the mode pill and
        // skip the admin sections — nothing to manage.
        invites = [];
        devices = [];
        notOwner = false;
        return;
      }

      // Restricted mode: try the owner-only lists. 403 = current user is a
      // member (not an owner); render the member view.
      try {
        const [invRes, devRes] = await Promise.all([listInvites(), listDevices()]);
        invites = invRes;
        devices = devRes;
        notOwner = false;
      } catch (e) {
        if (e instanceof AccessControlError && e.status === 403) {
          notOwner = true;
          invites = [];
          devices = [];
        } else {
          throw e;
        }
      }
    } catch (e) {
      loadError = e instanceof Error ? e.message : 'Failed to load access control';
    } finally {
      loading = false;
    }
  }

  // ── Invite mint ──────────────────────────────────────────────────────────

  function openMintModal() {
    mintLabel = '';
    mintTtlKey = '24h';
    mintError = '';
    mintedCode = null;
    showMintModal = true;
  }

  async function handleMint() {
    if (mintBusy) return;
    mintBusy = true;
    mintError = '';
    try {
      const res = await createInvite({
        label: mintLabel.trim() || 'Invite',
        ttlSecs: ttlSeconds(mintTtlKey),
      });
      mintedCode = { code: res.code, label: res.label, expiresAt: res.expires_at };
      await reload();
    } catch (e) {
      mintError =
        e instanceof AccessControlError
          ? e.message
          : e instanceof Error
            ? e.message
            : 'Failed to mint invite';
    } finally {
      mintBusy = false;
    }
  }

  async function handleCopyCode() {
    if (!mintedCode) return;
    try {
      await navigator.clipboard.writeText(mintedCode.code);
      byoToast.show('Invite code copied', { icon: 'seal' });
    } catch {
      byoToast.show('Copy failed — select the code and copy manually', { icon: 'warn' });
    }
  }

  function closeMintModal() {
    showMintModal = false;
    mintedCode = null;
  }

  // ── Revokes ──────────────────────────────────────────────────────────────

  async function doRevokeInvite(row: InviteRow) {
    try {
      await revokeInvite(row.id);
      byoToast.show(`Invite "${row.label || row.id}" revoked`, { icon: 'seal' });
      await reload();
    } catch (e) {
      byoToast.show(e instanceof Error ? e.message : 'Revoke failed', { icon: 'warn' });
    }
    confirmRevokeInvite = null;
  }

  // ── Sign-out (this device) ───────────────────────────────────────────────

  async function doSignOut() {
    if (signOutBusy) return;
    signOutBusy = true;
    try {
      await signOut();
      // Intentional sign-out = user actively leaving. Drop the "was
      // enrolled once" hint so the re-enrol flow shows the clean invite
      // entry, not the session-expired variant (that variant is for
      // passive cookie expiry, not a conscious sign-out).
      clearEnrolledHint();
      // Server has revoked this device + cleared the cookie. Full reload
      // re-probes /relay/info + /relay/admin/me → lands on InviteEntry.
      window.location.reload();
    } catch (e) {
      if (e instanceof AccessControlError && e.reason === 'last_owner') {
        soleOwnerBlock = true;
      } else {
        byoToast.show(e instanceof Error ? e.message : 'Sign out failed', { icon: 'warn' });
      }
      signOutBusy = false;
      confirmSignOut = false;
    }
  }

  async function doRevokeDevice(row: DeviceRow) {
    try {
      await revokeDevice(row.device_id);
      byoToast.show(`Device "${row.label || row.device_id}" revoked`, { icon: 'seal' });
      await reload();
    } catch (e) {
      if (e instanceof AccessControlError && e.reason === 'last_owner') {
        byoToast.show(
          "Can't revoke the last owner. Promote another device first, or recover via `wattcloud regenerate-claim-token` on the server.",
          { icon: 'warn' },
        );
      } else {
        byoToast.show(e instanceof Error ? e.message : 'Revoke failed', { icon: 'warn' });
      }
    }
    confirmRevokeDevice = null;
  }

  // ── Formatting ───────────────────────────────────────────────────────────

  function formatRelative(unixSecs: number): string {
    const now = Math.floor(Date.now() / 1000);
    const diff = unixSecs - now;
    const abs = Math.abs(diff);
    const suffix = diff >= 0 ? 'from now' : 'ago';
    if (abs < 60) return diff >= 0 ? 'in <1 min' : '<1 min ago';
    if (abs < 3600) return `${Math.floor(abs / 60)} min ${suffix}`;
    if (abs < 86400) return `${Math.floor(abs / 3600)} h ${suffix}`;
    return `${Math.floor(abs / 86400)} d ${suffix}`;
  }

  function formatHourBucket(hourBucket: number): string {
    const ts = hourBucket * 3600;
    const d = new Date(ts * 1000);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  function inviteStatus(row: InviteRow): { text: string; tone: 'active' | 'used' | 'expired' } {
    if (row.used_at) return { text: 'Used', tone: 'used' };
    if (row.expires_at < Math.floor(Date.now() / 1000))
      return { text: 'Expired', tone: 'expired' };
    return { text: `Expires ${formatRelative(row.expires_at)}`, tone: 'active' };
  }
</script>

<div class="access-panel">
  {#if loading}
    <p class="muted">Loading…</p>
  {:else if loadError}
    <p class="error" role="alert">{loadError}</p>
    <button class="link-btn" on:click={reload}>
      <ArrowClockwise size={14} />
      Retry
    </button>
  {:else if info}
    <!-- Mode status pill + explanatory line -->
    <div class="mode-card" class:mode-restricted={info.mode === 'restricted'}>
      <span class="mode-dot" aria-hidden="true"></span>
      <span class="mode-text">
        {#if info.mode === 'restricted'}
          <strong>Invite-only</strong>
          <span class="mode-sub">
            Only enrolled devices can use this relay. Set by <code>WATTCLOUD_ENROLLMENT_MODE</code>
            in your server's env file.
          </span>
        {:else}
          <strong>Open</strong>
          <span class="mode-sub">
            Anyone who reaches this URL can use the relay. Set
            <code>WATTCLOUD_ENROLLMENT_MODE=restricted</code> in your server's env file
            to lock down.
          </span>
        {/if}
      </span>
    </div>

    {#if info.mode === 'restricted' && notOwner}
      <!-- Member view — no admin controls. -->
      <div class="info-card">
        <p class="info-title">You're a member here</p>
        <p class="info-desc">
          Your host manages invites and enrolled devices. Ask them to revoke or re-issue
          access if anything's changed.
        </p>
      </div>

      <!-- Members can still sign out of their own session. -->
      <section class="section">
        <button class="signout-btn" on:click={() => (confirmSignOut = true)}>
          <SignOut size={14} weight="bold" />
          Sign out on this device
        </button>
        <p class="signout-hint">
          Clears the cookie and revokes this device. To come back, ask your host for a
          fresh invite.
        </p>
      </section>
    {:else if info.mode === 'restricted'}
      <!-- Owner view: invites + devices -->

      <section class="section">
        <div class="section-head">
          <h3 class="section-title">Invites</h3>
          <button class="ghost-btn" on:click={openMintModal}>
            <Plus size={14} weight="bold" />
            Generate invite
          </button>
        </div>

        {#if invites.length === 0}
          <p class="muted small">No invites yet. Generate one to add a new device.</p>
        {:else}
          <ul class="row-list">
            {#each invites as row (row.id)}
              {@const status = inviteStatus(row)}
              <li class="row" class:row-dim={status.tone !== 'active'}>
                <div class="row-main">
                  <span class="row-label">{row.label || 'Invite'}</span>
                  <span class="row-sub status-{status.tone}">{status.text}</span>
                </div>
                <button
                  class="icon-btn"
                  title="Revoke"
                  on:click={() => (confirmRevokeInvite = row)}
                  disabled={!!row.used_at}
                >
                  <Trash size={14} />
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </section>

      <section class="section">
        <div class="section-head">
          <h3 class="section-title">This session</h3>
        </div>
        {#if soleOwnerBlock}
          <div class="sole-owner-card">
            <p class="sole-title">You're the only owner</p>
            <p class="sole-desc">
              Signing out would lock you out of the web admin surface. If that's what you
              want — e.g. this is a shared computer and you're done with it — recover by
              running on your server:
            </p>
            <pre class="code"><code>sudo wattcloud regenerate-claim-token</code></pre>
            <p class="sole-desc">
              Then re-claim ownership from the bootstrap screen. Or invite another owner
              first so this device isn't load-bearing.
            </p>
            <button class="link-btn" on:click={() => (soleOwnerBlock = false)}>Got it</button>
          </div>
        {:else}
          <button class="signout-btn" on:click={() => (confirmSignOut = true)}>
            <SignOut size={14} weight="bold" />
            Sign out on this device
          </button>
          <p class="signout-hint">
            Clears the cookie and revokes this device. Anyone who captures the cookie
            later can't use it. To come back on this browser, redeem a fresh invite.
          </p>
        {/if}
      </section>

      <section class="section">
        <div class="section-head">
          <h3 class="section-title">Enrolled devices</h3>
        </div>

        {#if devices.length === 0}
          <p class="muted small">Just you so far.</p>
        {:else}
          <ul class="row-list">
            {#each devices as row (row.device_id)}
              <li class="row" class:row-dim={row.revoked_at !== null}>
                <div class="row-main">
                  <span class="row-label">
                    {row.label || 'Device'}
                    {#if row.is_owner}<span class="owner-badge">Owner</span>{/if}
                    {#if me?.device_id === row.device_id}<span class="self-badge">This device</span>{/if}
                  </span>
                  <span class="row-sub">
                    {#if row.revoked_at}
                      Revoked
                    {:else}
                      Last seen {formatHourBucket(row.last_seen_hour)}
                    {/if}
                  </span>
                </div>
                {#if !row.revoked_at}
                  <button
                    class="icon-btn"
                    title="Revoke"
                    on:click={() => (confirmRevokeDevice = row)}
                  >
                    <Trash size={14} />
                  </button>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}
  {/if}
</div>

<!-- Mint invite modal — split into create form and reveal-once result. -->
{#if showMintModal}
  <div class="modal-backdrop" on:click|self={closeMintModal} role="presentation">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="mint-title">
      {#if mintedCode}
        <h3 id="mint-title" class="modal-title">Invite for "{mintedCode.label}"</h3>
        <p class="modal-desc">
          Share this code with the person joining. <strong>It's shown once</strong> —
          after you close this, only the hash stays on the server.
        </p>
        <div class="code-display" aria-live="polite">{mintedCode.code}</div>
        <p class="code-hint">
          Expires {formatRelative(mintedCode.expiresAt)}. Single-use. Revokable from the list.
        </p>
        <div class="modal-actions">
          <button class="btn-secondary" on:click={handleCopyCode}>
            <Copy size={14} />
            Copy code
          </button>
          <button class="btn-primary" on:click={closeMintModal}>Done</button>
        </div>
      {:else}
        <h3 id="mint-title" class="modal-title">Generate invite</h3>
        <p class="modal-desc">Create a single-use code for a new device.</p>
        <label class="form-field">
          <span class="form-label">Label</span>
          <input
            type="text"
            bind:value={mintLabel}
            class="text-input"
            maxlength="64"
            placeholder="e.g. Bob's laptop"
            disabled={mintBusy}
          />
        </label>

        <div class="form-field">
          <span class="form-label">Expires in</span>
          <div class="ttl-row">
            {#each TTL_OPTIONS as opt (opt.key)}
              <button
                type="button"
                class="ttl-btn"
                class:ttl-btn-active={mintTtlKey === opt.key}
                on:click={() => (mintTtlKey = opt.key)}
                disabled={mintBusy}
              >{opt.label}</button>
            {/each}
          </div>
        </div>

        {#if mintError}
          <p class="error" role="alert">{mintError}</p>
        {/if}

        <div class="modal-actions">
          <button class="btn-secondary" on:click={closeMintModal} disabled={mintBusy}>Cancel</button>
          <button class="btn-primary" on:click={handleMint} disabled={mintBusy}>
            {mintBusy ? 'Generating…' : 'Generate'}
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if confirmSignOut}
  <ConfirmModal
    isOpen={true}
    title="Sign out on this device?"
    message={"This device will be signed out immediately and its cookie invalidated server-side. You can't undo this — to come back on this browser, you'll need to redeem a fresh invite."}
    confirmText={signOutBusy ? 'Signing out…' : 'Sign out'}
    confirmClass="btn-danger"
    loading={signOutBusy}
    on:confirm={doSignOut}
    on:cancel={() => (confirmSignOut = false)}
  />
{/if}

{#if confirmRevokeInvite}
  <ConfirmModal
    isOpen={true}
    title="Revoke invite?"
    message={`"${confirmRevokeInvite.label || confirmRevokeInvite.id}" won't be redeemable after this. You can always mint a new one.`}
    confirmText="Revoke"
    confirmClass="btn-danger"
    on:confirm={() => confirmRevokeInvite && doRevokeInvite(confirmRevokeInvite)}
    on:cancel={() => (confirmRevokeInvite = null)}
  />
{/if}

{#if confirmRevokeDevice}
  <ConfirmModal
    isOpen={true}
    title="Revoke this device?"
    message={`"${confirmRevokeDevice.label || confirmRevokeDevice.device_id}" will be signed out immediately and won't be able to reach the relay. You can't undo this.`}
    confirmText="Revoke"
    confirmClass="btn-danger"
    on:confirm={() => confirmRevokeDevice && doRevokeDevice(confirmRevokeDevice)}
    on:cancel={() => (confirmRevokeDevice = null)}
  />
{/if}

<style>
  .access-panel {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .muted {
    color: var(--text-secondary, #999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    margin: 0;
  }
  .muted.small {
    font-size: var(--t-body-xs-size, 0.75rem);
  }

  .error {
    margin: 0;
    padding: 10px 12px;
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 10px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .link-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 6px;
    background: transparent;
    border: none;
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    text-decoration: underline;
  }

  /* ── Mode pill ─────────────────────────────────────────────────────── */
  .mode-card {
    display: flex;
    gap: 10px;
    padding: 10px 12px;
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-card, 12px);
  }
  .mode-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-disabled, #888);
    margin-top: 6px;
    flex-shrink: 0;
  }
  .mode-restricted .mode-dot {
    background: var(--accent, #2EB860);
    box-shadow: 0 0 6px rgba(46, 184, 96, 0.6);
  }
  .mode-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
  }
  .mode-text strong {
    font-weight: 600;
  }
  .mode-sub {
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-secondary, #999);
    line-height: 1.4;
  }
  .mode-sub code {
    font-family: var(--font-mono, ui-monospace, monospace);
    background: var(--surface-3, #1F1F1F);
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.75rem;
    color: var(--text-secondary, #C2C2C2);
  }

  .info-card {
    padding: 12px;
    background: var(--accent-muted, #18311F);
    border: 1px solid var(--accent-border, #2B5A3A);
    border-radius: var(--r-card, 12px);
    color: var(--text-primary, #EDEDED);
  }
  .info-title {
    margin: 0 0 4px;
    font-size: var(--t-body-size, 0.875rem);
    font-weight: 600;
  }
  .info-desc {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #B8B8B8);
    line-height: 1.4;
  }

  /* ── Sections ──────────────────────────────────────────────────────── */
  .section {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 6px);
  }
  .section-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .section-title {
    margin: 0;
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 600;
    color: var(--text-secondary, #B8B8B8);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .ghost-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    background: transparent;
    border: 1px solid var(--border-subtle, #2F2F2F);
    border-radius: var(--r-pill, 999px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease;
  }
  .ghost-btn:hover {
    background: var(--surface-2, #171717);
    border-color: var(--accent, #2EB860);
  }

  .row-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-input, 10px);
  }
  .row-dim {
    opacity: 0.55;
  }
  .row-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .row-label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .row-sub {
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-secondary, #999);
  }
  .status-active {
    color: var(--accent-text, #5FDB8A);
  }
  .status-used,
  .status-expired {
    color: var(--text-disabled, #7A7A7A);
  }
  .owner-badge,
  .self-badge {
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 1px 6px;
    border-radius: 4px;
  }
  .owner-badge {
    background: var(--accent-muted, #18311F);
    color: var(--accent-text, #5FDB8A);
  }
  .self-badge {
    background: var(--surface-3, #1F1F1F);
    color: var(--text-secondary, #B8B8B8);
  }

  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--r-input, 8px);
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-secondary, #888);
    cursor: pointer;
    transition: background 120ms ease, color 120ms ease;
  }
  .icon-btn:hover:not(:disabled) {
    background: var(--danger-muted, #3D1F1F);
    color: var(--danger, #D64545);
  }
  .icon-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  /* ── Sign out ──────────────────────────────────────────────────────── */
  .signout-btn {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    background: transparent;
    border: 1px solid var(--border-subtle, #2F2F2F);
    border-radius: var(--r-pill, 999px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease, color 120ms ease;
  }
  .signout-btn:hover {
    background: var(--danger-muted, #3D1F1F);
    border-color: var(--danger, #D64545);
    color: var(--danger, #D64545);
  }
  .signout-hint {
    margin: 4px 0 0;
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-disabled, #7A7A7A);
    line-height: 1.4;
  }
  .sole-owner-card {
    padding: 12px;
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-card, 12px);
    color: var(--text-primary, #EDEDED);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .sole-title {
    margin: 0;
    font-size: var(--t-body-size, 0.875rem);
    font-weight: 600;
    color: var(--danger, #D64545);
  }
  .sole-desc {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #B8B8B8);
    line-height: 1.5;
  }
  .code {
    margin: 0;
    padding: 8px 10px;
    background: var(--surface-3, #1F1F1F);
    border-radius: var(--r-input, 8px);
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'Menlo', monospace);
    font-size: 0.8125rem;
    color: var(--accent-text, #5FDB8A);
    overflow-x: auto;
  }
  .code code {
    background: transparent;
    padding: 0;
  }

  /* ── Modal ─────────────────────────────────────────────────────────── */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: var(--sp-md, 16px);
    animation: fadeIn 150ms ease-out;
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  .modal {
    width: 100%;
    max-width: 420px;
    padding: var(--sp-lg, 24px);
    background: var(--surface-1, #111);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-card, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 12px);
  }
  .modal-title {
    margin: 0;
    font-size: var(--t-h2-size, 1.125rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }
  .modal-desc {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .form-label {
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 600;
    color: var(--text-secondary, #B8B8B8);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .text-input {
    padding: 10px 12px;
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-input, 10px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-size, 0.875rem);
  }
  .text-input:focus {
    outline: none;
    border-color: var(--accent, #2EB860);
  }
  .ttl-row {
    display: flex;
    gap: 6px;
  }
  .ttl-btn {
    flex: 1;
    padding: 8px;
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-input, 10px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease;
  }
  .ttl-btn:hover:not(:disabled) {
    background: var(--surface-3, #1F1F1F);
  }
  .ttl-btn-active {
    background: var(--accent-muted, #18311F);
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .code-display {
    padding: var(--sp-md, 16px);
    background: var(--surface-3, #1F1F1F);
    border: 1px dashed var(--accent, #2EB860);
    border-radius: var(--r-input, 12px);
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'Menlo', monospace);
    font-size: 1.125rem;
    letter-spacing: 0.08em;
    text-align: center;
    color: var(--accent-text, #5FDB8A);
    user-select: all;
  }
  .code-hint {
    margin: 0;
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-disabled, #7A7A7A);
    text-align: center;
  }

  .modal-actions {
    display: flex;
    gap: 8px;
    margin-top: var(--sp-xs, 4px);
  }
  .btn-primary,
  .btn-secondary {
    flex: 1;
    padding: 10px 14px;
    border-radius: var(--r-pill, 999px);
    font-size: var(--t-body-size, 0.875rem);
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    transition: background 120ms ease, opacity 120ms ease;
  }
  .btn-primary {
    background: var(--accent, #2EB860);
    border: none;
    color: #000;
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--accent-strong, #34CF6A);
  }
  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn-secondary {
    background: transparent;
    border: 1px solid var(--border-subtle, #2F2F2F);
    color: var(--text-primary, #EDEDED);
  }
  .btn-secondary:hover:not(:disabled) {
    background: var(--surface-2, #171717);
  }
</style>
