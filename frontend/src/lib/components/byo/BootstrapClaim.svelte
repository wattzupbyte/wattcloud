<script lang="ts">

  /**
   * BootstrapClaim — first-run screen shown when `/relay/info` returns
   * `{mode: "restricted", bootstrapped: false}`. Consumes the 32-byte
   * bootstrap token written to the relay's state dir by the relay at
   * startup, mints the first owner device, and sets the
   * `wattcloud_device` cookie. On success we reload the page so the
   * normal ByoApp mounts with the freshly-authenticated identity.
   *
   * Shown once per installation — after a successful claim the
   * `bootstrapped` flag flips true and this screen is never offered
   * again unless the operator runs `sudo wattcloud regenerate-claim-token`.
   */
  import Key from 'phosphor-svelte/lib/Key';
  import Terminal from 'phosphor-svelte/lib/Terminal';
  import Info from 'phosphor-svelte/lib/Info';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import CloudBadge from '../CloudBadge.svelte';
  import {
    claimBootstrap,
    defaultDeviceLabel,
    friendlyClaimError,
    generatePubkeyPlaceholder,
    markEnrolled,
    AccessControlError,
  } from '../../byo/accessControl';

  interface Props {
    /** Recovery mode: the relay already has at least one owner, and this
     *  device is being added alongside via a freshly-minted bootstrap
     *  token (`wattcloud regenerate-claim-token`). Tweaks copy so the
     *  user understands they're not "the first owner". */
    bootstrapped?: boolean;
  }

  let { bootstrapped = false }: Props = $props();

  let token = $state('');
  let label = $state(defaultDeviceLabel());
  let busy = $state(false);
  let error = $state('');
  let explainOpen = $state(false);

  let canSubmit = $derived(token.trim().length >= 16 && label.trim().length > 0 && !busy);

  async function handleSubmit() {
    if (!canSubmit) return;
    busy = true;
    error = '';
    try {
      await claimBootstrap({
        token: token.trim(),
        label: label.trim(),
        pubkeyB64: generatePubkeyPlaceholder(),
      });
      markEnrolled();
      // Strip the recovery-mode `?claim` flag so the post-claim reload
      // doesn't loop back into BootstrapClaim. history.replaceState
      // updates the URL in place; reload() then re-probes /relay/info
      // and lands the user on the normal ByoApp boot flow with a fresh
      // device cookie.
      const url = new URL(window.location.href);
      if (url.searchParams.has('claim')) {
        url.searchParams.delete('claim');
        history.replaceState({}, '', url.toString());
      }
      window.location.reload();
    } catch (e) {
      if (e instanceof AccessControlError) {
        error = friendlyClaimError(e);
      } else {
        error = e instanceof Error ? e.message : 'Something went wrong. Please try again.';
      }
      busy = false;
    }
  }
</script>

<div class="claim-screen">
  <div class="header">
    <div class="brand" aria-hidden="true">
      <CloudBadge size={56} variant="solid" color="var(--accent, #2EB860)" />
    </div>
    {#if bootstrapped}
      <h1 class="title">Add this device as an owner</h1>
      <p class="subtitle">
        Use a freshly-minted bootstrap token to enroll this device alongside
        the existing owner(s). Other devices stay enrolled.
      </p>
    {:else}
      <h1 class="title">Welcome to your Wattcloud</h1>
      <p class="subtitle">
        This instance doesn't have an owner yet. Claim ownership below to finish setup.
      </p>
    {/if}
  </div>

  <section class="instructions">
    <div class="step-icon" aria-hidden="true">
      <Terminal size={22} weight="regular" />
    </div>
    <div class="step-body">
      <p class="step-title">Fetch your one-time token</p>
      <p class="step-desc">
        Run this command on the server hosting Wattcloud:
      </p>
      <pre class="code"><code>sudo wattcloud claim-token</code></pre>
      <p class="step-hint">
        Single-use, expires in 24 hours. If you're running the repo
        via <code>make dev</code> instead of a packaged install, use
        <code>make claim-token</code> from the repo root.
      </p>
    </div>
  </section>

  <form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="form">
    <label class="field">
      <span class="field-label">Bootstrap token</span>
      <textarea
        bind:value={token}
        class="token-input"
        rows="2"
        spellcheck="false"
        autocomplete="off"
        autocapitalize="off"
        {...{ autocorrect: 'off' }}
        placeholder="Paste the 64-character token from your server"
        disabled={busy}
      ></textarea>
    </label>

    <label class="field">
      <span class="field-label">Device name</span>
      <input
        type="text"
        bind:value={label}
        class="text-input"
        maxlength="64"
        placeholder="e.g. Alice's MacBook"
        disabled={busy}
      />
      <span class="field-hint">
        Shown in your Access Control settings so you can tell devices apart later.
      </span>
    </label>

    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}

    <button type="submit" class="btn-primary" disabled={!canSubmit}>
      <Key size={18} weight="bold" />
      <span>{busy ? 'Claiming ownership…' : 'Claim ownership'}</span>
    </button>
  </form>

  <!-- Educational disclosure: how the ownership gate actually works. Folded
       by default so first-time operators see a clean screen; curious users
       expand. -->
  <section class="explain">
    <button
      type="button"
      class="explain-toggle"
      onclick={() => (explainOpen = !explainOpen)}
      aria-expanded={explainOpen}
    >
      <Info size={16} weight="regular" />
      <span>How this protection works</span>
      <CaretDown size={14} weight="bold" class="caret {explainOpen ? 'caret-open' : ''}" />
    </button>
    {#if explainOpen}
      <div class="explain-body">
        <dl>
          <dt>Cookie-based session</dt>
          <dd>
            Claiming ownership sets a long-lived <code>wattcloud_device</code> cookie
            (HttpOnly, Secure, SameSite=Strict). Every relay action — SFTP
            proxy, share upload, admin — is authorised by that cookie on the
            server side, so nothing bypasses it from the browser.
          </dd>

          <dt>Brute-force protection</dt>
          <dd>
            The bootstrap token is 32 random bytes (~256 bits) and expires in
            24 hours. Claim and invite-redeem attempts are rate-limited per IP
            (5 per 5 min + 10 per hour) on top of that, and each attempt has
            to solve a small proof-of-work challenge the server bound to your
            IP, so coordinated botnets pay CPU on every try. Guessing a token
            or invite code is infeasible by many orders of magnitude.
          </dd>

          <dt>Staying logged in</dt>
          <dd>
            The cookie has a 90-day lifetime with sliding refresh: any active
            use within 7 days of expiry mints a fresh cookie, so a device that
            keeps using Wattcloud stays signed in indefinitely. No manual
            renewal.
          </dd>

          <dt>When a session expires</dt>
          <dd>
            If a device goes silent for 90+ days, its cookie ages out. Next
            visit shows a "session expired" screen — ask your host for a
            fresh invite to return. Your vault data on the storage provider
            is never touched by this.
          </dd>

          <dt>Recovery if you lose access</dt>
          <dd>
            Lost your only owner device? Run
            <code>sudo wattcloud regenerate-claim-token</code> on your server.
            It mints a fresh bootstrap token without touching existing
            members. Paste it here again, and you're back.
          </dd>
        </dl>
      </div>
    {/if}
  </section>
</div>

<style>
  .claim-screen {
    display: flex;
    flex-direction: column;
    gap: var(--sp-lg, 24px);
    max-width: 520px;
    margin: 0 auto;
    padding: var(--sp-xl, 32px) var(--sp-md, 16px);
    animation: fadeIn 260ms ease-out;
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
  }
  .brand {
    color: var(--accent, #2EB860);
    filter: drop-shadow(0 0 10px rgba(46, 184, 96, 0.25));
  }
  .title {
    margin: 0;
    font-size: var(--t-h1-size, 1.375rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
    letter-spacing: -0.01em;
  }
  .subtitle {
    margin: 0;
    font-size: var(--t-body-size, 0.875rem);
    color: var(--text-secondary, #999999);
    max-width: 420px;
    line-height: 1.5;
  }

  .instructions {
    display: flex;
    gap: var(--sp-md, 14px);
    padding: var(--sp-md, 16px);
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-card, 16px);
  }
  .step-icon {
    flex-shrink: 0;
    color: var(--accent, #2EB860);
    margin-top: 2px;
  }
  .step-body {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  .step-title {
    margin: 0;
    font-size: var(--t-body-size, 0.875rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }
  .step-desc {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
  }
  .code {
    margin: 4px 0 2px;
    padding: 10px 14px;
    background: var(--surface-3, #1F1F1F);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-input, 10px);
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'Menlo', monospace);
    font-size: 0.875rem;
    color: var(--accent-text, #5FDB8A);
    overflow-x: auto;
  }
  .code code {
    background: transparent;
    padding: 0;
  }
  .step-hint {
    margin: 0;
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-disabled, #7A7A7A);
    line-height: 1.5;
  }
  .step-hint code {
    font-family: var(--font-mono, ui-monospace, monospace);
    background: var(--surface-3, #1F1F1F);
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--text-secondary, #AFAFAF);
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .field-label {
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 600;
    color: var(--text-secondary, #B8B8B8);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .field-hint {
    font-size: var(--t-body-xs-size, 0.75rem);
    color: var(--text-disabled, #7A7A7A);
    line-height: 1.4;
  }
  .text-input,
  .token-input {
    width: 100%;
    padding: 12px 14px;
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-size, 0.875rem);
    box-sizing: border-box;
    transition: border-color 120ms ease;
  }
  .text-input:focus,
  .token-input:focus {
    outline: none;
    border-color: var(--accent, #2EB860);
  }
  .token-input {
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'Menlo', monospace);
    font-size: 0.8125rem;
    resize: vertical;
    min-height: 56px;
  }

  .error {
    margin: 0;
    padding: var(--sp-sm, 10px) var(--sp-md, 14px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
    line-height: 1.45;
  }

  .btn-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 18px;
    background: var(--accent, #2EB860);
    border: none;
    border-radius: var(--r-pill, 999px);
    color: #000;
    font-size: var(--t-body-size, 0.875rem);
    font-weight: 600;
    cursor: pointer;
    transition: background 120ms ease, opacity 120ms ease;
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--accent-strong, #34CF6A);
  }
  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* ── Educational disclosure ─────────────────────────────────────── */
  .explain {
    border-top: 1px solid var(--border-subtle, #262626);
    padding-top: var(--sp-md, 16px);
    margin-top: var(--sp-xs, 4px);
  }
  .explain-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 2px;
    background: transparent;
    border: none;
    color: var(--text-secondary, #B8B8B8);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    cursor: pointer;
    transition: color 120ms ease;
  }
  .explain-toggle:hover {
    color: var(--accent-text, #5FDB8A);
  }
  .explain-toggle :global(.caret) {
    transition: transform 160ms ease;
  }
  .explain-toggle :global(.caret-open) {
    transform: rotate(180deg);
  }

  .explain-body {
    margin-top: 10px;
    padding: var(--sp-md, 14px);
    background: var(--surface-2, #171717);
    border: 1px solid var(--border-subtle, #262626);
    border-radius: var(--r-card, 12px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    line-height: 1.5;
  }
  .explain-body dl {
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .explain-body dt {
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }
  .explain-body dd {
    margin: 4px 0 0;
    color: var(--text-secondary, #999);
  }
  .explain-body code {
    font-family: var(--font-mono, ui-monospace, monospace);
    background: var(--surface-3, #1F1F1F);
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    color: var(--accent-text, #5FDB8A);
  }
</style>
