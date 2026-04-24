<script lang="ts">
  /**
   * InviteEntry — first-run screen shown when the relay is in
   * `restricted` mode, an owner has bootstrapped, and this device has no
   * valid `wattcloud_device` cookie. Collects a host-issued invite code,
   * posts to `POST /relay/admin/redeem`, and reloads on success.
   *
   * Copy + error mapping per SPEC.md §Access Control. Errors never
   * reveal whether a code prefix matched — the server always returns
   * `invalid_invite` for any unconsumed-bad-input case.
   */
  import ArrowRight from 'phosphor-svelte/lib/ArrowRight';
  import CloudBadge from '../CloudBadge.svelte';
  import {
    redeemInvite,
    formatInviteCode,
    isInviteCodeComplete,
    defaultDeviceLabel,
    generatePubkeyPlaceholder,
    friendlyInviteError,
    markEnrolled,
    AccessControlError,
  } from '../../byo/accessControl';

  /** When the SPA has a prior-enrollment hint but the server says we're no
   *  longer logged in, we're in the "session expired" variant: different
   *  header + explanatory copy, same form underneath. */
  export let expired: boolean = false;

  let code = '';
  let label = defaultDeviceLabel();
  let busy = false;
  let error = '';

  $: canSubmit = isInviteCodeComplete(code) && label.trim().length > 0 && !busy;

  function handleCodeInput(e: Event) {
    const target = e.target as HTMLInputElement;
    code = formatInviteCode(target.value);
  }

  async function handleSubmit() {
    if (!canSubmit) return;
    busy = true;
    error = '';
    try {
      await redeemInvite({
        code,
        label: label.trim(),
        pubkeyB64: generatePubkeyPlaceholder(),
      });
      markEnrolled();
      window.location.reload();
    } catch (e) {
      if (e instanceof AccessControlError) {
        error = friendlyInviteError(e);
      } else {
        error = e instanceof Error ? e.message : 'Something went wrong. Please try again.';
      }
      busy = false;
    }
  }
</script>

<div class="invite-screen">
  <div class="header">
    <div class="brand" aria-hidden="true">
      <CloudBadge size={56} variant="solid" color="var(--accent, #2EB860)" />
    </div>
    {#if expired}
      <h1 class="title">Your session expired</h1>
      <p class="subtitle">
        Your device has been signed out because it hadn't been used for a while
        (the session cookie ages out after 90 days of silence). Enter a fresh
        invite code from your host to continue — your vault data is untouched
        and will reappear after you re-enrol.
      </p>
    {:else}
      <h1 class="title">This Wattcloud is invite-only</h1>
      <p class="subtitle">
        Your host keeps this Wattcloud private to a small circle. To use it, you'll
        need an invite code from them.
      </p>
    {/if}
  </div>

  <form on:submit|preventDefault={handleSubmit} class="form">
    <label class="field">
      <span class="field-label">Invite code</span>
      <input
        type="text"
        value={code}
        on:input={handleCodeInput}
        class="code-input"
        maxlength="13"
        spellcheck="false"
        autocomplete="off"
        autocapitalize="characters"
        autocorrect="off"
        placeholder="ABCD-EFGH-JKM"
        disabled={busy}
      />
      <span class="field-hint">
        Single-use. Invite codes expire; ask your host for a fresh one if yours no longer works.
      </span>
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
        Shown to your host in their Access Control settings so they can recognise this device.
      </span>
    </label>

    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}

    <button type="submit" class="btn-primary" disabled={!canSubmit}>
      <span>{busy ? 'Redeeming…' : 'Continue'}</span>
      <ArrowRight size={18} weight="bold" />
    </button>
  </form>
</div>

<style>
  .invite-screen {
    display: flex;
    flex-direction: column;
    gap: var(--sp-lg, 24px);
    max-width: 480px;
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
    max-width: 380px;
    line-height: 1.5;
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
  .code-input {
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
  .code-input:focus {
    outline: none;
    border-color: var(--accent, #2EB860);
  }
  .code-input {
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'Menlo', monospace);
    font-size: 1.125rem;
    letter-spacing: 0.06em;
    text-align: center;
  }
  .code-input::placeholder {
    letter-spacing: 0.06em;
    color: var(--text-disabled, #5A5A5A);
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
</style>
