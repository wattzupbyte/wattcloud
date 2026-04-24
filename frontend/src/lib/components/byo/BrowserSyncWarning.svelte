<script lang="ts">
  export let onAcknowledged: () => void;

  let acknowledged = false;
</script>

<div class="sync-warning">
  <div class="icon-wrap" aria-hidden="true">
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
      <circle cx="14" cy="14" r="12" stroke="currentColor" stroke-width="2"/>
      <line x1="14" y1="9" x2="14" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
      <circle cx="14" cy="19" r="1.25" fill="currentColor"/>
    </svg>
  </div>

  <h3 class="title">Keep this tab open while saving</h3>

  <ul class="list">
    <li>Your vault is saved to your cloud provider (Google Drive, Dropbox, etc.).</li>
    <li>Closing this tab mid-save may leave an incomplete vault file.</li>
    <li>Wattcloud will replay any unsaved changes on next open using the mutation journal.</li>
    <li>For best results, wait for the "Saved" indicator before closing.</li>
  </ul>

  <label class="checkbox-label">
    <input
      type="checkbox"
      bind:checked={acknowledged}
      class="checkbox"
    />
    <span>I understand — don't warn me again this session</span>
  </label>

  <button
    class="btn btn-primary"
    disabled={!acknowledged}
    on:click={onAcknowledged}
  >
    Got it
  </button>
</div>

<style>
  .sync-warning {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    padding: var(--sp-lg, 24px);
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    max-width: 440px;
  }

  .icon-wrap {
    color: var(--accent, #2EB860);
    flex-shrink: 0;
  }

  .title {
    margin: 0;
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .list {
    margin: 0;
    padding: 0 0 0 var(--sp-md, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .list li {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  .checkbox-label {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-sm, 8px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    user-select: none;
  }

  /* DESIGN.md §13.4 — 20dp box with 1.5px border, rounded, filled accent
     + white check on toggle. Native checkbox on a dark surface rendered
     almost invisibly (browser default chrome on #262626), so we draw our
     own control with appearance: none. */
  .checkbox {
    appearance: none;
    -webkit-appearance: none;
    margin: 2px 0 0 0;
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    border: 1.5px solid var(--border, #3A3A3A);
    border-radius: var(--r-input, 6px);
    background: var(--bg-input, #1E1E1E);
    cursor: pointer;
    position: relative;
    transition: background 120ms, border-color 120ms;
  }
  .checkbox:hover {
    border-color: var(--text-secondary, #999999);
  }
  .checkbox:focus-visible {
    outline: 2px solid var(--accent, #2EB860);
    outline-offset: 2px;
  }
  .checkbox:checked {
    background: var(--accent, #2EB860);
    border-color: var(--accent, #2EB860);
  }
  .checkbox:checked::after {
    content: '';
    position: absolute;
    left: 5px;
    top: 1px;
    width: 6px;
    height: 11px;
    border: solid var(--bg-base, #1A1A1A);
    border-width: 0 2px 2px 0;
    transform: rotate(45deg);
  }
</style>
