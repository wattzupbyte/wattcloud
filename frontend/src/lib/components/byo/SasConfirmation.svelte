<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let sasCode: string;

  const dispatch = createEventDispatcher<{ confirm: void; mismatch: void }>();
</script>

<div class="sas-wrap">
  <p class="label">Does this code match on both devices?</p>

  <div class="code-display" aria-label="Security code: {sasCode}" role="status">
    {sasCode}
  </div>

  <p class="sublabel">
    Both devices must show the same code before you tap <strong>Yes, they match</strong>.
    If the codes differ, tap <strong>No — abort</strong>.
  </p>

  <div class="actions">
    <button class="btn btn-secondary danger-btn" on:click={() => dispatch('mismatch')}>
      No — abort
    </button>
    <button class="btn btn-primary" on:click={() => dispatch('confirm')}>
      Yes, they match
    </button>
  </div>
</div>

<style>
  .sas-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-lg, 24px);
    text-align: center;
    width: 100%;
  }

  .label {
    margin: 0;
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .code-display {
    font-family: var(--font-mono, ui-monospace, 'SF Mono', Consolas, monospace);
    font-size: 2.5rem;
    font-weight: 700;
    letter-spacing: 0.35em;
    color: var(--accent-text, #5FDB8A);
    background: var(--bg-surface-raised, #262626);
    border: 2px solid var(--accent, #2EB860);
    border-radius: var(--r-card, 16px);
    padding: var(--sp-lg, 24px) var(--sp-xl, 32px);
    min-width: 280px;
    user-select: all;
  }

  .sublabel {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  .actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    flex-wrap: wrap;
    justify-content: center;
    width: 100%;
  }

  .actions button {
    flex: 1;
    min-width: 140px;
    min-height: 44px;
  }

  @media (max-width: 599px) {
    .actions { flex-direction: column-reverse; }
    .actions button { min-width: 0; }
  }

  .danger-btn {
    border-color: var(--danger, #D64545) !important;
    color: var(--danger, #D64545) !important;
  }

  .danger-btn:hover {
    background: var(--danger-muted, #3D1F1F) !important;
  }
</style>
