<script lang="ts">
  export let onRetry: () => void;
  export let onBack: () => void;
</script>

<div class="memory-failure">
  <div class="icon-wrap">
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M16 4L28 26H4L16 4Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
      <line x1="16" y1="14" x2="16" y2="20" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
      <circle cx="16" cy="23" r="1" fill="currentColor"/>
    </svg>
  </div>
  <h3 class="title">Not enough memory</h3>
  <p class="body">
    BYO vaults use 128 MB of RAM to derive encryption keys (Argon2id).
    This browser tab ran out of memory. Try closing other tabs or using a
    desktop browser with more available RAM.
  </p>
  <div class="actions">
    <button class="btn btn-primary" on:click={onRetry}>Try again</button>
    <button class="btn btn-secondary" on:click={onBack}>Back</button>
  </div>
</div>

<style>
  .memory-failure {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px) var(--sp-lg, 24px);
    text-align: center;
    max-width: 400px;
    margin: 0 auto;
  }

  .icon-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 64px;
    height: 64px;
    background: var(--danger-muted, #3D1F1F);
    border-radius: var(--r-card, 16px);
    color: var(--danger, #D64545);
  }

  .title {
    margin: 0;
    font-size: var(--t-title-size, 1.25rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .body {
    margin: 0;
    font-size: var(--t-body-size, 0.9375rem);
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
    min-width: 120px;
  }
</style>
