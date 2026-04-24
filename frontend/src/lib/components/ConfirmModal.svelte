<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import BottomSheet from './BottomSheet.svelte';

  export let isOpen: boolean = false;
  export let title: string = 'Confirm';
  export let message: string = '';
  export let confirmText: string = 'Confirm';
  export let confirmClass: string = 'btn-danger';
  export let loading: boolean = false;

  const dispatch = createEventDispatcher();

  function handleConfirm() {
    dispatch('confirm');
  }

  function handleCancel() {
    if (!loading) {
      dispatch('cancel');
    }
  }

  /** Map legacy confirmClass values to design-system button classes */
  function resolveButtonClass(cls: string): string {
    if (cls === 'btn-danger') return 'btn btn-danger';
    if (cls === 'btn-primary') return 'btn btn-primary';
    return 'btn btn-primary';
  }
</script>

<BottomSheet open={isOpen} {title} on:close={handleCancel}>
  <div class="confirm-body">
    <slot>
      {#if message}
        <p class="confirm-message">{message}</p>
      {/if}
    </slot>
  </div>

  <div class="sheet-actions">
    <button class="btn btn-ghost" on:click={handleCancel} disabled={loading}>
      Cancel
    </button>
    <button class={resolveButtonClass(confirmClass)} on:click={handleConfirm} disabled={loading}>
      {#if loading}
        <span class="spinner"></span>
      {:else}
        {confirmText}
      {/if}
    </button>
  </div>
</BottomSheet>

<style>
  .confirm-body {
    color: var(--text-secondary);
    line-height: 1.5;
  }

  .confirm-body :global(p) {
    margin: 0 0 var(--sp-sm);
  }

  .confirm-message {
    margin: 0;
  }
</style>
