<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { fly, fade } from 'svelte/transition';

  export let open: boolean = false;
  export let title: string = '';
  export let subtitle: string = '';
  export let variant: 'default' | 'wide' = 'default';

  const dispatch = createEventDispatcher();

  function dismiss() {
    dispatch('close');
  }

  function handleOverlayClick() {
    dismiss();
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && open) {
      dismiss();
    }
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open}
  <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-noninteractive-element-interactions -->
  <div
    class="sheet-overlay"
    on:click={handleOverlayClick}
    role="presentation"
    transition:fade={{ duration: 200 }}
  ></div>

  <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-noninteractive-element-interactions -->
  <div
    class="sheet"
    class:sheet--wide={variant === 'wide'}
    on:click|stopPropagation
    transition:fly={{ y: 300, duration: 300, easing: t => 1 - Math.pow(1 - t, 3) }}
    role="dialog"
    aria-modal="true"
    aria-label={title || 'Bottom sheet'}
  >
    <div class="sheet-handle"></div>

    {#if title}
      <h2 class="sheet-title">{title}</h2>
    {/if}

    {#if subtitle}
      <p class="sheet-subtitle">{subtitle}</p>
    {/if}

    <div class="sheet-content">
      <slot />
    </div>
  </div>
{/if}

<style>
  /* Use component-classes.css for .sheet-overlay, .sheet, .sheet-handle,
     .sheet-title, .sheet-subtitle. Only add overrides or structural pieces here. */
  .sheet-content {
    overflow-y: auto;
  }
</style>
