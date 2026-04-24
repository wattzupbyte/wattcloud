<script lang="ts">
  import { fly, fade } from 'svelte/transition';

  interface Props {
    open?: boolean;
    title?: string;
    subtitle?: string;
    variant?: 'default' | 'wide';
    children?: import('svelte').Snippet;
  onClose?: (...args: any[]) => void;
  }

  let {
    open = false,
    title = '',
    subtitle = '',
    variant = 'default',
    children,
    onClose
  }: Props = $props();
function dismiss() {
    onClose?.();
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

<svelte:window onkeydown={handleKeydown} />

{#if open}
  <div
    class="sheet-overlay"
    onclick={handleOverlayClick}
    role="presentation"
    transition:fade={{ duration: 200 }}
  ></div>

  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_interactions -->
  <div
    class="sheet"
    class:sheet--wide={variant === 'wide'}
    onclick={(e) => e.stopPropagation()}
    transition:fly={{ y: 300, duration: 300, easing: t => 1 - Math.pow(1 - t, 3) }}
    role="dialog"
    aria-modal="true"
    aria-label={title || 'Bottom sheet'}
    tabindex="-1"
  >
    <div class="sheet-handle"></div>

    {#if title}
      <h2 class="sheet-title">{title}</h2>
    {/if}

    {#if subtitle}
      <p class="sheet-subtitle">{subtitle}</p>
    {/if}

    <div class="sheet-content">
      {@render children?.()}
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
