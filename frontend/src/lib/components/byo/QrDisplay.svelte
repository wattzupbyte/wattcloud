<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';

  export let data: string;
  /** Describes what the QR encodes — used as the canvas aria-label. */
  export let ariaLabel = 'QR code';

  let canvas: HTMLCanvasElement;
  let error = '';

  async function render() {
    if (!canvas || !data) return;
    try {
      await QRCode.toCanvas(canvas, data, {
        width: 256,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF',
        },
        errorCorrectionLevel: 'M',
      });
      error = '';
    } catch (e: any) {
      error = e.message || 'Failed to render QR code';
    }
  }

  onMount(() => { render(); });
  $: if (canvas && data) render();
</script>

<div class="qr-wrap">
  {#if error}
    <p class="qr-error">{error}</p>
  {:else}
    <canvas bind:this={canvas} class="qr-canvas" aria-label={ariaLabel}></canvas>
  {/if}
</div>

<style>
  .qr-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--sp-md, 16px);
    background: var(--bg-surface-raised, #1E1E1E);
    border-radius: var(--r-card, 16px);
    border: 1px solid var(--border, #2E2E2E);
  }

  .qr-canvas {
    display: block;
    border-radius: 4px;
    background: #ffffff;
    padding: 8px;
  }

  .qr-error {
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
    margin: 0;
    padding: var(--sp-lg, 24px);
  }
</style>
