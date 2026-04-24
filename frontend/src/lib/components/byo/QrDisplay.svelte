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
    <div class="qr-frame">
      <div class="qr-corner tl" aria-hidden="true"></div>
      <div class="qr-corner tr" aria-hidden="true"></div>
      <div class="qr-corner bl" aria-hidden="true"></div>
      <div class="qr-corner br" aria-hidden="true"></div>
      <canvas bind:this={canvas} class="qr-canvas" aria-label={ariaLabel}></canvas>
    </div>
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

  .qr-frame {
    position: relative;
    padding: var(--sp-md, 16px);
  }

  .qr-corner {
    position: absolute;
    width: 14px;
    height: 14px;
    border-color: var(--accent, #2EB860);
    border-style: solid;
  }
  .qr-corner.tl { top: 0;    left: 0;    border-width: 2px 0 0 2px; border-radius: 2px 0 0 0; }
  .qr-corner.tr { top: 0;    right: 0;   border-width: 2px 2px 0 0; border-radius: 0 2px 0 0; }
  .qr-corner.bl { bottom: 0; left: 0;    border-width: 0 0 2px 2px; border-radius: 0 0 0 2px; }
  .qr-corner.br { bottom: 0; right: 0;   border-width: 0 2px 2px 0; border-radius: 0 0 2px 0; }

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
