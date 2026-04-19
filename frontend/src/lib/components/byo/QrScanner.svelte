<script lang="ts">
  import { onMount, onDestroy, createEventDispatcher } from 'svelte';
  import jsQR from 'jsqr';

  const dispatch = createEventDispatcher<{ scanned: string; error: string }>();

  let video: HTMLVideoElement;
  let canvas: HTMLCanvasElement;
  let ctx: CanvasRenderingContext2D | null = null;
  let stream: MediaStream | null = null;
  let animFrame: number | null = null;
  let permissionDenied = false;
  let starting = true;
  let showRetryBanner = false;
  let showManualEntry = false;
  let manualCode = '';
  let manualError = '';
  let retryTimer: ReturnType<typeof setTimeout> | null = null;

  // Torch support
  let torchSupported = false;
  let torchOn = false;
  let videoTrack: MediaStreamTrack | null = null;

  onMount(async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      video.srcObject = stream;
      await video.play();
      ctx = canvas.getContext('2d');
      starting = false;

      // Check torch support
      videoTrack = stream.getVideoTracks()[0] ?? null;
      if (videoTrack) {
        const caps = videoTrack.getCapabilities() as any;
        torchSupported = !!(caps && caps.torch);
      }

      // Show retry banner after 10s of no decode
      retryTimer = setTimeout(() => { showRetryBanner = true; }, 10000);

      scanLoop();
    } catch (e: any) {
      starting = false;
      if (e.name === 'NotAllowedError' || e.name === 'PermissionDeniedError') {
        permissionDenied = true;
      } else {
        dispatch('error', e.message || 'Camera error');
      }
    }
  });

  onDestroy(stopAll);

  function stopAll() {
    if (retryTimer) clearTimeout(retryTimer);
    if (animFrame !== null) cancelAnimationFrame(animFrame);
    if (stream) stream.getTracks().forEach((t) => t.stop());
  }

  function scanLoop() {
    if (!ctx || !video || video.readyState !== video.HAVE_ENOUGH_DATA) {
      animFrame = requestAnimationFrame(scanLoop);
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert',
    });

    if (code) {
      stopAll();
      dispatch('scanned', code.data);
      return;
    }

    animFrame = requestAnimationFrame(scanLoop);
  }

  async function toggleTorch() {
    if (!videoTrack || !torchSupported) return;
    torchOn = !torchOn;
    try {
      await (videoTrack as any).applyConstraints({ advanced: [{ torch: torchOn }] });
    } catch {
      torchOn = !torchOn;
    }
  }

  function submitManual() {
    const trimmed = manualCode.trim();
    if (!trimmed) { manualError = 'Enter a code or URL to continue.'; return; }
    stopAll();
    dispatch('scanned', trimmed);
  }
</script>

<div class="scanner-wrap">
  <!-- Hidden video + canvas used for processing -->
  <!-- svelte-ignore a11y-media-has-caption -->
  <video bind:this={video} class="scanner-video" playsinline muted></video>
  <canvas bind:this={canvas} class="scanner-canvas" aria-hidden="true"></canvas>

  {#if starting}
    <div class="overlay">
      <p class="status-text">Starting camera…</p>
    </div>
  {:else if permissionDenied}
    <div class="overlay denied">
      <p class="status-text">Camera access denied.</p>
      <p class="status-sub">Enable camera permissions in your browser settings, then reload.</p>
      <button class="manual-link" on:click={() => showManualEntry = true}>Enter code manually</button>
    </div>
  {:else}
    <!-- Viewfinder overlay -->
    <div class="viewfinder" aria-hidden="true">
      <div class="corner tl"></div>
      <div class="corner tr"></div>
      <div class="corner bl"></div>
      <div class="corner br"></div>
    </div>
    <p class="hint">Point your camera at the QR code</p>

    <!-- Torch button -->
    {#if torchSupported}
      <button
        class="torch-btn"
        class:torch-on={torchOn}
        on:click={toggleTorch}
        aria-label={torchOn ? 'Turn torch off' : 'Turn torch on'}
        title={torchOn ? 'Torch: on' : 'Torch: off'}
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M8 2v4M16 2v4M9 22h6M12 6l-2 8h4l-2 8"/>
        </svg>
      </button>
    {/if}

    <!-- Retry banner (shown after 10s) -->
    {#if showRetryBanner}
      <div class="retry-banner">
        <span>Having trouble scanning?</span>
        <button class="manual-link" on:click={() => showManualEntry = true}>Enter code manually</button>
      </div>
    {/if}
  {/if}
</div>

<!-- Manual entry panel (outside the scanner box) -->
{#if showManualEntry}
  <div class="manual-entry">
    <label class="manual-label" for="qr-manual-input">Paste or type the enrollment code</label>
    <input
      id="qr-manual-input"
      class="manual-input"
      class:error={!!manualError}
      type="text"
      autocomplete="off"
      spellcheck={false}
      placeholder="Paste code or URL here"
      bind:value={manualCode}
      on:keydown={(e) => e.key === 'Enter' && submitManual()}
    />
    {#if manualError}
      <p class="manual-error" role="alert">{manualError}</p>
    {/if}
    <button class="btn btn-primary manual-submit" on:click={submitManual}>Continue</button>
  </div>
{/if}

<style>
  .scanner-wrap {
    position: relative;
    width: 100%;
    max-width: 360px;
    margin: 0 auto;
    border-radius: var(--r-card, 16px);
    overflow: hidden;
    background: #000;
    aspect-ratio: 1;
  }

  .scanner-video {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }

  .scanner-canvas { display: none; }

  .overlay {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.7);
    gap: var(--sp-sm, 8px);
    padding: var(--sp-lg, 24px);
    text-align: center;
  }

  .overlay.denied { background: rgba(61, 31, 31, 0.95); }

  .status-text {
    margin: 0;
    color: #EDEDED;
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
  }

  .status-sub {
    margin: 0;
    color: #999999;
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .viewfinder {
    position: absolute;
    inset: 20%;
    pointer-events: none;
  }

  .corner {
    position: absolute;
    width: 24px;
    height: 24px;
    border-color: var(--accent, #2EB860);
    border-style: solid;
  }

  .corner.tl { top: 0; left: 0; border-width: 3px 0 0 3px; border-radius: 4px 0 0 0; }
  .corner.tr { top: 0; right: 0; border-width: 3px 3px 0 0; border-radius: 0 4px 0 0; }
  .corner.bl { bottom: 0; left: 0; border-width: 0 0 3px 3px; border-radius: 0 0 0 4px; }
  .corner.br { bottom: 0; right: 0; border-width: 0 3px 3px 0; border-radius: 0 0 4px 0; }

  .hint {
    position: absolute;
    bottom: 56px;
    left: 0;
    right: 0;
    text-align: center;
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: rgba(255, 255, 255, 0.7);
    pointer-events: none;
  }

  .torch-btn {
    position: absolute;
    bottom: 12px;
    right: 12px;
    width: 44px;
    height: 44px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: rgba(0, 0, 0, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.25);
    color: rgba(255, 255, 255, 0.7);
    cursor: pointer;
    transition: background 150ms, color 150ms;
  }

  .torch-btn.torch-on {
    background: var(--accent-muted, rgba(46, 184, 96, 0.3));
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .retry-banner {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: rgba(0, 0, 0, 0.75);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: rgba(255, 255, 255, 0.7);
    flex-wrap: wrap;
  }

  .manual-link {
    background: none;
    border: none;
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
    padding: 0;
  }

  .manual-entry {
    margin-top: var(--sp-md, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .manual-label {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
  }

  .manual-input {
    width: 100%;
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .manual-input.error { border-color: var(--danger, #D64545); }

  .manual-error {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--danger, #D64545);
  }

  .manual-submit { width: 100%; }
</style>
