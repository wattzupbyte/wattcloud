<script lang="ts">

	import { fade } from 'svelte/transition';
	import { triggerDownload } from '../utils';
	import Icon from './Icons.svelte';
	import PaperPlaneTilt from 'phosphor-svelte/lib/PaperPlaneTilt';
	import type { FileRecord } from '../stores/files';
	import { parseExif, type PhotoExif } from '../byo/ExifExtractor';


	// BYO dual-mode: when provided, replaces downloadAndDecryptFile(file.id).
	

	let previewUrl: string | null = $state(null);
	let isLoading: boolean = $state(false);
	let error: string | null = $state(null);
	let fileType: 'image' | 'pdf' | 'other' = $state('other');


	function getFileType(filename: string): 'image' | 'pdf' | 'other' {
		const ext = filename.split('.').pop()?.toLowerCase() || '';
		const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'];
		if (imageExts.includes(ext)) return 'image';
		if (ext === 'pdf') return 'pdf';
		return 'other';
	}

	async function loadPreview() {
		if (!file) return;

		previewUrl = null;
		error = null;
		isLoading = true;

		const decryptedName = file.decrypted_name || file.name;
		fileType = getFileType(decryptedName);

		try {
			if (!loadFileData) {
				error = 'Preview not available';
				isLoading = false;
				return;
			}
			const blob = await loadFileData(file.id);
			previewUrl = URL.createObjectURL(blob);
		} catch (e: any) {
			console.error('Preview error:', e);
			error = e.message || 'Failed to load preview';
		} finally {
			isLoading = false;
		}
	}

	function close() {
		if (previewUrl) {
			URL.revokeObjectURL(previewUrl);
			previewUrl = null;
		}
		onClose();
	}

	async function download() {
		if (!file || !previewUrl) return;

		const decryptedName = file.decrypted_name || file.name;
		const blob = await fetch(previewUrl).then(r => r.blob());
		await triggerDownload(blob, decryptedName);
	}

	function handleKeydown(event: KeyboardEvent) {
		if (!isOpen) return;
		if (event.key === 'Escape') {
			close();
		} else if (event.key === 'ArrowLeft' && onPrev) {
			event.preventDefault();
			onPrev();
		} else if (event.key === 'ArrowRight' && onNext) {
			event.preventDefault();
			onNext();
		} else if (event.key === 'i' || event.key === 'I') {
			showInfo = !showInfo;
		}
	}

	// Optional prev/next navigation (Photos lightbox). When set, ArrowLeft /
	
	interface Props {
		file?: FileRecord | null;
		isOpen?: boolean;
		onClose: () => void;
		// Called with file.id; must return a Blob of the decrypted file content.
		loadFileData?: ((fileId: number) => Promise<Blob>) | null;
		// ArrowRight flip through siblings and chevron arrows appear on hover.
		onPrev?: (() => void) | null;
		onNext?: (() => void) | null;
		// Optional "Send to..." callback (OS share-sheet). Hidden when null.
		onSendToOS?: (() => void) | null;
	}

	let {
		file = null,
		isOpen = false,
		onClose,
		loadFileData = null,
		onPrev = null,
		onNext = null,
		onSendToOS = null
	}: Props = $props();

	// Metadata side-panel toggle — opened by the info button or 'I' key.
	let showInfo = $state(false);


	function formatExposure(s: number | undefined): string {
		if (s == null) return '—';
		if (s >= 1) return `${s}s`;
		return `1/${Math.round(1 / s)}s`;
	}
	function formatFocal(mm: number | undefined): string {
		return mm == null ? '—' : `${mm.toFixed(0)}mm`;
	}
	function formatFNumber(f: number | undefined): string {
		return f == null ? '—' : `f/${f.toFixed(f < 10 ? 1 : 0)}`;
	}
	function formatCoords(lat: number | undefined, lon: number | undefined): string {
		if (lat == null || lon == null) return '—';
		return `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`;
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
		return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
	}

	function formatDate(iso: string | undefined): string {
		if (!iso) return '—';
		try { return new Date(iso).toLocaleString(); } catch { return iso; }
	}

	// ── Touch swipe navigation + pinch-zoom (mobile) ────────────────────────
	// Single-finger horizontal drag ≥ SWIPE_THRESHOLD px triggers
	// onPrev/onNext. Two-finger pinch on an image zooms in/out, and a
	// single-finger drag pans when zoomed. Double-tap on an image resets
	// scale + offset. Swipe is ignored while the image is zoomed so pan
	// doesn't accidentally fire prev/next.
	const SWIPE_THRESHOLD = 60;
	const SWIPE_AXIS_RATIO = 1.5;
	const MIN_SCALE = 1;
	const MAX_SCALE = 5;
	const DOUBLE_TAP_MS = 300;
	const DOUBLE_TAP_DIST = 20;

	let swipeStartX = 0;
	let swipeStartY = 0;
	let swiping = false;

	// Image transform state
	let zoomScale = $state(1);
	let zoomTx = $state(0);
	let zoomTy = $state(0);

	// Gesture state
	let pinchStartDist = 0;
	let pinchStartScale = 1;
	let _pinchStartCenter: { x: number; y: number } = { x: 0, y: 0 };
	let panStart = { x: 0, y: 0, tx: 0, ty: 0 };
	let lastTapTime = 0;
	let lastTapX = 0;
	let lastTapY = 0;

	function touchDist(t: TouchList): number {
		const dx = t[0].clientX - t[1].clientX;
		const dy = t[0].clientY - t[1].clientY;
		return Math.hypot(dx, dy);
	}
	function touchCenter(t: TouchList): { x: number; y: number } {
		return { x: (t[0].clientX + t[1].clientX) / 2, y: (t[0].clientY + t[1].clientY) / 2 };
	}
	function clampScale(s: number): number { return Math.max(MIN_SCALE, Math.min(MAX_SCALE, s)); }
	function resetZoom() { zoomScale = 1; zoomTx = 0; zoomTy = 0; }


	function handleTouchStart(e: TouchEvent) {
		if (e.touches.length === 2 && fileType === 'image') {
			// Begin pinch.
			e.preventDefault();
			pinchStartDist = touchDist(e.touches);
			pinchStartScale = zoomScale;
			_pinchStartCenter = touchCenter(e.touches);
			swiping = false;
			return;
		}
		if (e.touches.length === 1) {
			const t = e.touches[0];
			// Double-tap on the image resets zoom.
			if (fileType === 'image') {
				const now = Date.now();
				const dt = now - lastTapTime;
				const dxT = t.clientX - lastTapX;
				const dyT = t.clientY - lastTapY;
				if (dt < DOUBLE_TAP_MS && Math.hypot(dxT, dyT) < DOUBLE_TAP_DIST) {
					resetZoom();
					lastTapTime = 0;
					return;
				}
				lastTapTime = now;
				lastTapX = t.clientX;
				lastTapY = t.clientY;
			}
			if (zoomScale > 1) {
				// Drag to pan while zoomed.
				panStart = { x: t.clientX, y: t.clientY, tx: zoomTx, ty: zoomTy };
				swiping = false;
				return;
			}
			swipeStartX = t.clientX;
			swipeStartY = t.clientY;
			swiping = true;
		}
	}
	function handleTouchMove(e: TouchEvent) {
		if (e.touches.length === 2 && fileType === 'image') {
			e.preventDefault();
			const d = touchDist(e.touches);
			if (pinchStartDist > 0) {
				zoomScale = clampScale(pinchStartScale * (d / pinchStartDist));
				if (zoomScale === 1) { zoomTx = 0; zoomTy = 0; }
			}
			return;
		}
		if (e.touches.length === 1 && zoomScale > 1) {
			// Pan; prevent the overlay from interpreting this as a swipe.
			e.preventDefault();
			const t = e.touches[0];
			zoomTx = panStart.tx + (t.clientX - panStart.x);
			zoomTy = panStart.ty + (t.clientY - panStart.y);
		}
	}
	function handleTouchEnd(e: TouchEvent) {
		// End of a pinch → exit without firing a swipe.
		if (pinchStartDist > 0 && e.touches.length < 2) {
			pinchStartDist = 0;
			return;
		}
		if (!swiping) return;
		swiping = false;
		if (zoomScale > 1) return; // panning, not swiping
		const t = e.changedTouches[0];
		if (!t) return;
		const dx = t.clientX - swipeStartX;
		const dy = t.clientY - swipeStartY;
		if (Math.abs(dx) < SWIPE_THRESHOLD) return;
		if (Math.abs(dx) < Math.abs(dy) * SWIPE_AXIS_RATIO) return;
		if (dx < 0 && onNext) onNext();
		else if (dx > 0 && onPrev) onPrev();
	}

	// Desktop: wheel-zoom on image (Ctrl+wheel to zoom, matches standard image viewers).
	function handleWheel(e: WheelEvent) {
		if (fileType !== 'image') return;
		if (!e.ctrlKey && !e.metaKey) return;
		e.preventDefault();
		const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
		zoomScale = clampScale(zoomScale * factor);
		if (zoomScale === 1) { zoomTx = 0; zoomTy = 0; }
	}
	$effect(() => {
		if (file && isOpen) {
			loadPreview();
		}
	});
	let mimeLabel = $derived((file as unknown as { mime_type?: string })?.mime_type || '—');
	// EXIF-derived camera info, parsed lazily from the `metadata` column on
	// BYO FileEntry records. Missing fields render as '—' (or the row is
	// omitted entirely when the whole group is absent).
	let exif = $derived(parseExif((file as unknown as { metadata?: string })?.metadata) as PhotoExif);
	let hasCamera = $derived(!!(exif.make || exif.model || exif.iso || exif.fNumber || exif.exposureTime || exif.focalLength));
	let hasLocation = $derived(typeof exif.lat === 'number' && typeof exif.lon === 'number');
	// Reset zoom whenever the active file changes so a previous-photo
	// zoom doesn't carry over into the next one.
	$effect(() => { void file; resetZoom(); });
</script>

<svelte:window onkeydown={handleKeydown} />

{#if isOpen && file}
	<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_interactions -->
	<div
		class="preview-overlay"
		onclick={close}
		ontouchstart={handleTouchStart}
		ontouchmove={handleTouchMove}
		ontouchend={handleTouchEnd}
		onwheel={handleWheel}
		role="presentation"
		transition:fade={{ duration: 200 }}
	>
		<!-- svelte-ignore a11y_no_noninteractive_element_interactions a11y_click_events_have_key_events -->
		<div class="preview-container" onclick={(e) => e.stopPropagation()} role="dialog" tabindex="-1">
			<!-- Top bar: close left, filename center, actions right -->
			<div class="preview-top-bar">
				<button class="preview-btn" onclick={close} title="Close" aria-label="Close preview">
					<Icon name="close" size={20} />
				</button>
				<div class="preview-filename">
					<span>{file.decrypted_name || file.name}</span>
				</div>
				<div class="preview-actions">
					<button class="preview-btn" class:active={showInfo} onclick={() => (showInfo = !showInfo)} title="Info (I)" aria-label="Toggle info panel">
						<Icon name="info" size={20} />
					</button>
					{#if onSendToOS}
						<button class="preview-btn" onclick={() => onSendToOS?.()} title="Send to..." aria-label="Send to...">
							<PaperPlaneTilt size={20} />
						</button>
					{/if}
					<button class="preview-btn" onclick={download} title="Download" aria-label="Download file">
						<Icon name="download" size={20} />
					</button>
				</div>
			</div>

			<!-- Prev/Next chevrons (only when Photos lightbox wires them) -->
			{#if onPrev}
				<button class="preview-nav-btn prev" onclick={onPrev} title="Previous (←)" aria-label="Previous">
					<Icon name="arrowLeft" size={24} />
				</button>
			{/if}
			{#if onNext}
				<button class="preview-nav-btn next" onclick={onNext} title="Next (→)" aria-label="Next">
					<Icon name="arrowRight" size={24} />
				</button>
			{/if}

			<!-- Info side panel -->
			{#if showInfo}
				<aside class="preview-info-panel" transition:fade={{ duration: 150 }}>
					<h3 class="info-heading">Info</h3>
					<dl class="info-list">
						<div class="info-row"><dt>Name</dt><dd>{file.decrypted_name || file.name}</dd></div>
						<div class="info-row"><dt>Size</dt><dd>{formatBytes(file.size ?? 0)}</dd></div>
						<div class="info-row"><dt>Type</dt><dd>{mimeLabel}</dd></div>
						<div class="info-row"><dt>Added</dt><dd>{formatDate(file.created_at)}</dd></div>
						<div class="info-row"><dt>Modified</dt><dd>{formatDate(file.updated_at)}</dd></div>
						{#if exif.takenAt}
							<div class="info-row"><dt>Taken</dt><dd>{formatDate(exif.takenAt)}</dd></div>
						{/if}
					</dl>

					{#if hasCamera}
						<h4 class="info-heading-sub">Camera</h4>
						<dl class="info-list">
							{#if exif.make || exif.model}
								<div class="info-row"><dt>Body</dt><dd>{[exif.make, exif.model].filter(Boolean).join(' ')}</dd></div>
							{/if}
							{#if exif.iso}<div class="info-row"><dt>ISO</dt><dd>{exif.iso}</dd></div>{/if}
							{#if exif.fNumber}<div class="info-row"><dt>Aperture</dt><dd>{formatFNumber(exif.fNumber)}</dd></div>{/if}
							{#if exif.exposureTime}<div class="info-row"><dt>Shutter</dt><dd>{formatExposure(exif.exposureTime)}</dd></div>{/if}
							{#if exif.focalLength}<div class="info-row"><dt>Focal length</dt><dd>{formatFocal(exif.focalLength)}</dd></div>{/if}
						</dl>
					{/if}

					{#if hasLocation}
						<h4 class="info-heading-sub">Location</h4>
						<dl class="info-list">
							<div class="info-row">
								<dt>Coordinates</dt>
								<dd>
									<a
										class="info-maplink"
										href={`https://www.openstreetmap.org/?mlat=${exif.lat}&mlon=${exif.lon}&zoom=14`}
										target="_blank"
										rel="noopener noreferrer"
									>{formatCoords(exif.lat, exif.lon)}</a>
								</dd>
							</div>
						</dl>
					{/if}
				</aside>
			{/if}

			<!-- Content -->
			<div class="preview-content">
				{#if isLoading}
					<div class="preview-loading">
						<div class="spinner"></div>
						<span>Loading preview...</span>
					</div>
				{:else if error}
					<div class="preview-error">
						<div class="error-icon-wrap">
							<Icon name="error" size={32} />
						</div>
						<p>{error}</p>
						<button class="btn btn-secondary" onclick={download}>Download instead</button>
					</div>
				{:else if previewUrl}
					{#if fileType === 'image'}
						<img
							src={previewUrl}
							alt={file.decrypted_name || file.name}
							class="preview-image"
							class:zoomed={zoomScale > 1}
							style:transform="translate({zoomTx}px, {zoomTy}px) scale({zoomScale})"
							ondblclick={() => resetZoom()}
							draggable="false"
						/>
					{:else if fileType === 'pdf'}
						<!-- Append docBaseUrl hint so Firefox's built-in pdf.js has a
						valid absolute base URL to resolve relative links
						against — avoids the "Invalid absolute docBaseUrl"
						warning it emits for raw blob: URLs. -->
						<iframe src={`${previewUrl}#docBaseUrl=${encodeURIComponent(window.location.origin + '/')}`} class="preview-pdf" title="PDF Preview"></iframe>
					{:else}
						<div class="preview-unsupported">
							<div class="unsupported-icon-wrap">
								<Icon name="file" size={32} />
							</div>
							<p>Preview not available for this file type</p>
							<button class="btn btn-primary" onclick={download}>Download</button>
						</div>
					{/if}
				{/if}
			</div>
		</div>
	</div>
{/if}

<style>
	.preview-overlay {
		position: fixed;
		inset: 0;
		background: rgba(18, 18, 18, 0.95);
		background: color-mix(in srgb, var(--bg-base, #121212) 95%, transparent);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}

	.preview-container {
		width: 100%;
		height: 100%;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.preview-top-bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--sp-sm, 8px) var(--sp-md, 16px);
		background: transparent;
		flex-shrink: 0;
		min-height: 48px;
	}

	.preview-filename {
		flex: 1;
		text-align: center;
		min-width: 0;
	}

	.preview-filename span {
		font-size: var(--t-body-sm-size, 0.8125rem);
		font-weight: 500;
		color: var(--text-primary, #EDEDED);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		display: block;
	}

	.preview-actions {
		display: flex;
		align-items: center;
		gap: var(--sp-xs, 4px);
	}

	.preview-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 44px;
		height: 44px;
		padding: 0;
		background: var(--bg-surface-raised, #262626);
		border: 1px solid var(--border, #2E2E2E);
		border-radius: 50%;
		color: var(--text-secondary, #999999);
		cursor: pointer;
		transition: all 100ms ease;
		-webkit-tap-highlight-color: transparent;
		flex-shrink: 0;
	}

	.preview-btn:hover {
		background: var(--bg-surface-hover, #2E2E2E);
		color: var(--text-primary, #EDEDED);
	}

	.preview-btn.active {
		background: var(--accent);
		color: var(--text-inverse, #fff);
		border-color: var(--accent);
	}

	/* Prev/Next chevrons — hover-reveal on desktop, always visible on touch */
	.preview-nav-btn {
		position: absolute;
		top: 50%;
		transform: translateY(-50%);
		width: 48px;
		height: 48px;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: rgba(0, 0, 0, 0.55);
		border: none;
		color: #fff;
		border-radius: 50%;
		cursor: pointer;
		z-index: 2;
		opacity: 0;
		transition: opacity 150ms ease, background-color 150ms ease;
	}
	.preview-container:hover .preview-nav-btn { opacity: 1; }
	.preview-nav-btn:hover { background: rgba(0, 0, 0, 0.75); }
	.preview-nav-btn.prev { left: var(--sp-md); }
	.preview-nav-btn.next { right: var(--sp-md); }
	@media (pointer: coarse) {
		.preview-nav-btn { opacity: 1; }
	}

	/* Info side panel */
	.preview-info-panel {
		position: absolute;
		top: 60px;
		right: var(--sp-md);
		width: 280px;
		max-height: calc(100% - 72px);
		padding: var(--sp-md);
		background: var(--glass-bg-heavy);
		backdrop-filter: var(--glass-blur);
		-webkit-backdrop-filter: var(--glass-blur);
		border: var(--glass-border);
		border-radius: var(--r-card);
		z-index: 3;
		overflow-y: auto;
		color: var(--text-primary);
	}
	@supports not (backdrop-filter: blur(1px)) {
		.preview-info-panel {
			background: var(--bg-surface-raised);
			border: 1px solid var(--border);
		}
	}
	.info-heading { margin: 0 0 var(--sp-sm); font-size: var(--t-body-size); font-weight: 600; }
	.info-heading-sub {
		margin: var(--sp-md) 0 var(--sp-sm);
		font-size: var(--t-label-size);
		font-weight: 600;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.info-list { margin: 0; display: flex; flex-direction: column; gap: var(--sp-sm); }
	.info-row { display: flex; flex-direction: column; gap: 2px; }
	.info-row dt { font-size: var(--t-label-size); color: var(--text-secondary); margin: 0; }
	.info-row dd { font-size: var(--t-body-sm-size); color: var(--text-primary); margin: 0; word-break: break-word; }
	.info-maplink { color: var(--accent-text); text-decoration: underline; }
	.info-maplink:hover { color: var(--accent); }

	.preview-content {
		flex: 1;
		height: 0;
		overflow: hidden;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		min-height: 0;
		width: 100%;
		position: relative;
	}

	.preview-loading {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--sp-md, 16px);
		color: var(--text-secondary, #999999);
		padding: var(--sp-2xl, 48px);
	}

	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid var(--border, #2E2E2E);
		border-top-color: var(--accent, #2EB860);
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.preview-error,
	.preview-unsupported {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--sp-md, 16px);
		color: var(--text-secondary, #999999);
		padding: var(--sp-2xl, 48px);
		text-align: center;
	}

	.error-icon-wrap,
	.unsupported-icon-wrap {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 64px;
		height: 64px;
		background: var(--danger-muted, #3D1F1F);
		border-radius: var(--r-card, 16px);
		color: var(--danger, #D64545);
	}

	.unsupported-icon-wrap {
		background: var(--bg-surface-raised, #262626);
		color: var(--text-secondary, #999999);
	}

	.preview-error p,
	.preview-unsupported p {
		margin: 0;
		font-size: var(--t-body-sm-size, 0.8125rem);
		max-width: 280px;
	}

	.preview-image {
		max-width: 100%;
		max-height: 100%;
		object-fit: contain;
		transform-origin: center center;
		transition: transform 100ms ease-out;
		touch-action: none;
		user-select: none;
		-webkit-user-select: none;
		-webkit-user-drag: none;
		will-change: transform;
	}
	.preview-image.zoomed {
		/* Pan follows finger instantly — kill the transition to avoid lag. */
		transition: none;
		cursor: grab;
	}
	.preview-image.zoomed:active { cursor: grabbing; }

	.preview-pdf {
		position: absolute;
		inset: 0;
		width: 100%;
		height: 100%;
		border: none;
		background: white;
	}

	@media (max-width: 640px) {
		.preview-top-bar {
			padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
		}

		.preview-filename span {
			font-size: var(--t-label-size, 0.75rem);
		}
	}
</style>
