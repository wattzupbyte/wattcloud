/**
 * Shared utility functions
 */

/**
 * Detect iOS devices (iPad, iPhone, iPod)
 */
export function isIOS(): boolean {
	return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
		(navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

/**
 * Get MIME type from filename extension
 */
export function getMimeType(filename: string): string {
	const ext = filename.split('.').pop()?.toLowerCase() ?? '';
	const types: Record<string, string> = {
		pdf: 'application/pdf',
		jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
		gif: 'image/gif', webp: 'image/webp', heic: 'image/heic',
		mp4: 'video/mp4', mov: 'video/quicktime', avi: 'video/x-msvideo',
		mp3: 'audio/mpeg', m4a: 'audio/mp4', wav: 'audio/wav',
		txt: 'text/plain', md: 'text/markdown',
		zip: 'application/zip', gz: 'application/gzip',
		docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
	};
	return types[ext] ?? 'application/octet-stream';
}

/**
 * iOS download state for showing a tappable link
 */
export interface IOSDownloadState {
	url: string;
	name: string;
	timer: ReturnType<typeof setTimeout>;
}

let iosDownloadLink: IOSDownloadState | null = null;

/**
 * Get the current iOS download link state (for showing in UI)
 */
export function getIOSDownloadLink(): IOSDownloadState | null {
	return iosDownloadLink;
}

/**
 * Clear the iOS download link state
 */
export function clearIOSDownloadLink(): void {
	if (iosDownloadLink) {
		URL.revokeObjectURL(iosDownloadLink.url);
		clearTimeout(iosDownloadLink.timer);
		iosDownloadLink = null;
	}
}

/**
 * Trigger file download with iOS/WebKit compatibility
 * Uses Web Share API on iOS 15+, falls back to tappable link on older iOS,
 * and uses standard anchor click on other platforms.
 */
export async function triggerDownload(blob: Blob, name: string): Promise<void> {
	// Web Share API: best on iOS 15+, also works on Android Chrome
	if (typeof navigator.share === 'function' && typeof navigator.canShare === 'function') {
		const file = new File([blob], name, { type: blob.type });
		if (navigator.canShare({ files: [file] })) {
			try {
				await navigator.share({ files: [file], title: name });
				return;
			} catch (e: any) {
				if (e.name === 'AbortError') return; // user cancelled — don't fall through
				// Share failed for another reason — fall through to link/click
			}
		}
	}

	const url = URL.createObjectURL(blob);

	if (isIOS()) {
		// Fallback on iOS: show a tappable link (direct user gesture required)
		if (iosDownloadLink) {
			URL.revokeObjectURL(iosDownloadLink.url);
			clearTimeout(iosDownloadLink.timer);
		}
		const timer = setTimeout(() => {
			if (iosDownloadLink) {
				URL.revokeObjectURL(iosDownloadLink.url);
				iosDownloadLink = null;
			}
		}, 60000);
		iosDownloadLink = { url, name, timer };
	} else {
		const a = document.createElement('a');
		a.href = url;
		a.download = name;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	}
}