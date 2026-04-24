import { writable, derived, get } from 'svelte/store';

export interface FolderNode {
	id: number;
	parentId: number | null;
	name: string; // decrypted
}

export interface DownloadItem {
	id: string;
	type: 'file' | 'folder' | 'bulk';
	name: string;
	fileIds: number[];
	folderIds: number[];
	folderTree?: FolderNode[]; // for building zip paths in bulk downloads
	// 'ready-to-save' is the terminal pre-save state on iOS Safari, where
	// we've buffered the decrypted plaintext in memory and are waiting
	// for a fresh user-gesture tap to hand it to navigator.share. Only
	// used by the BYO queue; managed paths don't buffer on iOS.
	status: 'pending' | 'estimating' | 'confirming' | 'downloading' | 'decrypting' | 'zipping' | 'paused' | 'ready-to-save' | 'completed' | 'cancelled' | 'error';
	progress: number;
	error?: string;
	createdAt: Date;
	// Chunking support
	totalSize: number;           // Total size in bytes
	totalChunks: number;         // Number of ZIP chunks
	currentChunk: number;        // Current chunk being processed
	chunkProgress: number;       // Progress within current chunk (0-100)
	filesProcessed: number;      // Number of files processed
	totalFiles: number;          // Total number of files
	cancelRequested: boolean;    // Cancellation flag
	pauseRequested: boolean;     // Pause flag (resolved by the pause gate in downloadService)
	pausedStatus?: DownloadItem['status']; // Status to restore on resume (downloading/decrypting/zipping)
}

interface DownloadQueueState {
	items: DownloadItem[];
}

function createDownloadQueue() {
	const { subscribe, update, set } = writable<DownloadQueueState>({
		items: []
	});

	function generateId(): string {
		return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
	}

	function addFile(fileId: number, name: string): string {
		const newItem: DownloadItem = {
			id: generateId(),
			type: 'file',
			name,
			fileIds: [fileId],
			folderIds: [],
			status: 'pending',
			progress: 0,
			createdAt: new Date(),
			totalSize: 0,
			totalChunks: 1,
			currentChunk: 0,
			chunkProgress: 0,
			filesProcessed: 0,
			totalFiles: 1,
			cancelRequested: false,
			pauseRequested: false
		};

		update((state) => ({
			items: [...state.items, newItem]
		}));

		return newItem.id;
	}

	function addFolder(folderId: number, name: string): string {
		const newItem: DownloadItem = {
			id: generateId(),
			type: 'folder',
			name,
			fileIds: [],
			folderIds: [folderId],
			status: 'pending',
			progress: 0,
			createdAt: new Date(),
			totalSize: 0,
			totalChunks: 1,
			currentChunk: 0,
			chunkProgress: 0,
			filesProcessed: 0,
			totalFiles: 0,
			cancelRequested: false,
			pauseRequested: false
		};

		update((state) => ({
			items: [...state.items, newItem]
		}));

		return newItem.id;
	}

	function addBulk(fileIds: number[], folderIds: number[], name: string, folderTree?: FolderNode[]): string {
		const newItem: DownloadItem = {
			id: generateId(),
			type: 'bulk',
			name,
			fileIds,
			folderIds,
			folderTree,
			status: 'pending',
			progress: 0,
			createdAt: new Date(),
			totalSize: 0,
			totalChunks: 1,
			currentChunk: 0,
			chunkProgress: 0,
			filesProcessed: 0,
			totalFiles: fileIds.length + folderIds.length,
			cancelRequested: false,
			pauseRequested: false
		};

		update((state) => ({
			items: [...state.items, newItem]
		}));

		return newItem.id;
	}

	function removeItem(id: string): void {
		update((state) => ({
			items: state.items.filter((item) => item.id !== id)
		}));
	}

	function clearCompleted(): void {
		update((state) => ({
			items: state.items.filter((item) => item.status !== 'completed')
		}));
	}

	function clearAll(): void {
		set({ items: [] });
	}

	function updateProgress(id: string, progress: number): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, progress: Math.min(100, Math.max(0, progress)) } : item
			)
		}));
	}

	function setStatus(id: string, status: DownloadItem['status'], error?: string): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, status, error } : item
			)
		}));
	}

	function startDownload(): DownloadItem | null {
		const state = get({ subscribe });
		const pendingItem = state.items.find((item) => item.status === 'pending');

		if (pendingItem) {
			update((s) => ({
				items: s.items.map((item) =>
					item.id === pendingItem.id ? { ...item, status: 'downloading' } : item
				)
			}));
			return { ...pendingItem, status: 'downloading' };
		}

		return null;
	}

	function getNextPending(): DownloadItem | null {
		const state = get({ subscribe });
		return state.items.find((item) => item.status === 'pending') ?? null;
	}

	function cancelDownload(id: string): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, cancelRequested: true } : item
			)
		}));
	}

	/**
	 * Request a pause. The actual state transition to `'paused'` happens in
	 * `downloadService` when the pause gate observes the flag — that way the
	 * progress UI only flips to "Paused" once bytes actually stop flowing.
	 * Stores the previous status so resume can restore it.
	 */
	function pauseDownload(id: string): void {
		update((state) => ({
			items: state.items.map((item) => {
				if (item.id !== id) return item;
				// Only pause things that are actually in flight.
				if (
					item.status !== 'downloading' &&
					item.status !== 'decrypting' &&
					item.status !== 'zipping'
				) {
					return item;
				}
				return {
					...item,
					pauseRequested: true,
					pausedStatus: item.status,
					status: 'paused',
				};
			}),
		}));
	}

	function resumeDownload(id: string): void {
		update((state) => ({
			items: state.items.map((item) => {
				if (item.id !== id) return item;
				if (item.status !== 'paused') return item;
				return {
					...item,
					pauseRequested: false,
					status: item.pausedStatus ?? 'downloading',
					pausedStatus: undefined,
				};
			}),
		}));
	}

	function updateChunkProgress(id: string, chunkProgress: number, currentChunk: number, totalChunks: number): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, chunkProgress: Math.min(100, Math.max(0, chunkProgress)), currentChunk, totalChunks } : item
			)
		}));
	}

	function updateFilesProcessed(id: string, filesProcessed: number, totalFiles: number): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, filesProcessed, totalFiles } : item
			)
		}));
	}

	function updateTotalSize(id: string, totalSize: number): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, totalSize } : item
			)
		}));
	}

	function getItem(id: string): DownloadItem | null {
		const state = get({ subscribe });
		return state.items.find((item) => item.id === id) ?? null;
	}

	return {
		subscribe,
		addFile,
		addFolder,
		addBulk,
		removeItem,
		clearCompleted,
		clearAll,
		updateProgress,
		setStatus,
		startDownload,
		getNextPending,
		cancelDownload,
		pauseDownload,
		resumeDownload,
		updateChunkProgress,
		updateFilesProcessed,
		updateTotalSize,
		getItem
	};
}

export const downloadQueue = createDownloadQueue();

// Helper functions for component usage
export function clearCompletedDownloads(): void {
	downloadQueue.clearCompleted();
}

export function removeDownload(id: string): void {
	downloadQueue.removeItem(id);
}

// Derived stores
export const downloadQueueItems = derived(downloadQueue, ($queue) => $queue.items);

export const isDownloading = derived(downloadQueue, ($queue) =>
	$queue.items.some((item) => item.status === 'downloading' || item.status === 'decrypting')
);

export const completedDownloadCount = derived(downloadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'completed').length
);

export const totalDownloadCount = derived(downloadQueue, ($queue) => $queue.items.length);

export const pendingDownloadCount = derived(downloadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'pending').length
);

export const downloadErrorCount = derived(downloadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'error').length
);