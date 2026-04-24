import { writable, derived, get } from 'svelte/store';

export interface UploadItemGroup {
	/** Stable id shared by every file from the same folder-upload operation. */
	id: string;
	/** Disambiguated top-level folder name shown in the upload queue UI. */
	rootName: string;
}

export interface UploadItem {
	id: string;
	file: File;
	folderId: number | null;
	status: 'pending' | 'encrypting' | 'uploading' | 'completed' | 'error';
	progress: number;
	error?: string;
	createdAt: Date;
	overrideName?: string;
	/** File IDs to delete after successful upload (for overwrite) */
	deleteAfterUpload?: number[];
	// Encrypted upload fields
	encryptedData?: string;
	encryptedFilename?: string;
	/** Set for folder uploads — groups all files under the same root folder. */
	uploadGroup?: UploadItemGroup;
}

interface UploadQueueState {
	items: UploadItem[];
}

function createUploadQueue() {
	const { subscribe, update, set } = writable<UploadQueueState>({
		items: []
	});

	function generateId(): string {
		return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
	}

	function addFile(file: File, folderId: number | null, opts?: { overrideName?: string; deleteAfterUpload?: number[]; uploadGroup?: UploadItemGroup }): void {
		const newItem: UploadItem = {
			id: generateId(),
			file,
			folderId,
			status: 'pending',
			progress: 0,
			createdAt: new Date(),
			overrideName: opts?.overrideName,
			deleteAfterUpload: opts?.deleteAfterUpload,
			uploadGroup: opts?.uploadGroup,
		};

		update((state) => ({
			items: [...state.items, newItem]
		}));
	}

	function addFiles(files: File[], folderId: number | null): void {
		const newItems: UploadItem[] = files.map((file) => ({
			id: generateId(),
			file,
			folderId,
			status: 'pending',
			progress: 0,
			createdAt: new Date()
		}));

		update((state) => ({
			items: [...state.items, ...newItems]
		}));
	}

	function removeItem(id: string): void {
		update((state) => ({
			items: state.items.filter((item) => item.id !== id)
		}));
	}

	function removeGroup(groupId: string): void {
		update((state) => ({
			items: state.items.filter((item) => item.uploadGroup?.id !== groupId)
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

	function setStatus(id: string, status: UploadItem['status'], error?: string): void {
		update((state) => ({
			items: state.items.map((item) =>
				item.id === id ? { ...item, status, error } : item
			)
		}));
	}

	function startUpload(): UploadItem | null {
		const state = get({ subscribe });
		const pendingItem = state.items.find((item) => item.status === 'pending');

		if (pendingItem) {
			update((s) => ({
				items: s.items.map((item) =>
					item.id === pendingItem.id ? { ...item, status: 'uploading' } : item
				)
			}));
			return { ...pendingItem, status: 'uploading' };
		}

		return null;
	}

	function getNextPending(): UploadItem | null {
		const state = get({ subscribe });
		return state.items.find((item) => item.status === 'pending') ?? null;
	}

	return {
		subscribe,
		addFile,
		addFiles,
		removeItem,
		removeGroup,
		clearCompleted,
		clearAll,
		updateProgress,
		setStatus,
		startUpload,
		getNextPending
	};
}

export const uploadQueue = createUploadQueue();

// Helper functions for component usage
export function clearCompleted(): void {
	uploadQueue.clearCompleted();
}

export function removeItem(id: string): void {
	uploadQueue.removeItem(id);
}

export function removeGroup(groupId: string): void {
	uploadQueue.removeGroup(groupId);
}

// Derived stores
export const uploadQueueItems = derived(uploadQueue, ($queue) => $queue.items);

export const isUploading = derived(uploadQueue, ($queue) =>
	$queue.items.some((item) => item.status === 'uploading')
);

export const completedCount = derived(uploadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'completed').length
);

export const totalCount = derived(uploadQueue, ($queue) => $queue.items.length);

export const pendingCount = derived(uploadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'pending').length
);

export const errorCount = derived(uploadQueue, ($queue) =>
	$queue.items.filter((item) => item.status === 'error').length
);
