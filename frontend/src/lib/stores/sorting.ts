import { writable } from 'svelte/store';
import { get } from 'svelte/store';

// Sorting types
export type SortBy = 'date' | 'name';
export type SortDirection = 'up' | 'down';

export interface SortingState {
	by: SortBy;
	direction: SortDirection;
}

// Default sorting: date, down (newest first)
const DEFAULT_SORTING: SortingState = {
	by: 'date',
	direction: 'down'
};

// Storage keys
const FILES_SORTING_KEY = 'secure_cloud_files_sorting';
const PHOTOS_SORTING_KEY = 'secure_cloud_photos_sorting';
const FAVORITES_SORTING_KEY = 'secure_cloud_favorites_sorting';

function createSortingStore(storageKey: string) {
	// Load from localStorage
	function loadFromStorage(): SortingState {
		if (typeof window === 'undefined') return { ...DEFAULT_SORTING };

		try {
			const stored = localStorage.getItem(storageKey);
			if (stored) {
				const parsed = JSON.parse(stored);
				return {
					by: parsed.by || 'date',
					direction: parsed.direction || 'down'
				};
			}
		} catch (e) {
		}
		return { ...DEFAULT_SORTING };
	}

	// Save to localStorage
	function saveToStorage(state: SortingState): void {
		if (typeof window === 'undefined') return;

		try {
			localStorage.setItem(storageKey, JSON.stringify(state));
		} catch (e) {
		}
	}

	const { subscribe, set, update } = writable<SortingState>(loadFromStorage());

	return {
		subscribe,
		setBy: (by: SortBy) => {
			update(state => {
				const newState = { ...state, by };
				saveToStorage(newState);
				return newState;
			});
		},
		setDirection: (direction: SortDirection) => {
			update(state => {
				const newState = { ...state, direction };
				saveToStorage(newState);
				return newState;
			});
		},
		toggleDirection: () => {
			update(state => {
				const newState = { ...state, direction: (state.direction === 'up' ? 'down' : 'up') as SortDirection };
				saveToStorage(newState);
				return newState;
			});
		},
		setSorting: (by: SortBy, direction: SortDirection) => {
			const newState = { by, direction };
			saveToStorage(newState);
			set(newState);
		},
		reset: () => {
			saveToStorage({ ...DEFAULT_SORTING });
			set({ ...DEFAULT_SORTING });
		}
	};
}

// Separate stores for each section
export const filesSorting = createSortingStore(FILES_SORTING_KEY);
export const photosSorting = createSortingStore(PHOTOS_SORTING_KEY);
export const favoritesSorting = createSortingStore(FAVORITES_SORTING_KEY);

// Helper function to sort files
export function sortFiles<T extends { name?: string; created_at?: string; decrypted_name?: string; decrypted_filename?: string; decrypted_metadata?: { takenAt?: string } }>(
	files: T[],
	sorting: SortingState,
	useCreationDate: boolean = false
): T[] {
	const sorted = [...files];

	sorted.sort((a, b) => {
		let comparison = 0;

		if (sorting.by === 'name') {
			// Support both decrypted_name (files) and decrypted_filename (photos)
			const nameA = (a as any).decrypted_name || (a as any).decrypted_filename || a.name || '';
			const nameB = (b as any).decrypted_name || (b as any).decrypted_filename || b.name || '';
			comparison = nameA.localeCompare(nameB);
		} else {
			// Date sorting
			let dateA: number;
			let dateB: number;

			if (useCreationDate) {
				// For photos, use takenAt from metadata if available, fallback to created_at
				dateA = a.decrypted_metadata?.takenAt
					? new Date(a.decrypted_metadata.takenAt).getTime()
					: a.created_at ? new Date(a.created_at).getTime() : 0;
				dateB = b.decrypted_metadata?.takenAt
					? new Date(b.decrypted_metadata.takenAt).getTime()
					: b.created_at ? new Date(b.created_at).getTime() : 0;
			} else {
				dateA = a.created_at ? new Date(a.created_at).getTime() : 0;
				dateB = b.created_at ? new Date(b.created_at).getTime() : 0;
			}

			comparison = dateA - dateB;
		}

		// Reverse for 'down' direction (newest first)
		return sorting.direction === 'down' ? -comparison : comparison;
	});

	return sorted;
}

// Helper function to sort folders — uses sorting state if provided
export function sortFolders<T extends { name?: string; decrypted_name?: string; created_at?: string }>(
	folders: T[],
	sorting?: SortingState
): T[] {
	const sorted = [...folders];

	sorted.sort((a, b) => {
		let comparison = 0;

		if (!sorting || sorting.by === 'name') {
			const nameA = (a as any).decrypted_name || a.name || '';
			const nameB = (b as any).decrypted_name || b.name || '';
			comparison = nameA.localeCompare(nameB);
		} else {
			const dateA = a.created_at ? new Date(a.created_at).getTime() : 0;
			const dateB = b.created_at ? new Date(b.created_at).getTime() : 0;
			comparison = dateA - dateB;
		}

		return sorting && sorting.direction === 'down' ? -comparison : comparison;
	});

	return sorted;
}