/**
 * BYO Search Store
 *
 * Wraps DataProvider.searchFiles() with debouncing.
 * Provides the same reactive interface as the managed search store
 * (searchQuery, searchResults, isSearching) for use in ByoSearchFilter.
 *
 * DataProvider must be set via setDataProvider() after vault unlock.
 * On vault lock, call resetByoSearch() to clear all state.
 */

import { writable, derived } from 'svelte/store';
import type { DataProvider } from '../DataProvider';
import type { FileEntry } from '../DataProvider';

// ── State ──────────────────────────────────────────────────────────────────

export const byoSearchQuery = writable<string>('');
export const byoSearchResults = writable<FileEntry[]>([]);
export const isByoSearching = writable<boolean>(false);

export const byoSearchFilters = writable<{
  fileType: string | null;
  dateFrom: string | null;
  dateTo: string | null;
}>({
  fileType: null,
  dateFrom: null,
  dateTo: null,
});

// ── DataProvider reference ─────────────────────────────────────────────────

let _dataProvider: DataProvider | null = null;
let _debounceTimer: ReturnType<typeof setTimeout> | null = null;

export function setByoSearchDataProvider(dp: DataProvider): void {
  _dataProvider = dp;
}

// ── Actions ────────────────────────────────────────────────────────────────

export async function performByoSearch(): Promise<void> {
  if (!_dataProvider) return;

  let query = '';
  const unsubQ = byoSearchQuery.subscribe((v) => { query = v; });
  unsubQ();

  let filters = { fileType: null as string | null, dateFrom: null as string | null, dateTo: null as string | null };
  const unsubF = byoSearchFilters.subscribe((v) => { filters = v; });
  unsubF();

  if (!query.trim() && !filters.fileType && !filters.dateFrom && !filters.dateTo) {
    byoSearchResults.set([]);
    isByoSearching.set(false);
    return;
  }

  isByoSearching.set(true);
  try {
    let results = query.trim()
      ? await _dataProvider.searchFiles(query.trim())
      : await _dataProvider.listImageFiles(); // fallback for type-only filter

    // Apply client-side filters
    if (filters.fileType) {
      results = results.filter((f) => f.file_type === filters.fileType);
    }
    if (filters.dateFrom) {
      const from = new Date(filters.dateFrom);
      results = results.filter((f) => new Date(f.created_at) >= from);
    }
    if (filters.dateTo) {
      const to = new Date(filters.dateTo);
      to.setHours(23, 59, 59, 999);
      results = results.filter((f) => new Date(f.created_at) <= to);
    }

    byoSearchResults.set(results);
  } catch (e) {
    console.error('[byoSearch] search failed:', e);
    byoSearchResults.set([]);
  } finally {
    isByoSearching.set(false);
  }
}

export function setByoSearchQuery(query: string): void {
  byoSearchQuery.set(query);
  if (_debounceTimer) clearTimeout(_debounceTimer);
  _debounceTimer = setTimeout(() => performByoSearch(), 300);
}

export function setByoFileTypeFilter(fileType: string | null): void {
  byoSearchFilters.update((f) => ({ ...f, fileType }));
  performByoSearch();
}

export function setByoDateRange(dateFrom: string | null, dateTo: string | null): void {
  byoSearchFilters.update((f) => ({ ...f, dateFrom, dateTo }));
  performByoSearch();
}

export function clearByoSearch(): void {
  if (_debounceTimer) { clearTimeout(_debounceTimer); _debounceTimer = null; }
  byoSearchQuery.set('');
  byoSearchFilters.set({ fileType: null, dateFrom: null, dateTo: null });
  byoSearchResults.set([]);
  isByoSearching.set(false);
}

export function resetByoSearch(): void {
  clearByoSearch();
  _dataProvider = null;
}

// ── Derived ────────────────────────────────────────────────────────────────

export const hasByoActiveFilters = derived(
  [byoSearchQuery, byoSearchFilters],
  ([$q, $f]) =>
    $q.length > 0 || $f.fileType !== null || $f.dateFrom !== null || $f.dateTo !== null,
);
