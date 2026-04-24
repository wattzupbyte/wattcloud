/**
 * BYO Collections store.
 *
 * Collections are per-provider, encrypted-name albums that group files
 * (typically photos). Membership lives in `collection_files`; the collection
 * row itself stores only the encrypted name + cover file reference.
 *
 * State is loaded on demand — vault unlock does not eagerly populate.
 */

import { writable, derived, get, type Readable } from 'svelte/store';
import type { DataProvider, CollectionEntry, FileEntry } from '../DataProvider';

/** Raw, unordered collections as returned by the DataProvider. */
const byoCollectionsRaw = writable<CollectionEntry[]>([]);
export const byoCollectionsLoading = writable<boolean>(false);
/** Currently-opened collection id, or null when on the collections index. */
export const byoSelectedCollectionId = writable<number | null>(null);
export const byoCollectionFiles = writable<FileEntry[]>([]);

/**
 * User-ordered id list, persisted per-vault in localStorage. Collections
 * not listed here fall through after the ordered ones (new items land at
 * the end by default).
 */
const ORDER_PREF_PREFIX = 'byo:collections_order:';
const byoCollectionsOrder = writable<number[]>([]);
let _orderVaultId: string | null = null;

function persistOrder(): void {
  if (!_orderVaultId) return;
  try {
    const order: number[] = [];
    byoCollectionsOrder.subscribe((v) => { order.push(...v); })();
    localStorage.setItem(ORDER_PREF_PREFIX + _orderVaultId, JSON.stringify(order));
  } catch { /* storage unavailable — in-memory ordering still works */ }
}

export function initByoCollectionsOrder(vaultId: string): void {
  _orderVaultId = vaultId;
  try {
    const raw = localStorage.getItem(ORDER_PREF_PREFIX + vaultId);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.every((n) => typeof n === 'number')) {
        byoCollectionsOrder.set(parsed);
        return;
      }
    }
  } catch { /* ignore */ }
  byoCollectionsOrder.set([]);
}

export function moveByoCollection(id: number, delta: -1 | 1): void {
  byoCollectionsOrder.update((order) => {
    // Seed the order list from the current collection view if empty so
    // reorder works the first time without requiring a prior "order" set.
    let working = order.slice();
    if (working.length === 0) {
      byoCollectionsRaw.subscribe((rows) => {
        working = rows.map((r) => r.id);
      })();
    }
    if (!working.includes(id)) working.push(id);
    const i = working.indexOf(id);
    const j = i + delta;
    if (j < 0 || j >= working.length) return working;
    [working[i], working[j]] = [working[j], working[i]];
    return working;
  });
  persistOrder();
}

/**
 * Publicly exposed ordered collections — derived from raw + the
 * localStorage-backed order list.
 */
export const byoCollections: Readable<CollectionEntry[]> = derived(
  [byoCollectionsRaw, byoCollectionsOrder],
  ([$raw, $order]) => {
    if ($order.length === 0) return $raw;
    const byId = new Map($raw.map((c) => [c.id, c] as const));
    const seen = new Set<number>();
    const out: CollectionEntry[] = [];
    for (const id of $order) {
      const c = byId.get(id);
      if (c && !seen.has(id)) { out.push(c); seen.add(id); }
    }
    // Append any collections not in the saved order (new ones).
    for (const c of $raw) if (!seen.has(c.id)) out.push(c);
    return out;
  },
);

export const hasByoCollections = derived(byoCollections, ($c) => $c.length > 0);

let _dataProvider: DataProvider | null = null;

export function setByoCollectionsDataProvider(dp: DataProvider): void {
  _dataProvider = dp;
}

export async function loadByoCollections(): Promise<void> {
  if (!_dataProvider) return;
  byoCollectionsLoading.set(true);
  try {
    const rows = await _dataProvider.listCollections();
    byoCollectionsRaw.set(rows);
  } catch (e) {
    console.error('[byoCollections] load failed:', e);
    byoCollectionsRaw.set([]);
  } finally {
    byoCollectionsLoading.set(false);
  }
}

export async function loadByoCollectionFiles(collectionId: number): Promise<void> {
  if (!_dataProvider) return;
  try {
    const files = await _dataProvider.listCollectionFiles(collectionId);
    byoCollectionFiles.set(files);
  } catch (e) {
    console.error(`[byoCollections] load files for ${collectionId} failed:`, e);
    byoCollectionFiles.set([]);
  }
}

export async function createByoCollection(name: string): Promise<void> {
  if (!_dataProvider) return;
  await _dataProvider.createCollection(name.trim());
  await loadByoCollections();
}

export async function renameByoCollection(id: number, newName: string): Promise<void> {
  if (!_dataProvider) return;
  await _dataProvider.renameCollection(id, newName.trim());
  await loadByoCollections();
}

export async function deleteByoCollection(id: number): Promise<void> {
  if (!_dataProvider) return;
  await _dataProvider.deleteCollection(id);
  if (get(byoSelectedCollectionId) === id) {
    byoSelectedCollectionId.set(null);
    byoCollectionFiles.set([]);
  }
  await loadByoCollections();
}

export async function addByoFilesToCollection(
  collectionId: number,
  fileIds: number[],
): Promise<void> {
  if (!_dataProvider || fileIds.length === 0) return;
  await _dataProvider.addFilesToCollection(collectionId, fileIds);
  await loadByoCollections();
  if (get(byoSelectedCollectionId) === collectionId) {
    await loadByoCollectionFiles(collectionId);
  }
}

export async function removeByoFilesFromCollection(
  collectionId: number,
  fileIds: number[],
): Promise<void> {
  if (!_dataProvider || fileIds.length === 0) return;
  await _dataProvider.removeFilesFromCollection(collectionId, fileIds);
  await loadByoCollections();
  if (get(byoSelectedCollectionId) === collectionId) {
    await loadByoCollectionFiles(collectionId);
  }
}

export function resetByoCollections(): void {
  byoCollectionsRaw.set([]);
  byoCollectionsOrder.set([]);
  byoCollectionsLoading.set(false);
  byoSelectedCollectionId.set(null);
  byoCollectionFiles.set([]);
  _dataProvider = null;
  _orderVaultId = null;
}
