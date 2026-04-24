/**
 * BYO Filename Search Index
 *
 * In-memory case-insensitive substring search over decrypted filenames.
 * Built from byoFileStore after vault unlock and maintained on mutations.
 *
 * For 10K files, ~500KB plaintext in main-thread Map. Substring search
 * over 10K strings takes <5ms — fast enough for interactive search.
 *
 * Re-indexed when vault changes (conflict merge, journal replay).
 * See BYO_PLAN §6.1.
 */

import type { FileEntry } from './DataProvider';

// ── SearchIndex ────────────────────────────────────────────────────────────

export class SearchIndex {
  private readonly index = new Map<number, string>();

  /** Build the index from a list of FileEntry objects. */
  build(files: FileEntry[]): void {
    this.index.clear();
    for (const f of files) {
      this.index.set(f.id, f.decrypted_name.toLowerCase());
    }
  }

  /** Add or update a single file in the index. */
  upsert(fileId: number, decryptedName: string): void {
    this.index.set(fileId, decryptedName.toLowerCase());
  }

  /** Remove a file from the index (on delete). */
  remove(fileId: number): void {
    this.index.delete(fileId);
  }

  /**
   * Case-insensitive substring search.
   * Returns matching file IDs sorted by name (alphabetical).
   */
  search(query: string): number[] {
    if (!query.trim()) return [];
    const q = query.toLowerCase();
    const results: Array<{ id: number; name: string }> = [];

    for (const [id, name] of this.index) {
      if (name.includes(q)) {
        results.push({ id, name });
      }
    }

    results.sort((a, b) => a.name.localeCompare(b.name));
    return results.map((r) => r.id);
  }

  /** Number of indexed files. */
  get size(): number {
    return this.index.size;
  }

  /** Clear the entire index (on vault lock). */
  clear(): void {
    this.index.clear();
  }
}
