/**
 * BYO Vault Mutation Journal (P3.1 — thin I/O wrapper)
 *
 * Crypto (serialize, HMAC, encrypt, parse, verify) is delegated to Rust via
 * WASM (`byo_journal_append` / `byo_journal_parse`).  This module handles
 * only buffer management, provider upload/download, and SQLite replay.
 *
 * Wire format (byte-identical to original TS implementation):
 *   Journal file = MAGIC(8) || entry*
 *   Entry = type(1) | table_len(1) | table | row_id(4 LE)
 *           | iv_len(1=12) | iv(12) | data_len(4 LE) | enc_data | hmac(32)
 *
 * See BYO_PLAN §4.2, §4.3.
 */

import type { StorageProvider } from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';
import { bytesToBase64, base64ToBytes } from './base64';

// ── Types ─────────────────────────────────────────────────────────────────────

export type JournalEntryType = 'INSERT' | 'UPDATE' | 'DELETE';

export interface JournalEntry {
  type: JournalEntryType;
  table: string;
  rowId: number;
  /** Plaintext row data as JSON string. */
  data: string;
}

/**
 * Logical per-provider journal name. Most code paths should route through
 * `provider.journalRef(providerId)` instead so the real storage path
 * (SFTP places journals under `{vaultRoot}/data/`) is honored.
 */
export function journalFileName(providerId: string): string {
  return `WattcloudVault/vault_journal_${providerId}.j`;
}

// ── VaultJournal class ────────────────────────────────────────────────────────

export class VaultJournal {
  private readonly provider: StorageProvider;
  private readonly providerId: string;
  private readonly sessionId: number;
  /** In-memory buffer of base64-encoded serialized+HMAC'd entry bytes. */
  private readonly buffer: Uint8Array[] = [];

  constructor(provider: StorageProvider, providerId: string, sessionId: number) {
    this.provider = provider;
    this.providerId = providerId;
    this.sessionId = sessionId;
  }

  // ── Append ──────────────────────────────────────────────────────────────────

  /** Add a mutation entry to the in-memory buffer. Does NOT upload immediately. */
  async append(entry: JournalEntry): Promise<void> {
    const result = await byoWorker.Worker.byoJournalAppend(
      this.sessionId,
      this.providerId,
      entry.type,
      entry.table,
      entry.rowId,
      entry.data,
    );
    this.buffer.push(base64ToBytes(result.entry_b64));
  }

  // ── Flush to provider ────────────────────────────────────────────────────────

  /**
   * Upload buffered entries as vault_journal.j on the provider.
   * Called before vault save so recovery is possible on crash.
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const MAGIC = new Uint8Array([0x53, 0x43, 0x4a, 0x4e, 0x52, 0x4c, 0x00, 0x01]);
    const totalLen = MAGIC.length + this.buffer.reduce((s, e) => s + e.length, 0);
    const out = new Uint8Array(totalLen);
    out.set(MAGIC, 0);
    let offset = MAGIC.length;
    for (const entry of this.buffer) {
      out.set(entry, offset);
      offset += entry.length;
    }

    // ref = provider's canonical journal path; name = bare filename so
    // providers that auto-prefix (SFTP adds {vaultRoot}/data/, Mock adds
    // WattcloudVault/) don't double the prefix.
    await this.provider.upload(
      this.provider.journalRef(this.providerId),
      `vault_journal_${this.providerId}.j`,
      out,
      {},
    );
  }

  /** Clear in-memory buffer and delete journal from provider after successful vault save. */
  async commit(): Promise<void> {
    this.buffer.length = 0;
    try {
      await this.provider.delete(this.provider.journalRef(this.providerId));
    } catch {
      // Not found is fine — journal may already be gone
    }
  }

  /** Clear buffer without committing (e.g. on vault lock). */
  clear(): void {
    this.buffer.length = 0;
  }

  // ── Replay on vault open ──────────────────────────────────────────────────

  /**
   * Download and replay an existing vault_journal.j.
   *
   * 1. Check if journal exists on provider
   * 2. Download, parse via WASM (verify HMACs, decrypt entries)
   * 3. Replay onto the in-memory SQLite
   * 4. Delete journal from provider
   *
   * @returns number of entries replayed
   */
  async replayIfExists(db: import('sql.js').Database): Promise<number> {
    let journalData: Uint8Array;
    try {
      const result = await this.provider.download(this.provider.journalRef(this.providerId));
      journalData = result.data;
    } catch {
      // Journal doesn't exist — normal startup
      return 0;
    }

    let entries: JournalEntry[];
    try {
      const parsed = await byoWorker.Worker.byoJournalParse(
        this.sessionId,
        this.providerId,
        bytesToBase64(journalData),
      );
      entries = parsed.entries.map((e) => ({
        type: e.entry_type as JournalEntryType,
        table: e.table,
        rowId: e.row_id,
        data: e.data,
      }));
    } catch (err) {
      // H5: fail closed — discard tampered/corrupted journal.
      console.warn('[VaultJournal] Journal discarded due to integrity failure:', err);
      try { await this.provider.delete(this.provider.journalRef(this.providerId)); } catch { /* ignore */ }
      this.buffer.length = 0;
      return 0;
    }

    let replayed = 0;
    for (const entry of entries) {
      try {
        this.applyEntry(db, entry);
        replayed++;
      } catch (err) {
        console.warn('[VaultJournal] Failed to replay entry:', entry.type, entry.table, err);
      }
    }

    // Delete journal after successful replay
    try {
      await this.provider.delete(this.provider.journalRef(this.providerId));
    } catch {
      // Ignore — journal may already be gone
    }

    return replayed;
  }

  // ── Private: apply ────────────────────────────────────────────────────────

  private applyEntry(db: import('sql.js').Database, entry: JournalEntry): void {
    const rowData = JSON.parse(entry.data) as Record<string, unknown>;

    switch (entry.type) {
      case 'INSERT': {
        const cols = Object.keys(rowData);
        const placeholders = cols.map(() => '?').join(', ');
        const values = cols.map((c) => rowData[c]);
        db.run(
          `INSERT OR REPLACE INTO ${entry.table} (${cols.join(', ')}) VALUES (${placeholders})`,
          values as import('sql.js').BindParams,
        );
        break;
      }
      case 'UPDATE': {
        const cols = Object.keys(rowData).filter((c) => c !== 'id');
        const setClause = cols.map((c) => `${c} = ?`).join(', ');
        const values = [...cols.map((c) => rowData[c]), entry.rowId];
        db.run(
          `UPDATE ${entry.table} SET ${setClause} WHERE id = ?`,
          values as import('sql.js').BindParams,
        );
        break;
      }
      case 'DELETE': {
        db.run(`DELETE FROM ${entry.table} WHERE id = ?`, [entry.rowId]);
        break;
      }
    }
  }
}
