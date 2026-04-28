/**
 * BYO Vault SQLite Migrations (R6+)
 *
 * R6 is a greenfield reset: the app is pre-production, so all M1–M5 migration
 * code has been removed. New vaults are created with the R6 schema
 * (provider_id NOT NULL, cross-provider triggers, no providers/provider_config tables).
 *
 * A handful of additive migrations live here for schema changes shipped
 * after the initial R6 greenfield — they use ALTER TABLE so existing vaults
 * pick up new columns on open.
 */

import type { ProviderType } from '@wattcloud/sdk';

type Database = import('sql.js').Database;

function hasColumn(db: Database, table: string, col: string): boolean {
  try {
    const stmt = db.prepare(`PRAGMA table_info(${table})`);
    let found = false;
    try {
      while (stmt.step()) {
        const row = stmt.getAsObject();
        if (row['name'] === col) {
          found = true;
          break;
        }
      }
    } finally {
      stmt.free();
    }
    return found;
  } catch {
    return false;
  }
}

function addColumn(db: Database, table: string, col: string, decl: string): void {
  if (!hasColumn(db, table, col)) {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
  }
}

/**
 * Drop the legacy `variant` column from `share_tokens`.
 *
 * Can't use `ALTER TABLE ... DROP COLUMN` because the original column had an
 * inline CHECK constraint, which SQLite refuses to drop along with the column.
 * Standard SQLite workaround: rebuild the table without the column, copy
 * non-revoked rows, swap names.
 *
 * Rows with `variant NOT IN ('B2')` are legacy A/A+/B1 shares from earlier
 * builds; those flows no longer work (no recipient path), so we drop them
 * on migration. Per CLAUDE.md R6 is pre-production and no legacy share
 * links exist in the wild.
 */
function dropVariantColumn(db: Database): void {
  db.run('DROP TABLE IF EXISTS share_tokens_new');
  db.run(`
    CREATE TABLE share_tokens_new (
      share_id TEXT PRIMARY KEY,
      kind TEXT NOT NULL DEFAULT 'file' CHECK (kind IN ('file','folder','collection')),
      file_id INTEGER,
      folder_id INTEGER,
      collection_id INTEGER,
      provider_id TEXT NOT NULL,
      provider_ref TEXT,
      public_link TEXT,
      presigned_expires_at INTEGER,
      owner_token TEXT,
      total_bytes INTEGER,
      blob_count INTEGER,
      created_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0
    );
  `);
  db.run(`
    INSERT INTO share_tokens_new
      (share_id, kind, file_id, folder_id, collection_id, provider_id,
       provider_ref, public_link, presigned_expires_at, owner_token,
       total_bytes, blob_count, created_at, revoked)
    SELECT share_id, COALESCE(kind, 'file'), file_id, folder_id, collection_id,
           provider_id, provider_ref, public_link, presigned_expires_at,
           owner_token, total_bytes, blob_count, created_at, revoked
    FROM share_tokens
    WHERE variant = 'B2';
  `);
  db.run('DROP TABLE share_tokens');
  db.run('ALTER TABLE share_tokens_new RENAME TO share_tokens');
}

/**
 * Apply schema migrations to an opened vault SQLite.
 *
 * Ordering matters — additive ALTER TABLE first, then the variant-drop
 * rebuild (so the rebuilt table inherits the Phase-3b bundle columns).
 *
 * `primaryProviderId` is used to backfill rows that pre-date `provider_id`
 * being a tracked column on files/folders/favorites. SQLite can't add
 * NOT NULL columns to populated tables without a default, so we add the
 * column nullable, backfill with the primary's id, and rely on every
 * subsequent INSERT to set it explicitly (the schema's NOT NULL is on
 * the CREATE TABLE only — pre-existing rows keep flowing).
 */
export function runMigrations(db: Database, primaryProviderId?: string): void {
  // ── files / folders / favorites: provider_id backfill ────────────────────
  // Existing vaults from before R6's per-row provider_id stamping have no
  // such column, so ByoDataProvider.downloadFile reads `undefined` and
  // resolveProvider falls back to the primary — wrong target whenever the
  // file actually lives on a secondary. Add the column and stamp the
  // primary's id on every legacy row. Skipped silently when the caller
  // didn't pass a primary (e.g. tests).
  if (primaryProviderId) {
    backfillProviderIdColumn(db, 'files', primaryProviderId);
    backfillProviderIdColumn(db, 'folders', primaryProviderId);
    backfillProviderIdColumn(db, 'favorites', primaryProviderId);
  }

  addColumn(db, 'share_tokens', 'kind', `TEXT DEFAULT 'file'`);
  addColumn(db, 'share_tokens', 'folder_id', `INTEGER`);
  addColumn(db, 'share_tokens', 'collection_id', `INTEGER`);
  addColumn(db, 'share_tokens', 'total_bytes', `INTEGER`);
  addColumn(db, 'share_tokens', 'blob_count', `INTEGER`);

  if (hasColumn(db, 'share_tokens', 'variant')) {
    dropVariantColumn(db);
  }

  // Recoverable share links: fragment column persists the URL fragment
  // so the user can copy the share link again from Settings after the
  // create-flow modal is dismissed. Added AFTER dropVariantColumn so
  // the rebuilt table picks it up via this ALTER without needing the
  // rebuild SQL to know about it. Backfill is intentionally NULL —
  // shares created before this column existed don't have the key
  // anymore (it was zeroized on create), so they remain copy-only-once.
  addColumn(db, 'share_tokens', 'fragment', `TEXT`);

  // Display surface for the share row in Settings:
  //   - bundle_kind   — finer than `kind`; lets the UI render Folder+File
  //                     badges for mixed bundles which ride the 'folder'
  //                     wire kind.
  //   - label         — user-supplied display name; same on both ends
  //                     (creator's Settings + recipient's landing page).
  // Vault-only columns; never sent to the relay.
  addColumn(db, 'share_tokens', 'bundle_kind', `TEXT`);
  addColumn(db, 'share_tokens', 'label', `TEXT`);
}

/** Add the provider_id column if missing, then UPDATE WHERE provider_id IS NULL
 *  to stamp legacy rows with the vault's primary id. No-op when the column
 *  already exists and every row is populated. */
function backfillProviderIdColumn(db: Database, table: string, primaryId: string): void {
  if (!hasColumn(db, table, 'provider_id')) {
    db.run(`ALTER TABLE ${table} ADD COLUMN provider_id TEXT`);
  }
  db.run(`UPDATE ${table} SET provider_id = ? WHERE provider_id IS NULL OR provider_id = ''`, [primaryId]);
}

export function providerDisplayName(type: ProviderType): string {
  const names: Partial<Record<ProviderType, string>> = {
    gdrive:   'Google Drive',
    dropbox:  'Dropbox',
    onedrive: 'OneDrive',
    webdav:   'WebDAV',
    sftp:     'SFTP',
    box:      'Box',
    pcloud:   'pCloud',
    s3:       'S3',
  };
  return names[type] ?? type;
}
