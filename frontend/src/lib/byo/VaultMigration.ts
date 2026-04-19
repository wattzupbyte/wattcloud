/**
 * BYO Vault SQLite Migrations (R6+)
 *
 * R6 is a greenfield reset: the app is pre-production, so all M1–M5 migration
 * code has been removed. New vaults are created with the R6 schema
 * (provider_id NOT NULL, cross-provider triggers, no providers/provider_config tables).
 *
 * runMigrations() is a no-op kept for call-site compatibility.
 */

import type { ProviderType } from '@secure-cloud/byo';

/**
 * No-op for R6 greenfield vaults. Kept for call-site compatibility.
 * Any future schema changes to existing vaults would go here.
 */
export function runMigrations(_db: import('sql.js').Database): void {
  // Greenfield reset — no migrations needed.
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
