import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';

import {
  deleteDeviceCryptoKey,
  generateDeviceCryptoKey,
  readRawDeviceCryptoKey,
  setDeviceRecord,
  deleteDeviceRecord,
} from '../../src/lib/byo/DeviceKeyStore';
import {
  saveProviderConfig,
  loadProvidersForVault,
  clearAllProviderConfigs,
  type ProviderConfigMeta,
} from '../../src/lib/byo/ProviderConfigStore';
import { migrateDeviceKey } from '../../src/lib/byo/DeviceKeyMigration';
import type { ProviderConfig } from '../../src/lib/sdk/types';
import { MockProvider } from './mocks/MockProvider';

const VAULT_A = 'aa'.repeat(16);

function makeMeta(overrides: Partial<ProviderConfigMeta>): ProviderConfigMeta {
  return {
    provider_id: crypto.randomUUID(),
    vault_id: VAULT_A,
    vault_label: 'Personal',
    type: 'sftp',
    display_name: 'Hetzner',
    is_primary: true,
    saved_at: new Date().toISOString(),
    ...overrides,
  };
}

const SAMPLE_CONFIG: ProviderConfig = {
  type: 'sftp',
  sftpHost: 'u12345.your-storagebox.de',
  sftpPort: 22,
  sftpUsername: 'u12345',
  sftpBasePath: '/wattcloud',
};

describe('migrateDeviceKey — atomic provider_configs rewrap', () => {
  beforeEach(async () => {
    await clearAllProviderConfigs().catch(() => {});
    await deleteDeviceCryptoKey(VAULT_A).catch(() => {});
    await deleteDeviceRecord(VAULT_A).catch(() => {});
  });

  it('reverts every provider_configs row when the remote manifest step fails', async () => {
    const oldKey = await generateDeviceCryptoKey(VAULT_A);
    // Two rows (different provider_ids) both wrapped under oldKey.
    await saveProviderConfig(makeMeta({ provider_id: crypto.randomUUID() }), SAMPLE_CONFIG);
    await saveProviderConfig(makeMeta({ provider_id: crypto.randomUUID() }), SAMPLE_CONFIG);

    const newKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );

    // No device record → rewrapShardInManifest throws immediately,
    // AFTER rewrapAllProviderConfigs has already committed under newKey.
    // The revert path must put the originals back.
    await expect(
      migrateDeviceKey({
        vaultId: VAULT_A,
        provider: new MockProvider(),
        oldKey,
        newKey,
        vaultSessionId: 0,
      }),
    ).rejects.toThrow(/no device record/);

    // loadProvidersForVault uses whatever is in device_crypto_keys — still
    // oldKey. If the revert worked, both rows decrypt cleanly.
    const { hydrated, failed } = await loadProvidersForVault(VAULT_A);
    expect(hydrated.length).toBe(2);
    expect(hydrated.every((r) => r.config.type === 'sftp')).toBe(true);
    expect(failed).toEqual([]);
  });

  it('leaves IDB untouched when the oldKey cannot decrypt existing rows', async () => {
    // Simulate a caller that passes the wrong oldKey. Prep phase (decrypt)
    // throws before any IDB write — the stored rows must be byte-identical
    // to what was there before the call.
    const realKey = await generateDeviceCryptoKey(VAULT_A);
    const row = makeMeta({ provider_id: crypto.randomUUID() });
    await saveProviderConfig(row, SAMPLE_CONFIG);

    const wrongOldKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const newKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );

    await expect(
      migrateDeviceKey({
        vaultId: VAULT_A,
        provider: new MockProvider(),
        oldKey: wrongOldKey,
        newKey,
        vaultSessionId: 0,
      }),
    ).rejects.toThrow();

    // Original row still decrypts under the real key that's in IDB.
    const storedKey = await readRawDeviceCryptoKey(VAULT_A);
    expect(storedKey).toBeTruthy();
    const { hydrated } = await loadProvidersForVault(VAULT_A);
    expect(hydrated.length).toBe(1);
    expect(hydrated[0]!.provider_id).toBe(row.provider_id);
    // Silence unused-binding warnings for the two keys held for clarity.
    void realKey;
  });
});
