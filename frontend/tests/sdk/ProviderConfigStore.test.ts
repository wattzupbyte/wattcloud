import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';

import {
  setDeviceCryptoKey,
  deleteDeviceCryptoKey,
  generateDeviceCryptoKey,
} from '../../src/lib/byo/DeviceKeyStore';
import {
  saveProviderConfig,
  loadProvidersForVault,
  listAllProviderMetas,
  listPersistedVaults,
  deleteProviderConfig,
  deleteVaultProviderConfigs,
  clearAllProviderConfigs,
  renameVaultLabel,
  type ProviderConfigMeta,
} from '../../src/lib/byo/ProviderConfigStore';
import type { ProviderConfig } from '../../src/lib/sdk/types';

const VAULT_A = 'aa'.repeat(16);
const VAULT_B = 'bb'.repeat(16);

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

describe('ProviderConfigStore', () => {
  beforeEach(async () => {
    // fake-indexeddb persists across tests in the same process; wipe between.
    // Use structuredClone safety: just nuke by API.
    await clearAllProviderConfigs().catch(() => {});
    await deleteDeviceCryptoKey(VAULT_A).catch(() => {});
    await deleteDeviceCryptoKey(VAULT_B).catch(() => {});
    await generateDeviceCryptoKey(VAULT_A);
    await generateDeviceCryptoKey(VAULT_B);
  });

  it('round-trips a saved provider config', async () => {
    const meta = makeMeta({});
    await saveProviderConfig(meta, SAMPLE_CONFIG);

    const { hydrated, failed } = await loadProvidersForVault(VAULT_A);
    expect(hydrated.length).toBe(1);
    expect(hydrated[0]!.provider_id).toBe(meta.provider_id);
    expect(hydrated[0]!.config).toEqual(SAMPLE_CONFIG);
    expect(failed).toEqual([]);
  });

  it('lists metas without decrypting', async () => {
    const meta = makeMeta({ vault_label: 'Personal' });
    await saveProviderConfig(meta, SAMPLE_CONFIG);

    const metas = await listAllProviderMetas();
    expect(metas.length).toBe(1);
    expect(metas[0]!.vault_label).toBe('Personal');
    // Ensure the wrapped payload fields don't leak into the meta shape.
    expect(metas[0]).not.toHaveProperty('iv');
    expect(metas[0]).not.toHaveProperty('wrapped_config');
  });

  it('groups multiple providers per vault and flags the primary', async () => {
    await saveProviderConfig(
      makeMeta({ is_primary: true, display_name: 'Hetzner' }),
      SAMPLE_CONFIG,
    );
    await saveProviderConfig(
      makeMeta({ is_primary: false, display_name: 'Dropbox', type: 'dropbox' }),
      { type: 'dropbox', accessToken: 'tok', refreshToken: 'rt', tokenExpiry: 0 },
    );

    const vaults = await listPersistedVaults();
    expect(vaults.length).toBe(1);
    expect(vaults[0]!.vault_id).toBe(VAULT_A);
    expect(vaults[0]!.providers.length).toBe(2);
    expect(vaults[0]!.primary.display_name).toBe('Hetzner');
  });

  it('separates vaults from each other', async () => {
    await saveProviderConfig(makeMeta({ vault_id: VAULT_A }), SAMPLE_CONFIG);
    await saveProviderConfig(
      makeMeta({ vault_id: VAULT_B, vault_label: 'Work' }),
      SAMPLE_CONFIG,
    );

    const vaults = await listPersistedVaults();
    expect(vaults.length).toBe(2);
    expect(new Set(vaults.map((v) => v.vault_id))).toEqual(new Set([VAULT_A, VAULT_B]));
  });

  it('skips rows whose device key is missing (different vault context)', async () => {
    const meta = makeMeta({ vault_id: VAULT_A });
    await saveProviderConfig(meta, SAMPLE_CONFIG);

    // Delete the device key so decrypt is impossible.
    await deleteDeviceCryptoKey(VAULT_A);

    const { hydrated, failed } = await loadProvidersForVault(VAULT_A);
    // With no key, nothing decrypts — but the stored rows still surface
    // under `failed` so the UI can offer a self-heal.
    expect(hydrated).toEqual([]);
    expect(failed.length).toBe(1);
    expect(failed[0]!.provider_id).toBe(meta.provider_id);
  });

  it('fails to decrypt a row wrapped with a different vault key', async () => {
    // Save under vault A, then simulate a stale row pointing at vault A but
    // wrapped with vault B's key. Round-tripping real AES-GCM: manually swap
    // the device key on the vault_id axis and confirm the row is skipped.
    const meta = makeMeta({ vault_id: VAULT_A });
    await saveProviderConfig(meta, SAMPLE_CONFIG);

    // Replace VAULT_A's key with a brand-new one (previous IV+ct won't verify).
    await deleteDeviceCryptoKey(VAULT_A);
    await generateDeviceCryptoKey(VAULT_A);

    const { hydrated, failed } = await loadProvidersForVault(VAULT_A);
    // Decrypt fails under the new key; the row shows up in `failed` so
    // the caller can distinguish "no rows" from "rows we can't unwrap".
    expect(hydrated).toEqual([]);
    expect(failed.length).toBe(1);
  });

  it('splits rows into hydrated + failed when only some predate a key swap', async () => {
    // Simulate a partial migration: one row wrapped under K1, then the
    // device key rotates to K2, then a second row is saved under K2. The
    // loader must decrypt the K2 row and surface the K1 row as failed.
    const metaK1 = makeMeta({ provider_id: crypto.randomUUID() });
    await saveProviderConfig(metaK1, SAMPLE_CONFIG);

    await deleteDeviceCryptoKey(VAULT_A);
    await generateDeviceCryptoKey(VAULT_A);

    const metaK2 = makeMeta({ provider_id: crypto.randomUUID() });
    await saveProviderConfig(metaK2, SAMPLE_CONFIG);

    const { hydrated, failed } = await loadProvidersForVault(VAULT_A);
    expect(hydrated.map((r) => r.provider_id)).toEqual([metaK2.provider_id]);
    expect(failed.map((r) => r.provider_id)).toEqual([metaK1.provider_id]);
  });

  it('deletes a single row via deleteProviderConfig', async () => {
    const meta1 = makeMeta({});
    const meta2 = makeMeta({});
    await saveProviderConfig(meta1, SAMPLE_CONFIG);
    await saveProviderConfig(meta2, SAMPLE_CONFIG);

    await deleteProviderConfig(meta1.provider_id);

    const remaining = await listAllProviderMetas();
    expect(remaining.length).toBe(1);
    expect(remaining[0]!.provider_id).toBe(meta2.provider_id);
  });

  it('deletes all rows for a vault via deleteVaultProviderConfigs', async () => {
    await saveProviderConfig(makeMeta({ vault_id: VAULT_A }), SAMPLE_CONFIG);
    await saveProviderConfig(makeMeta({ vault_id: VAULT_A }), SAMPLE_CONFIG);
    await saveProviderConfig(makeMeta({ vault_id: VAULT_B }), SAMPLE_CONFIG);

    await deleteVaultProviderConfigs(VAULT_A);

    const remaining = await listAllProviderMetas();
    expect(remaining.length).toBe(1);
    expect(remaining[0]!.vault_id).toBe(VAULT_B);
  });

  it('renames a vault label across every row sharing its vault_id', async () => {
    const m1 = makeMeta({ vault_id: VAULT_A, vault_label: 'Old' });
    const m2 = makeMeta({ vault_id: VAULT_A, vault_label: 'Old' });
    await saveProviderConfig(m1, SAMPLE_CONFIG);
    await saveProviderConfig(m2, SAMPLE_CONFIG);

    await renameVaultLabel(VAULT_A, 'New Personal');

    const metas = await listAllProviderMetas();
    expect(metas.every((m) => m.vault_label === 'New Personal')).toBe(true);
  });
});
