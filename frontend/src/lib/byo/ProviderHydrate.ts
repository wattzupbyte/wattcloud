/**
 * ProviderHydrate — re-materialize a StorageProvider instance from a
 * persisted ProviderConfig (IDB wrapped). Mirrors the inline submit flow
 * in AddProviderSheet, minus the user-facing form.
 *
 * SFTP credentials ride inside the ProviderConfig alongside host/port/basePath
 * for parity with OAuth tokens and WebDAV passwords — see SECURITY.md §12
 * "Credential Handling (BYO)" for the storage layers and threat model.
 * Legacy vaults whose manifest predates the credential change fall back to
 * the `SftpReauthSheet`: `providerNeedsReauth(config)` is true iff SFTP *and*
 * no password/privateKey is stored, and after a successful reauth the caller
 * writes the freshly-entered creds back to `ProviderConfigStore` so the next
 * reload skips the sheet.
 */

import {
  createProvider,
  SftpProvider,
  type StorageProvider,
  type ProviderConfig,
} from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';

export interface SftpCredentials {
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

/**
 * True when a persisted config cannot reconnect on its own because the
 * secret is missing (legacy SFTP vaults written before credentials were
 * persisted in the config). New SFTP vaults include `sftpPassword` or
 * `sftpPrivateKey` in the config and do NOT need the reauth sheet.
 */
export function providerNeedsReauth(config: ProviderConfig): boolean {
  if (config.type !== 'sftp') return false;
  return !config.sftpPassword && !config.sftpPrivateKey;
}

export async function hydrateProvider(
  config: ProviderConfig,
  creds?: SftpCredentials,
): Promise<StorageProvider> {
  const instance = createProvider(config.type);

  if (instance instanceof SftpProvider) {
    const password = creds?.password ?? config.sftpPassword ?? undefined;
    const privateKey = creds?.privateKey ?? config.sftpPrivateKey ?? undefined;
    const passphrase = creds?.passphrase ?? config.sftpPassphrase ?? undefined;
    if (!password && !privateKey) {
      throw new Error(
        'SFTP credentials required: this vault was persisted without a saved password or private key. Re-enter them to unlock.',
      );
    }
    const credHandle = await byoWorker.Worker.sftpStoreCredential(
      password,
      privateKey,
      passphrase,
    );
    instance.credHandle = credHandle;
    instance.credUsername = config.sftpUsername || '';

    // First-connect hook: if the stored fingerprint doesn't match the
    // server's, the provider rejects. For hydrate we assume the stored
    // fingerprint is authoritative; if absent, accept TOFU silently
    // (matches the existing behavior when the vault manifest carries the
    // fingerprint across reloads).
    instance.onFirstHostKey = async () => true;
  }

  await instance.init(config);
  return instance;
}
