/**
 * ProviderHydrate — re-materialize a StorageProvider instance from a
 * persisted ProviderConfig (IDB wrapped). Mirrors the inline submit flow
 * in AddProviderSheet, minus the user-facing form.
 *
 * Provider credentials ride inside the ProviderConfig alongside host/url/etc.
 * for parity across SFTP password / private key, WebDAV password, S3 access
 * keys, and OAuth refresh tokens — see SECURITY.md §12 "Credential Handling
 * (BYO)" for the storage layers and threat model. Legacy vaults whose
 * manifest predates the credential change fall back to the
 * `ProviderReauthSheet`: `providerNeedsReauth(config)` is true iff the
 * stored config is missing the secret needed to reconnect, and after a
 * successful reauth the caller writes the freshly-entered creds back to
 * `ProviderConfigStore` so the next reload skips the sheet.
 */

import {
  createProvider,
  SftpProvider,
  type StorageProvider,
  type ProviderConfig,
} from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';

/**
 * Generic credential bundle collected by `ProviderReauthSheet`. Only the
 * fields relevant to `config.type` are populated — the others are ignored
 * by `hydrateProvider`.
 */
export interface ProviderCredentials {
  // SFTP
  password?: string;
  privateKey?: string;
  passphrase?: string;
  // S3-family
  accessKeyId?: string;
  secretAccessKey?: string;
}

/** @deprecated Use `ProviderCredentials`. Retained for source-level compatibility. */
export type SftpCredentials = ProviderCredentials;

/**
 * True when a persisted config cannot reconnect on its own because the
 * secret is missing (legacy vaults written before credentials were
 * persisted in the config). New vaults include the secret in the config
 * and do NOT need the reauth sheet.
 */
export function providerNeedsReauth(config: ProviderConfig): boolean {
  switch (config.type) {
    case 'sftp':
      return !config.sftpPassword && !config.sftpPrivateKey;
    case 'webdav':
      return !config.password;
    case 's3':
      return !config.s3AccessKeyId || !config.s3SecretAccessKey;
    default:
      return false;
  }
}

export async function hydrateProvider(
  config: ProviderConfig,
  creds?: ProviderCredentials,
): Promise<StorageProvider> {
  // Pass providerId through so the factory's cache slot is keyed by id, not
  // by the type-only `'<type>:primary'` fallback. Without this the cache
  // would hand a sibling provider's already-init'd instance back to us, and
  // our subsequent init(config) call would mutate that shared object's
  // host/basePath in place — silently swapping the OTHER provider's storage
  // target. See ProviderFactory.createProvider for the full failure mode.
  const instance = createProvider(config.type, config.providerId);

  // Splice freshly-typed creds back into the config for providers whose
  // init() reads the secret directly from ProviderConfig (WebDAV, S3).
  let effectiveConfig = config;
  if (creds) {
    if (config.type === 'webdav' && creds.password !== undefined) {
      effectiveConfig = { ...config, password: creds.password };
    } else if (config.type === 's3') {
      const patch: Partial<ProviderConfig> = {};
      if (creds.accessKeyId !== undefined) patch.s3AccessKeyId = creds.accessKeyId;
      if (creds.secretAccessKey !== undefined) patch.s3SecretAccessKey = creds.secretAccessKey;
      if (Object.keys(patch).length > 0) effectiveConfig = { ...config, ...patch };
    }
  }

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
    instance.credUsername = effectiveConfig.sftpUsername || '';

    // First-connect hook: if the stored fingerprint doesn't match the
    // server's, the provider rejects. For hydrate we assume the stored
    // fingerprint is authoritative; if absent, accept TOFU silently
    // (matches the existing behavior when the vault manifest carries the
    // fingerprint across reloads).
    instance.onFirstHostKey = async () => true;
  }

  await instance.init(effectiveConfig);
  return instance;
}
