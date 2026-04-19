/**
 * Provider factory for creating and caching BYO storage providers.
 *
 * P8: All providers (except SFTP) are now WASM-backed via WasmStorageProviderShim.
 * SFTP uses its own thin WebSocket transport wrapper (SftpProvider).
 * S3 uses WasmS3Provider (introduced in P11, kept for backward-compatibility;
 * functionally equivalent to WasmStorageProviderShim for 's3').
 *
 * Caches provider instances by provider_id. Multiple instances of the same
 * type are supported (e.g. two GDrive accounts with different provider_ids).
 */

import type { StorageProvider, ProviderType, ProviderConfig } from './types';
import { WasmStorageProviderShim } from './providers/WasmStorageProviderShim';
import { SftpProvider } from './providers/SftpProvider';

function makeProvider(type: ProviderType): StorageProvider {
  if (type === 'sftp') return new SftpProvider();
  return new WasmStorageProviderShim(type);
}

/** Cache keyed by provider_id (stable identifier, not type). Multiple instances
 *  of the same provider type are supported (e.g. two GDrive accounts). */
const providerInstances = new Map<string, StorageProvider>();

/**
 * Create or return a cached provider instance keyed by provider_id.
 * Falls back to type-only key ('primary') when no provider_id is supplied,
 * preserving backward-compatibility with single-provider vaults.
 */
export function createProvider(type: ProviderType, providerId?: string): StorageProvider {
  const key = `${type}:${providerId ?? 'primary'}`;
  const existing = providerInstances.get(key);
  if (existing?.isReady()) return existing;

  const instance = makeProvider(type);
  providerInstances.set(key, instance);
  return instance;
}

/** Create and initialize a provider with saved config. */
export async function initializeProvider(
  type: ProviderType,
  savedConfig?: ProviderConfig,
): Promise<StorageProvider> {
  const provider = createProvider(type, savedConfig?.providerId);
  await provider.init(savedConfig);
  return provider;
}

/**
 * Get a cached provider instance by provider_id (may not be initialized).
 * Accepts either the full `type:id` cache key or a bare provider_id (suffix match).
 */
export function getProvider(providerId: string): StorageProvider | undefined {
  const direct = providerInstances.get(providerId);
  if (direct) return direct;
  // Fallback: scan for a key whose suffix matches `:${providerId}`
  const suffix = `:${providerId}`;
  for (const [key, val] of providerInstances) {
    if (key.endsWith(suffix)) return val;
  }
  return undefined;
}

/** Register an already-initialized provider instance under a given provider_id. */
export function registerProvider(providerId: string, instance: StorageProvider): void {
  providerInstances.set(providerId, instance);
}

/**
 * Disconnect and remove a cached provider instance by provider_id.
 * Accepts either the full `type:id` cache key or a bare provider_id (suffix match).
 */
export async function clearProvider(providerId: string): Promise<void> {
  let key = providerInstances.has(providerId) ? providerId : null;
  if (!key) {
    const suffix = `:${providerId}`;
    for (const k of providerInstances.keys()) {
      if (k.endsWith(suffix)) { key = k; break; }
    }
  }
  if (key) {
    await providerInstances.get(key)!.disconnect();
    providerInstances.delete(key);
  }
}

/** Disconnect and remove all cached provider instances. */
export async function clearAllProviders(): Promise<void> {
  for (const provider of providerInstances.values()) {
    await provider.disconnect();
  }
  providerInstances.clear();
}

/** Get the display name for a provider type. */
export function getDisplayName(type: ProviderType): string {
  return makeProvider(type).displayName;
}
