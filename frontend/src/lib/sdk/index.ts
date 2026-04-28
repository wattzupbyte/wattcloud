/**
 * @wattcloud/sdk — BYO Storage Provider library
 *
 * Self-contained package for Bring Your Own Storage mode.
 * Depends only on sdk-wasm (loaded by the BYO Web Worker).
 * No imports from /frontend/ — fully independent.
 *
 * Key modules:
 *   - types: StorageProvider interface, ProviderConfig, StorageEntry
 *   - errors: ProviderError, ConflictError, UnauthorizedError
 *   - ProviderFactory: create, initialize, cache, clear providers
 *   - worker: BYO's own Web Worker + client (V7 streaming, vault ops)
 *   - streaming: UploadStream, DownloadStream
 *   - providers: GDrive, Dropbox, OneDrive, WebDAV, SFTP
 *   - oauth: PKCE, OAuthConfig, OAuthFlow
 */

// Core types and errors
export type {
  ProviderType,
  StorageEntry,
  UploadOptions,
  UploadResult,
  ProviderConfig,
  StorageProvider,
} from './types';

export { ProviderError, ConflictError, UnauthorizedError } from './errors';

// Provider factory
export {
  createProvider,
  initializeProvider,
  getProvider,
  registerProvider,
  clearProvider,
  clearAllProviders,
  getDisplayName,
} from './ProviderFactory';

// Storage providers (P8: HTTP classes retired; all backed by WasmStorageProviderShim)
export {
  SftpProvider,         // WebSocket transport wrapper (not HTTP)
  WasmStorageProviderShim,  // generic WASM shim for all HTTP providers (gdrive/dropbox/onedrive/webdav/box/pcloud/s3)
} from './providers';

// Streaming adapters
export { ByoUploadStream } from './streaming/UploadStream';
export { ByoDownloadStream } from './streaming/DownloadStream';
export { createZipStream, predictZipLength, type ZipEntry } from './streaming/zip';

// OAuth
export { generatePKCE, base64URLEncode, type PKCEPair } from './oauth/PKCE';
export { OAUTH_CONFIGS, validateOAuthConfig, type OAuthProviderConfig } from './oauth/OAuthConfig';
export { initiateOAuthFlow, refreshAccessToken, type OAuthResult } from './oauth/OAuthFlow';

// Runtime config (fetched from /config.json at SPA boot).
export {
  initRuntimeConfig,
  getRuntimeConfig,
  validateRuntimeConfig,
  type WattcloudRuntimeConfig,
} from './runtimeConfig';

// Relay auth (PoW-gated cookie acquisition for WS connections)
export {
  acquireRelayCookie,
  acquireSftpRelayCookie,
  acquireEnrollmentRelayCookie,
  evictRelayCookieCache,
  evictSftpRelayCookieCache,
  evictEnrollmentRelayCookieCache,
} from './relay/RelayAuth';

// Worker client (for direct access if needed)
export * as Worker from './worker/byoWorkerClient';

// Stats client
export { initStatsClient, recordEvent, classifyErr, bucketLog2, addShareRelayBandwidth, getShareRelayBandwidthAndReset } from './stats/StatsClient';
export type { StatsPayload } from './stats/StatsClient';

// Test-only: MockProvider for E2E testing.
// Tree-shaken from production builds when __BYO_TEST_MODE__ is false.
export { MockProvider } from './providers/MockProvider';