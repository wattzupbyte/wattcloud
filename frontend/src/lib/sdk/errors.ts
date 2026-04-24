/**
 * BYO Provider error hierarchy.
 *
 * Follows the same discriminated-union pattern as frontend/src/lib/errors.ts.
 * ProviderError is the base; ConflictError and UnauthorizedError are specific
 * subclasses used for merge-based conflict resolution and re-auth flows.
 */

import type { ProviderType } from './types';

// ── Error codes ────────────────────────────────────────────────────────────

export type ProviderErrorCode =
  | 'CONFLICT'            // ETag/rev mismatch — version conflict
  | 'NOT_FOUND'          // File or folder not found
  | 'UNAUTHORIZED'       // Auth expired, needs re-auth
  | 'FORBIDDEN'          // Insufficient permissions
  | 'RATE_LIMITED'       // Provider rate limit hit
  | 'NETWORK_ERROR'      // Connection failed, timeout, offline
  | 'PROVIDER_ERROR'     // Generic provider error
  | 'INVALID_RESPONSE'   // Malformed response from provider
  | 'SFTP_RELAY_ERROR'    // SFTP relay connection failed
  | 'WEBDAV_CONFIG_ERROR' // WebDAV configuration invalid (e.g. non-HTTPS URL)
  | 'UNSUPPORTED'         // Operation not supported (e.g. oversized cross-provider move)
  | 'INSUFFICIENT_SPACE'; // Destination storage reports it can't hold the upload

// ── ProviderError (base) ────────────────────────────────────────────────────

export class ProviderError extends Error {
  constructor(
    public readonly code: ProviderErrorCode,
    message: string,
    public readonly providerType: ProviderType,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

// ── ConflictError ───────────────────────────────────────────────────────────
//
// Thrown on ETag/rev mismatch during vault upload. The caller uses
// currentVersion to perform merge-based conflict resolution (BYO_PLAN §4.4):
// download remote vault + journal, merge with local, re-upload.

export class ConflictError extends ProviderError {
  /** The current version on the provider (ETag, rev, mtime:size). */
  public readonly currentVersion: string;

  constructor(providerType: ProviderType, currentVersion: string) {
    super(
      'CONFLICT',
      `Version conflict. Current version: ${currentVersion}`,
      providerType,
    );
    this.name = 'ConflictError';
    this.currentVersion = currentVersion;
  }
}

// ── UnauthorizedError ──────────────────────────────────────────────────────
//
// Thrown when an OAuth access token is expired or invalid. The caller should
// attempt refreshAuth() and retry. If refreshAuth() also fails, prompt the
// user to re-authenticate (BYO_PLAN §3.2).

export class UnauthorizedError extends ProviderError {
  constructor(
    providerType: ProviderType,
    message = 'Authentication expired',
  ) {
    super('UNAUTHORIZED', message, providerType);
    this.name = 'UnauthorizedError';
  }
}

// ── InsufficientSpaceError ──────────────────────────────────────────────────
//
// Thrown when an upload would exceed the destination's free space and the
// provider exposes a portable quota query (WebDAV RFC 4331, SFTP
// statvfs@openssh.com). Providers without a portable query don't throw this;
// they surface server errors mid-upload instead.

export class InsufficientSpaceError extends ProviderError {
  public readonly neededBytes: number;
  public readonly availableBytes: number;

  constructor(
    providerType: ProviderType,
    neededBytes: number,
    availableBytes: number,
  ) {
    super(
      'INSUFFICIENT_SPACE',
      `Not enough space on ${providerType}: need ${neededBytes} bytes, ${availableBytes} available`,
      providerType,
    );
    this.name = 'InsufficientSpaceError';
    this.neededBytes = neededBytes;
    this.availableBytes = availableBytes;
  }
}