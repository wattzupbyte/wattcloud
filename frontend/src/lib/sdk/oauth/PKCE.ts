/**
 * PKCE (Proof Key for Code Exchange) — RFC 7636.
 *
 * generatePKCE() is a thin wrapper over sdk-core's Rust implementation,
 * executed in the BYO Web Worker. The Rust implementation uses OsRng for
 * entropy and SHA-256 for the challenge digest — the same code path used on
 * Android via sdk-ffi.
 *
 * base64URLEncode() is a pure TS utility kept for backwards-compatibility
 * with callers that import it directly.
 */

import { generatePkce as workerGeneratePkce, initByoWorker } from '../worker/byoWorkerClient';

export interface PKCEPair {
  /** URL-safe base64 (no padding) code verifier — 43 chars */
  codeVerifier: string;
  /** SHA-256(codeVerifier), base64url-encoded (no padding) */
  codeChallenge: string;
}

/**
 * Generate a PKCE code verifier and SHA-256 challenge via the BYO Web Worker.
 * Entropy: OsRng in Rust (equivalent to crypto.getRandomValues in the browser).
 */
export async function generatePKCE(): Promise<PKCEPair> {
  await initByoWorker();
  return workerGeneratePkce();
}

/**
 * Base64url-encode a byte array (no padding) per RFC 7636 §Appendix B.
 *
 * Kept for backwards-compatibility. Prefer the Rust implementation via
 * generatePKCE() for security-sensitive use-cases.
 */
export function base64URLEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
