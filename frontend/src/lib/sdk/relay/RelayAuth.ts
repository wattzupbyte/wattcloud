/**
 * Relay auth handshake — acquires a purpose-scoped, PoW-gated relay cookie.
 *
 * Protocol (per cookie):
 *   1. GET /relay/auth/challenge?purpose=<purpose>  →  { nonce_id, nonce, difficulty }
 *   2. Worker solves sha256(nonce_raw || purpose || answer_le64) with ≥difficulty leading zero bits
 *   3. POST /relay/auth { nonce_id, answer }  →  204 + Set-Cookie: relay_auth=<jwt>; HttpOnly
 *
 * Per-purpose in-memory cache: a cookie acquired for a given purpose is cached
 * until it expires (matching the server's RELAY_COOKIE_TTL_SECS, default 600 s).
 * Consecutive reconnects to the same host skip the PoW work within the window.
 *
 * The cookie is HttpOnly — JS never sees its value. The browser attaches it
 * automatically on subsequent same-origin WS upgrades to /relay/ws.
 */

import * as Worker from '../worker/byoWorkerClient';

// Server TTL is 600 s; cache expires a full minute early so an ahead-of-server
// client clock can drift up to ~60 s without the next WS upgrade eating a 401
// before we evict the entry. C11: the previous 570_000 (30 s buffer) left a
// narrow window where a slightly-fast client kept using a server-expired cookie.
const CACHE_TTL_MS = 540_000; // 9 minutes

interface CacheEntry {
  expiresAt: number; // Date.now() + CACHE_TTL_MS
}

// Per-purpose cache: purpose string → expiry timestamp.
const cookieCache = new Map<string, CacheEntry>();

// In-flight dedup: if two callers race for the same purpose, coalesce into one PoW handshake.
const pendingByPurpose = new Map<string, Promise<void>>();

/**
 * Ensure a valid relay_auth cookie exists for the given purpose.
 *
 * If a cookie was acquired for this purpose within the last 9.5 minutes,
 * this is a no-op (the browser holds the cookie). Otherwise, executes the
 * full challenge → PoW → POST handshake.
 *
 * @param purpose - "sftp:<hex>" or "enroll:<channelId>"
 * @throws if the server returns an unexpected error or the worker fails
 */
export function acquireRelayCookie(purpose: string): Promise<void> {
  const cached = cookieCache.get(purpose);
  if (cached && Date.now() < cached.expiresAt) {
    return Promise.resolve(); // Cache hit — existing cookie is still valid.
  }

  // Coalesce concurrent callers for the same purpose into one handshake.
  const existing = pendingByPurpose.get(purpose);
  if (existing) return existing;

  const handshake = _doAcquire(purpose).finally(() => pendingByPurpose.delete(purpose));
  pendingByPurpose.set(purpose, handshake);
  return handshake;
}

async function _doAcquire(purpose: string): Promise<void> {
  // Ensure the worker (and WASM) is ready.
  await Worker.initByoWorker();

  // Step 1: fetch challenge.
  const challengeResp = await fetch(
    `/relay/auth/challenge?purpose=${encodeURIComponent(purpose)}`,
    { method: 'GET', credentials: 'same-origin' },
  );

  if (!challengeResp.ok) {
    throw new Error(
      `Relay challenge failed: ${challengeResp.status} ${challengeResp.statusText}`,
    );
  }

  const { nonce_id, nonce, difficulty } = (await challengeResp.json()) as {
    nonce_id: string;
    nonce: string;
    difficulty: number;
  };

  // Step 2: solve PoW in the worker (non-blocking for main thread).
  const { answer } = await Worker.byoSolveRelayPow(nonce, purpose, difficulty);

  // Step 3: submit answer — server sets the relay_auth HttpOnly cookie.
  const authResp = await fetch('/relay/auth', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce_id, answer }),
  });

  if (!authResp.ok) {
    throw new Error(
      `Relay auth failed: ${authResp.status} ${authResp.statusText}`,
    );
  }

  // Cache the acquisition so repeated reconnects within the cookie TTL skip PoW.
  cookieCache.set(purpose, { expiresAt: Date.now() + CACHE_TTL_MS });
}

/**
 * Derive and acquire a relay cookie scoped to the given SFTP host and port.
 * Convenience wrapper around acquireRelayCookie + byoDeriveSftpPurpose.
 */
export async function acquireSftpRelayCookie(host: string, port: number): Promise<void> {
  await Worker.initByoWorker();
  const purpose = await Worker.byoDeriveSftpPurpose(host, port);
  return acquireRelayCookie(purpose);
}

/**
 * Derive and acquire a relay cookie scoped to the given enrollment channel.
 * Convenience wrapper around acquireRelayCookie + byoDeriveEnrollmentPurpose.
 */
export async function acquireEnrollmentRelayCookie(channelId: string): Promise<void> {
  await Worker.initByoWorker();
  const purpose = await Worker.byoDeriveEnrollmentPurpose(channelId);
  return acquireRelayCookie(purpose);
}

/** Evict the cached entry for a purpose (e.g. on 401/403 from WS upgrade). */
export function evictRelayCookieCache(purpose: string): void {
  cookieCache.delete(purpose);
}

/**
 * Evict the cached relay cookie for an SFTP host:port.
 * Call this on WS upgrade failure (onerror/close) before retrying,
 * so the next attempt re-acquires a fresh cookie.
 */
export async function evictSftpRelayCookieCache(host: string, port: number): Promise<void> {
  await Worker.initByoWorker();
  const purpose = await Worker.byoDeriveSftpPurpose(host, port);
  evictRelayCookieCache(purpose);
}

/**
 * Evict the cached relay cookie for an enrollment channel.
 * Call this on WS upgrade failure before retrying.
 */
export async function evictEnrollmentRelayCookieCache(channelId: string): Promise<void> {
  await Worker.initByoWorker();
  const purpose = await Worker.byoDeriveEnrollmentPurpose(channelId);
  evictRelayCookieCache(purpose);
}
