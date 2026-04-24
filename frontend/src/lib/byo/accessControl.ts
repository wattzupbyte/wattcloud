/**
 * Restricted-enrollment client helpers.
 *
 * Wraps the `/relay/info` + `/relay/admin/*` endpoints from SPEC.md
 * §Access Control. Consumers (main.ts boot, Access Control settings
 * panel, bootstrap/invite screens) import from here rather than calling
 * `fetch` directly so request shapes + error mapping stay consistent.
 *
 * Zero-knowledge posture: none of these calls carry plaintext vault
 * material. They deal exclusively with enrollment metadata (mode,
 * bootstrapped flag, invite codes, device labels, pubkeys).
 */

import * as Worker from '../sdk/worker/byoWorkerClient';

export type EnrollmentMode = 'open' | 'restricted';

export interface RelayInfo {
  mode: EnrollmentMode;
  bootstrapped: boolean;
  version: string;
}

export interface MeDevice {
  device_id: string;
  is_owner: boolean;
  label: string;
}

export interface MeResponse {
  mode: EnrollmentMode;
  device: MeDevice | null;
}

export interface InviteRow {
  id: string;
  label: string;
  issued_by: string;
  created_at: number;
  expires_at: number;
  used_by: string | null;
  used_at: number | null;
}

export interface DeviceRow {
  device_id: string;
  label: string;
  is_owner: boolean;
  created_at: number;
  last_seen_hour: number;
  revoked_at: number | null;
}

export interface InviteCreateResponse {
  id: string;
  code: string;
  label: string;
  expires_at: number;
}

/**
 * Error the handlers throw when the relay returns a non-2xx. The
 * `reason` field mirrors the body the relay sends so callers can
 * branch on it without parsing text (e.g. `invalid_invite` vs
 * `rate_limited`).
 */
export class AccessControlError extends Error {
  status: number;
  reason: string;
  constructor(status: number, reason: string) {
    super(`relay ${status}: ${reason}`);
    this.status = status;
    this.reason = reason;
  }
}

async function readReason(res: Response): Promise<string> {
  try {
    const text = await res.text();
    const trimmed = text.trim();
    return trimmed.length > 0 ? trimmed : res.statusText;
  } catch {
    return res.statusText;
  }
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new AccessControlError(res.status, await readReason(res));
  }
  // 204 No Content (e.g. revoke endpoints) — no body to parse.
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { credentials: 'include' });
  if (!res.ok) {
    throw new AccessControlError(res.status, await readReason(res));
  }
  return res.json() as Promise<T>;
}

async function delJson(url: string): Promise<void> {
  const res = await fetch(url, { method: 'DELETE', credentials: 'include' });
  if (!res.ok) {
    throw new AccessControlError(res.status, await readReason(res));
  }
}

// ── Public endpoints ─────────────────────────────────────────────────────────

/** `GET /relay/info` — no-auth posture probe. */
export function fetchRelayInfo(): Promise<RelayInfo> {
  return getJson<RelayInfo>('/relay/info');
}

/** `GET /relay/admin/me` — identity probe. Always 200; `device` is null in
 *  Open mode or when no valid cookie accompanied the request. */
export function fetchMe(): Promise<MeResponse> {
  return getJson<MeResponse>('/relay/admin/me');
}

// ── PoW for admin claim/redeem ──────────────────────────────────────────────
//
// Same handshake the relay already uses for `/relay/auth`: GET
// `/relay/auth/challenge` to pick up a nonce + difficulty, solve in the
// Web Worker, include `nonce_id + answer` in the POST body. Single-use
// + IP-bound + purpose-bound on the relay side.

type AdminPowPurpose = 'admin:claim' | 'admin:redeem';

async function solveAdminPow(
  purpose: AdminPowPurpose,
): Promise<{ nonce_id: string; answer: number }> {
  await Worker.initByoWorker();
  // Dedicated admin-public challenge endpoint — the generic
  // `/relay/auth/challenge` sits behind the device-cookie middleware
  // and isn't reachable pre-claim. Each admin purpose has its own path
  // so there's no purpose-string injection in the query.
  const path =
    purpose === 'admin:claim'
      ? '/relay/admin/claim/challenge'
      : '/relay/admin/redeem/challenge';
  const res = await fetch(path, { method: 'GET', credentials: 'same-origin' });
  if (!res.ok) {
    throw new AccessControlError(res.status, await readReason(res));
  }
  const { nonce_id, nonce, difficulty } = (await res.json()) as {
    nonce_id: string;
    nonce: string;
    difficulty: number;
  };
  const { answer } = await Worker.byoSolveRelayPow(nonce, purpose, difficulty);
  return { nonce_id, answer };
}

// ── Enrolment flows ──────────────────────────────────────────────────────────

/** `POST /relay/admin/claim` — consume bootstrap token, install first owner. */
export async function claimBootstrap(args: {
  token: string;
  label: string;
  pubkeyB64: string;
}): Promise<{ device_id: string; is_owner: boolean }> {
  const { nonce_id, answer } = await solveAdminPow('admin:claim');
  return postJson('/relay/admin/claim', {
    token: args.token,
    label: args.label,
    pubkey_b64: args.pubkeyB64,
    nonce_id,
    answer,
  });
}

/** `POST /relay/admin/redeem` — consume an invite code. */
export async function redeemInvite(args: {
  code: string;
  label: string;
  pubkeyB64: string;
}): Promise<{ device_id: string; is_owner: boolean }> {
  const { nonce_id, answer } = await solveAdminPow('admin:redeem');
  return postJson('/relay/admin/redeem', {
    code: args.code,
    label: args.label,
    pubkey_b64: args.pubkeyB64,
    nonce_id,
    answer,
  });
}

// ── Owner admin (Access Control panel) ───────────────────────────────────────

/** `POST /relay/admin/invite` — owner mints a new code. */
export function createInvite(args: {
  label: string;
  ttlSecs: number;
}): Promise<InviteCreateResponse> {
  return postJson('/relay/admin/invite', {
    label: args.label,
    ttl_secs: args.ttlSecs,
  });
}

/** `GET /relay/admin/invites` — list all invites (active + consumed). */
export function listInvites(): Promise<InviteRow[]> {
  return getJson<InviteRow[]>('/relay/admin/invites');
}

/** `DELETE /relay/admin/invites/:id` — idempotent revoke. */
export function revokeInvite(id: string): Promise<void> {
  return delJson(`/relay/admin/invites/${encodeURIComponent(id)}`);
}

/** `GET /relay/admin/devices` — list enrolled devices. */
export function listDevices(): Promise<DeviceRow[]> {
  return getJson<DeviceRow[]>('/relay/admin/devices');
}

/** `DELETE /relay/admin/devices/:id` — revoke. Server enforces the last-owner
 *  guard and surfaces a 409 last_owner if violated. */
export function revokeDevice(id: string): Promise<void> {
  return delJson(`/relay/admin/devices/${encodeURIComponent(id)}`);
}

/**
 * `POST /relay/admin/signout` — sign out this browser. Server-side this
 * revokes the device tied to the current cookie, so a leaked cookie can
 * no longer reach the relay. To come back, the user needs a fresh invite
 * from an owner. 409 `last_owner` means the sole owner tried to sign
 * themselves out; recovery is via `wattcloud regenerate-claim-token`.
 */
export function signOut(): Promise<void> {
  return postJson('/relay/admin/signout', {});
}

// ── Local hint: "this browser was enrolled once" ────────────────────────────
//
// Used by main.ts to distinguish a first-time invitee (show plain invite
// entry) from a returning user whose cookie just aged out (show the
// session-expired variant). This is purely a UX hint — the server is the
// authority on actual cookie validity. Wiped on explicit sign-out.

const ENROLLED_HINT_KEY = 'wc_enrolled_once';

export function markEnrolled(): void {
  try {
    localStorage.setItem(ENROLLED_HINT_KEY, '1');
  } catch {
    /* localStorage may be disabled — the hint is best-effort */
  }
}

export function hasEnrolledHint(): boolean {
  try {
    return localStorage.getItem(ENROLLED_HINT_KEY) === '1';
  } catch {
    return false;
  }
}

export function clearEnrolledHint(): void {
  try {
    localStorage.removeItem(ENROLLED_HINT_KEY);
  } catch {
    /* noop */
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Generate a random 32-byte ed25519 placeholder. Phase 2 stores this blob
 * in `authorized_devices.pubkey` but doesn't yet verify signatures with it
 * — reserved for the v1.1 WebAuthn/PRF integration. Until then the
 * value's only role is to populate a NOT NULL UNIQUE column, so fresh
 * random bytes per enrolment are sufficient.
 */
export function generatePubkeyPlaceholder(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Best-effort device label from `navigator.userAgent`. Used as the
 * enrol-time default so invitees can skip typing a label on small
 * screens. Returns something like "Chrome on macOS" or falls back to
 * "Device" on exotic UAs.
 */
export function defaultDeviceLabel(): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  let os = 'Unknown OS';
  if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS|Macintosh/i.test(ua)) os = 'macOS';
  else if (/iPhone|iPad|iOS/i.test(ua)) os = 'iOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Linux/i.test(ua)) os = 'Linux';

  let browser = 'Browser';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\//i.test(ua) || /Opera/i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua)) browser = 'Safari';

  return `${browser} on ${os}`;
}

/**
 * Format an invite code into the canonical 4-4-3 display shape.
 * Input may be lowercased, contain spaces, dashes, or slashes — we
 * strip non-alphanumerics, uppercase, and re-insert two dashes. The
 * server re-normalises so this is purely cosmetic, but it gives the
 * user a consistent appearance as they paste/type.
 */
export function formatInviteCode(raw: string): string {
  const norm = raw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 11);
  if (norm.length <= 4) return norm;
  if (norm.length <= 8) return `${norm.slice(0, 4)}-${norm.slice(4)}`;
  return `${norm.slice(0, 4)}-${norm.slice(4, 8)}-${norm.slice(8)}`;
}

/** Returns true iff `raw` contains exactly 11 alphanumeric chars. */
export function isInviteCodeComplete(raw: string): boolean {
  return raw.replace(/[^A-Z0-9]/gi, '').length === 11;
}

/** Map relay error reasons to friendly copy for the invite entry screen. */
export function friendlyInviteError(err: AccessControlError): string {
  switch (err.reason) {
    case 'invalid_invite':
      return "That invite isn't valid anymore. It may be expired, already used, or typed incorrectly.";
    case 'rate_limited':
      return "Too many attempts. Please try again later.";
    default:
      return err.message;
  }
}

/** Map relay error reasons to friendly copy for the bootstrap claim screen. */
export function friendlyClaimError(err: AccessControlError): string {
  switch (err.reason) {
    case 'invalid_token':
      return "That token isn't valid — it may be mistyped, expired, or already used. Mint a new one with `sudo wattcloud regenerate-claim-token` on your server, then read it with `sudo wattcloud claim-token`.";
    case 'rate_limited':
      return 'Too many attempts. Please try again later.';
    default:
      return err.message;
  }
}
