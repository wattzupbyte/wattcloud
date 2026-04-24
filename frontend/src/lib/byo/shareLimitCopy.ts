/**
 * shareLimitCopy — translate relay abuse-protection 4xx/5xx responses into
 * user-facing copy.
 *
 * The relay emits two headers on every limit-triggered rejection:
 *   - `X-Wattcloud-Reason` — short token (rate-hour, bytes-hour, concurrent, …)
 *   - `Retry-After` — RFC 7231 seconds (where predictable)
 *
 * Any call into /relay/share/* that receives a non-OK response should run it
 * through `parseShareLimitError`. If the reason header is present, wrap
 * the response in a `ShareLimitError` and throw; callers catch via
 * `isShareLimitError` and surface the `.message` via the toast host or
 * an inline banner.
 *
 * Reason tokens must stay in sync with byo-relay/src/share_relay.rs
 * (REASON_* constants). See SECURITY.md §14 for the full table.
 */

export type ShareLimitReason =
  | 'disk-watermark'
  | 'rate-hour'
  | 'rate-day'
  | 'ip-storage-full'
  | 'per-ip-daily-budget'
  | 'too-large'
  | 'bytes-hour'
  | 'concurrent'
  | 'fetch-rate'
  | 'unknown';

/** Severity drives toast icon choice + auto-dismiss vs sticky. */
export type ShareLimitSeverity = 'transient' | 'sticky';

export interface ShareLimitError {
  kind: 'share-limit';
  reason: ShareLimitReason;
  retryAfterSecs: number | null;
  status: number;
  message: string;
  severity: ShareLimitSeverity;
}

export function isShareLimitError(e: unknown): e is ShareLimitError {
  return (
    typeof e === 'object' &&
    e !== null &&
    (e as { kind?: unknown }).kind === 'share-limit'
  );
}

/**
 * If `response` carries an `X-Wattcloud-Reason` header, build a
 * `ShareLimitError` describing it. Returns null otherwise — caller
 * falls back to its existing error-handling (usually generic "failed").
 */
export function parseShareLimitError(response: Response): ShareLimitError | null {
  const reason = response.headers.get('X-Wattcloud-Reason');
  if (!reason) return null;
  const retryAfter = response.headers.get('Retry-After');
  const parsedRetry = retryAfter ? Number.parseInt(retryAfter, 10) : NaN;
  const retryAfterSecs = Number.isFinite(parsedRetry) ? parsedRetry : null;
  const typedReason = isKnownReason(reason) ? reason : 'unknown';
  return {
    kind: 'share-limit',
    reason: typedReason,
    retryAfterSecs,
    status: response.status,
    message: buildMessage(typedReason, retryAfterSecs, response.status),
    severity: severityFor(typedReason),
  };
}

function isKnownReason(s: string): s is ShareLimitReason {
  switch (s) {
    case 'disk-watermark':
    case 'rate-hour':
    case 'rate-day':
    case 'ip-storage-full':
    case 'per-ip-daily-budget':
    case 'too-large':
    case 'bytes-hour':
    case 'concurrent':
    case 'fetch-rate':
      return true;
    default:
      return false;
  }
}

function severityFor(reason: ShareLimitReason): ShareLimitSeverity {
  switch (reason) {
    // These clear on their own within minutes or by revoking old state —
    // a transient toast is enough, no need for a blocking modal.
    case 'concurrent':
    case 'fetch-rate':
    case 'bytes-hour':
    case 'rate-hour':
    case 'disk-watermark':
      return 'transient';
    // These require user action (revoke shares, pick a smaller file,
    // wait a day) — the toast should stick until dismissed.
    case 'rate-day':
    case 'ip-storage-full':
    case 'per-ip-daily-budget':
    case 'too-large':
    case 'unknown':
      return 'sticky';
  }
}

function buildMessage(
  reason: ShareLimitReason,
  retryAfterSecs: number | null,
  status: number,
): string {
  const retryHint = formatRetry(retryAfterSecs);
  switch (reason) {
    case 'disk-watermark':
      return `Wattcloud relay is at capacity. Try again ${retryHint}.`;
    case 'rate-hour':
      return `You've hit the hourly share-creation limit. Try again ${retryHint}.`;
    case 'rate-day':
      return `You've hit the daily share-creation limit. Try again tomorrow.`;
    case 'ip-storage-full':
      return 'Your share storage is full. Revoke old shares to free up space.';
    case 'per-ip-daily-budget':
      return `You've hit today's upload limit. Try again ${retryHint}.`;
    case 'too-large':
      return 'This file is too large to share. Ask an operator to raise the limit, or split the file.';
    case 'bytes-hour':
      return `This share has served too much data this hour. Try again ${retryHint}.`;
    case 'concurrent':
      return 'Another recipient is downloading right now. Try again in a moment.';
    case 'fetch-rate':
      return `Too many requests for this share. Try again ${retryHint}.`;
    case 'unknown':
      return status >= 500
        ? 'Wattcloud relay is unavailable. Try again later.'
        : 'This action was blocked. Try again.';
  }
}

function formatRetry(secs: number | null): string {
  if (secs === null || secs <= 0) return 'later';
  if (secs < 60) return `in ${secs}s`;
  if (secs < 3600) return `in ${Math.ceil(secs / 60)} min`;
  if (secs < 86400) return `in ${Math.ceil(secs / 3600)} h`;
  return `in ${Math.ceil(secs / 86400)} d`;
}

/**
 * Check a response. If it's a share-limit rejection, throw the
 * error; otherwise return the response unchanged so the caller's
 * normal success/failure path runs.
 */
export async function throwIfShareLimit(response: Response): Promise<Response> {
  if (response.ok) return response;
  const err = parseShareLimitError(response);
  if (err) throw err;
  return response;
}
