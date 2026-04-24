import { describe, expect, it } from 'vitest';

import {
  AccessControlError,
  defaultDeviceLabel,
  formatInviteCode,
  friendlyClaimError,
  friendlyInviteError,
  generatePubkeyPlaceholder,
  isInviteCodeComplete,
} from '../../src/lib/byo/accessControl';

describe('formatInviteCode', () => {
  it('inserts dashes at 4/8 boundaries', () => {
    expect(formatInviteCode('A')).toBe('A');
    expect(formatInviteCode('ABCD')).toBe('ABCD');
    expect(formatInviteCode('ABCDE')).toBe('ABCD-E');
    expect(formatInviteCode('ABCDEFGH')).toBe('ABCD-EFGH');
    expect(formatInviteCode('ABCDEFGHJ')).toBe('ABCD-EFGH-J');
    expect(formatInviteCode('ABCDEFGHJKM')).toBe('ABCD-EFGH-JKM');
  });

  it('uppercases, strips separators, truncates to 11 alphanumerics', () => {
    expect(formatInviteCode('abcd-efgh-jkm')).toBe('ABCD-EFGH-JKM');
    expect(formatInviteCode('abcd efgh jkm')).toBe('ABCD-EFGH-JKM');
    expect(formatInviteCode('ABCD/EFGH/JKM')).toBe('ABCD-EFGH-JKM');
    expect(formatInviteCode('ABCDEFGHJKMNPQR')).toBe('ABCD-EFGH-JKM');
  });
});

describe('isInviteCodeComplete', () => {
  it('is true for exactly 11 alphanumeric chars regardless of display format', () => {
    expect(isInviteCodeComplete('ABCD-EFGH-JKM')).toBe(true);
    expect(isInviteCodeComplete('ABCDEFGHJKM')).toBe(true);
    expect(isInviteCodeComplete('abcd-efgh-jkm')).toBe(true);
  });

  it('is false for short or missing codes', () => {
    expect(isInviteCodeComplete('')).toBe(false);
    expect(isInviteCodeComplete('ABCD-EFGH')).toBe(false);
    expect(isInviteCodeComplete('ABCD-EFGH-JK')).toBe(false);
  });
});

describe('generatePubkeyPlaceholder', () => {
  it('produces a url-safe base64 string that decodes to 32 bytes', () => {
    const p = generatePubkeyPlaceholder();
    expect(p).toMatch(/^[A-Za-z0-9_-]+$/);
    // Base64url(32 bytes) = 43 chars (no padding).
    expect(p.length).toBe(43);
  });

  it('emits different output across calls (unless you are very unlucky)', () => {
    const a = generatePubkeyPlaceholder();
    const b = generatePubkeyPlaceholder();
    expect(a).not.toBe(b);
  });
});

describe('defaultDeviceLabel', () => {
  it('returns a short human-readable label', () => {
    const label = defaultDeviceLabel();
    expect(typeof label).toBe('string');
    expect(label.length).toBeGreaterThan(0);
    expect(label.length).toBeLessThan(50);
  });
});

describe('friendlyInviteError', () => {
  it('maps known reasons to supportive copy', () => {
    expect(friendlyInviteError(new AccessControlError(401, 'invalid_invite'))).toMatch(
      /isn't valid anymore/i,
    );
    // Rate-limit copy deliberately omits any specific duration — the server
    // has multiple windows (5/5min, 10/hr) and picking one would be wrong
    // for the other. "Try again later" is honest without misleading.
    expect(friendlyInviteError(new AccessControlError(429, 'rate_limited'))).toMatch(
      /try again later/i,
    );
    expect(friendlyInviteError(new AccessControlError(429, 'rate_limited'))).not.toMatch(
      /minute|hour|second/i,
    );
  });

  it('falls back to the raw message on unknown reasons', () => {
    const msg = friendlyInviteError(new AccessControlError(500, 'internal'));
    expect(msg).toContain('internal');
  });
});

describe('friendlyClaimError', () => {
  it('maps known reasons with clear next-step guidance', () => {
    expect(friendlyClaimError(new AccessControlError(401, 'invalid_token'))).toMatch(
      /claim-token/i,
    );
    expect(friendlyClaimError(new AccessControlError(429, 'rate_limited'))).toMatch(
      /try again later/i,
    );
  });
});

describe('AccessControlError', () => {
  it('carries status + reason', () => {
    const err = new AccessControlError(418, 'teapot');
    expect(err.status).toBe(418);
    expect(err.reason).toBe('teapot');
    expect(err.message).toContain('418');
    expect(err.message).toContain('teapot');
  });
});
