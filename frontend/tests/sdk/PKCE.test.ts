import { describe, it, expect, vi, beforeAll } from 'vitest';
import { generatePKCE, base64URLEncode } from '../../src/lib/sdk/oauth/PKCE';

// generatePKCE() delegates to the BYO Web Worker (Rust sdk-core).
// The worker uses `new Worker(...)` which is not available in Node/Vitest.
// We mock the worker client to verify the wrapper contract without spinning
// up the full WASM stack. The correctness of the Rust PKCE implementation is
// verified in sdk-core unit tests (pkce.rs).
vi.mock('../../src/lib/sdk/worker/byoWorkerClient', () => ({
  initByoWorker: vi.fn().mockResolvedValue(undefined),
  generatePkce: vi.fn().mockResolvedValue({
    codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  }),
}));

describe('PKCE', () => {
  describe('base64URLEncode', () => {
    it('should encode bytes to base64url without padding', () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = base64URLEncode(bytes);
      expect(encoded).toBe('SGVsbG8');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });

    it('should handle empty bytes', () => {
      const encoded = base64URLEncode(new Uint8Array(0));
      expect(encoded).toBe('');
    });

    it('should produce URL-safe characters only', () => {
      // Test with bytes that would produce + and / in standard base64
      const bytes = new Uint8Array([0xfb, 0xff, 0xfe]); // produces + and / in base64
      const encoded = base64URLEncode(bytes);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });
  });

  describe('generatePKCE', () => {
    it('should return a PKCE pair with codeVerifier and codeChallenge', async () => {
      const pkce = await generatePKCE();
      expect(pkce).toHaveProperty('codeVerifier');
      expect(pkce).toHaveProperty('codeChallenge');
    });

    it('codeVerifier should be at least 43 characters', async () => {
      const pkce = await generatePKCE();
      expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(43);
    });

    it('codeChallenge should be different from codeVerifier', async () => {
      const pkce = await generatePKCE();
      expect(pkce.codeChallenge).not.toBe(pkce.codeVerifier);
    });

    it('delegates to the BYO worker (Rust sdk-core)', async () => {
      // Verifies the wrapper calls the worker, not any local crypto.
      const { generatePkce } = await import('../../src/lib/sdk/worker/byoWorkerClient');
      const pkce = await generatePKCE();
      expect(generatePkce).toHaveBeenCalled();
      // RFC 7636 Appendix B known-answer values returned by the mock above.
      expect(pkce.codeVerifier).toBe('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      expect(pkce.codeChallenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    });
  });
});
