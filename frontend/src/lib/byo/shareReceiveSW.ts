/**
 * Share-receive Service Worker registration + cleanup messaging.
 *
 * The SW at /share-receive/sw.js intercepts POSTs to /share-receive
 * (Web Share Target API), stages files into OPFS under
 * /share-staging/<sessionId>/, and 303-redirects the browser to
 * /share-receive?session=<id>. The page-side flow (PR 5) reads the
 * staged files from OPFS and walks the user through unlock + upload.
 *
 * The /dl/ download SW lives in its own scope so a regression in this
 * one cannot brick downloads.
 */

const SW_URL = '/share-receive/sw.js';
const SW_SCOPE = '/share-receive/';

let registrationPromise: Promise<ServiceWorkerRegistration | null> | null = null;

export async function registerShareReceiveSW(): Promise<ServiceWorkerRegistration | null> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return null;
  if (registrationPromise) return registrationPromise;
  registrationPromise = (async () => {
    try {
      const existing = await navigator.serviceWorker.getRegistration(SW_SCOPE);
      if (existing?.active) {
        existing.update().catch(() => { /* best-effort */ });
        return existing;
      }
      const reg = await Promise.race([
        navigator.serviceWorker.register(SW_URL, { scope: SW_SCOPE }),
        new Promise<ServiceWorkerRegistration>((_, reject) =>
          setTimeout(() => reject(new Error('share-receive SW register timed out (10s)')), 10_000),
        ),
      ]);
      if (!reg.active) {
        await new Promise<void>((resolve) => {
          const done = () => resolve();
          if (reg.installing) reg.installing.addEventListener('statechange', () => {
            if (reg.active) done();
          });
          if (reg.waiting) reg.waiting.addEventListener('statechange', () => {
            if (reg.active) done();
          });
          // Safety timeout — if activation stalls, the next Web Share
          // Target POST won't be intercepted, but we don't want boot to
          // hang waiting for it.
          setTimeout(done, 3_000);
        });
      }
      return reg;
    } catch (err) {
      console.warn('[sw-share-receive] registration failed', err);
      return null;
    }
  })();
  return registrationPromise;
}

/** Tell the SW to delete a specific staging session. Used when the
 *  page-side flow finishes (success, cancel) or detects an orphan. */
export async function shareReceiveCleanupSession(sessionId: string): Promise<void> {
  const reg = await registerShareReceiveSW();
  reg?.active?.postMessage({ type: 'share-cleanup', sessionId });
}

/** Sweep stale staging sessions (>1 hour old). Fire-and-forget at boot. */
export async function shareReceiveSweepStale(): Promise<void> {
  const reg = await registerShareReceiveSW();
  reg?.active?.postMessage({ type: 'share-sweep' });
}
