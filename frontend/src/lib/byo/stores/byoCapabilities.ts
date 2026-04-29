/**
 * byoCapabilities — runtime feature detection for browser APIs we
 * conditionally rely on. Populated once at app boot; consumed by UI
 * components to hide/show optional affordances (e.g. the "Send to..."
 * button on file rows).
 *
 * Detection here is cheap and presence-only ("does the API exist?").
 * Per-call gates (e.g. `navigator.canShare({files: <real files>})` for
 * a specific MIME) belong at the call site — Safari and a few mobile
 * browsers gate file sharing on MIME and we only know the MIME at click
 * time. The store answers "is it worth showing the button at all?",
 * not "will every share succeed?".
 */
import { writable, type Readable } from 'svelte/store';

export interface ByoCapabilities {
  /** Web Share API with file support is at least theoretically available
   *  in this browser — `navigator.share` and `navigator.canShare` both
   *  exist. The actual per-share `canShare({files})` check still runs at
   *  click time because some browsers (Safari) gate by MIME. */
  webShareFiles: boolean;
}

const INITIAL: ByoCapabilities = { webShareFiles: false };

const INTERNAL = writable<ByoCapabilities>(INITIAL);

export const byoCapabilities: Readable<ByoCapabilities> = {
  subscribe: INTERNAL.subscribe,
};

/** Run feature detection. Idempotent — safe to call from any boot path. */
export function detectByoCapabilities(): ByoCapabilities {
  const caps: ByoCapabilities = {
    webShareFiles:
      typeof navigator !== 'undefined' &&
      typeof navigator.share === 'function' &&
      typeof navigator.canShare === 'function',
  };
  INTERNAL.set(caps);
  return caps;
}

/** Test-only: force the store to a specific value. */
export function __setByoCapabilitiesForTest(caps: ByoCapabilities): void {
  INTERNAL.set(caps);
}
