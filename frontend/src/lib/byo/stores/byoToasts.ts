/**
 * byoToasts — transient notification queue (DESIGN.md §20).
 *
 * One toast visible at a time; a new toast replaces the current one.
 * Pill-shaped, bottom-center, auto-dismisses after 3000ms.
 * Host is `ByoToastHost.svelte` mounted once in ByoApp.
 */
import { writable } from 'svelte/store';

export interface ByoToast {
  /** Monotonic id; lets the host key transitions correctly. */
  id: number;
  /** Plain-text body (single line preferred). */
  text: string;
  /** Optional accent icon: 'seal' = hex-shield check, 'info' = dot. */
  icon?: 'seal' | 'info' | 'warn';
  /** Auto-dismiss in ms (default 3000). */
  durationMs?: number;
}

const INTERNAL = writable<ByoToast | null>(null);
let nextId = 1;
let dismissTimer: ReturnType<typeof setTimeout> | null = null;

export const byoToast = {
  subscribe: INTERNAL.subscribe,
  show(text: string, opts?: { icon?: ByoToast['icon']; durationMs?: number }) {
    const toast: ByoToast = {
      id: nextId++,
      text,
      icon: opts?.icon,
      durationMs: opts?.durationMs ?? 3000,
    };
    INTERNAL.set(toast);
    if (dismissTimer !== null) clearTimeout(dismissTimer);
    dismissTimer = setTimeout(() => {
      INTERNAL.update((cur) => (cur?.id === toast.id ? null : cur));
      dismissTimer = null;
    }, toast.durationMs);
  },
  dismiss() {
    if (dismissTimer !== null) clearTimeout(dismissTimer);
    dismissTimer = null;
    INTERNAL.set(null);
  },
};
