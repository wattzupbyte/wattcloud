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
  /** Accent icon: 'seal' = cloud-badge check, 'warn' = amber hex,
   *  'danger' = red hex (for errors), 'info' = neutral dot. */
  icon?: 'seal' | 'info' | 'warn' | 'danger';
  /** Auto-dismiss in ms (default 3000). Set to `Infinity` — or pass a
   *  danger-iconed toast with no override — to keep the toast visible
   *  until the user dismisses it manually. */
  durationMs?: number;
}

const INTERNAL = writable<ByoToast | null>(null);
let nextId = 1;
let dismissTimer: ReturnType<typeof setTimeout> | null = null;

export const byoToast = {
  subscribe: INTERNAL.subscribe,
  show(text: string, opts?: { icon?: ByoToast['icon']; durationMs?: number }) {
    // Errors persist until the user dismisses them — auto-fading means the
    // user may miss them while reading, scrolled away, or in another tab.
    const defaultDuration = opts?.icon === 'danger' ? Infinity : 3000;
    const toast: ByoToast = {
      id: nextId++,
      text,
      icon: opts?.icon,
      durationMs: opts?.durationMs ?? defaultDuration,
    };
    INTERNAL.set(toast);
    if (dismissTimer !== null) clearTimeout(dismissTimer);
    dismissTimer = null;
    if (Number.isFinite(toast.durationMs)) {
      dismissTimer = setTimeout(() => {
        INTERNAL.update((cur) => (cur?.id === toast.id ? null : cur));
        dismissTimer = null;
      }, toast.durationMs);
    }
  },
  dismiss() {
    if (dismissTimer !== null) clearTimeout(dismissTimer);
    dismissTimer = null;
    INTERNAL.set(null);
  },
};
