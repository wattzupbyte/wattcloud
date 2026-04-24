import { writable } from 'svelte/store';

// Storage usage for the active BYO vault. Populated by whatever screen
// first loads the dashboard/settings context so the Drawer (hoisted to
// ByoApp and shared across screens) can show a usage indicator without
// re-fetching on every state change.
export const storageUsage = writable<{ used: number; quota: number | null }>({
  used: 0,
  quota: null,
});

export function resetStorageUsage() {
  storageUsage.set({ used: 0, quota: null });
}
