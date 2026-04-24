import { writable } from 'svelte/store';

// Cross-page drawer state. Collapsing the drawer on one screen (e.g.
// dashboard) should persist when the user navigates to another screen
// (e.g. settings) — otherwise the sidebar keeps snapping open.
//
// `drawerOpen` is the mobile-overlay toggle; desktop always shows the
// sidebar inline, toggled between wide and collapsed via `drawerCollapsed`.
export const drawerCollapsed = writable(false);
export const drawerOpen = writable(false);
