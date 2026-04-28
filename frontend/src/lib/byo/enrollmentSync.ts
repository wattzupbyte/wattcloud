import { writable } from 'svelte/store';

/**
 * Bumped whenever an enrollment cycle completes and either side has
 * meaningful state changes downstream views should pick up:
 *  - The sender's Settings → Devices list (vault_meta.enrolled_devices,
 *    which the receiver wrote on the backend).
 *  - The Access Control panel's relay-side device list, which the relay
 *    accepted on enrollment.
 *
 * Subscribers re-fetch their respective lists when the count changes.
 * No payload is needed — just a "something happened" tick.
 */
export const enrollmentEpoch = writable(0);

export function bumpEnrollmentEpoch(): void {
  enrollmentEpoch.update((n) => n + 1);
}
