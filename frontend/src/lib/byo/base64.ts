/**
 * Shared base64 ↔ Uint8Array helpers.
 *
 * Single source of truth — import from here, not from VaultLifecycle.
 * VaultLifecycle re-exports these for backwards compat with existing callers.
 */

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
