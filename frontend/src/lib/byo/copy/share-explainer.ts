/**
 * User-facing copy for the "How does this work?" accordion in ShareLinkSheet.
 *
 * Plain-language, non-technical explanation of the E2E share mechanism.
 * Centralised here so translations (future) can override per-locale.
 *
 * Each entry: { icon, heading, body }
 * icon: Phosphor icon name (used by caller to render the correct component).
 */

export interface ExplainerItem {
  icon: string;
  heading: string;
  body: string;
}

export const SHARE_EXPLAINER_ITEMS: ExplainerItem[] = [
  {
    icon: 'ShieldCheck',
    heading: 'Encrypted end to end.',
    body: 'The relay and your cloud provider only ever see scrambled ciphertext. The decryption key never leaves your device.',
  },
  {
    icon: 'Link',
    heading: 'The key travels in the link, not through any server.',
    body: 'The per-share key is placed after the # in the URL. Browsers never send the part after # to any server — not the relay, not the recipient\'s ISP.',
  },
  {
    icon: 'Key',
    heading: 'Each link has its own key.',
    body: 'If this link leaks, only what you put in this share is exposed. Your vault password, your account, and everything else in your vault stay safe.',
  },
  {
    icon: 'UserCircle',
    heading: "Recipients don't need an account.",
    body: 'They open the link in any browser. Decryption happens inside their browser, on their device. Content is reassembled locally and streamed straight to their Downloads folder.',
  },
  {
    icon: 'Lock',
    heading: 'Password-protected?',
    body: 'The password wraps the share key using Argon2id (128 MiB memory, 3 iterations, 4 lanes) — the same settings as your vault unlock. The password never leaves your device, so no server can brute-force it.',
  },
  {
    icon: 'Clock',
    heading: 'Time-bounded.',
    body: 'The relay stores only an encrypted blob — never your key, never your content in readable form. When the link expires or you revoke it, the relay purges the blob; nothing orphaned is left behind.',
  },
  {
    icon: 'ArrowsClockwise',
    heading: 'Revocation is cryptographic.',
    body: 'Revoking a link deletes the ciphertext on the relay. Even an attacker who saved the link beforehand has nothing left to decrypt.',
  },
];

export const SHARE_EXPLAINER_HEADER = 'End-to-end encrypted, even when shared.';
