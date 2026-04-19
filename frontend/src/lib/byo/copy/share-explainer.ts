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
    heading: 'Your file stays encrypted.',
    body: 'SecureCloud and your cloud provider only ever see scrambled ciphertext. The decryption key never leaves your device.',
  },
  {
    icon: 'Link',
    heading: 'The key travels in the link, not through our servers.',
    body: "When you click \"Generate link\", the one-time key for this file only is placed after the # in the URL. Browsers never send the part after # to any server — not ours, not your provider's, not the recipient's ISP.",
  },
  {
    icon: 'Key',
    heading: 'One link = one file.',
    body: 'Every file in your vault has its own independent key. If this link leaks, only this file is exposed. Your other files, your vault password, your account — all remain safe.',
  },
  {
    icon: 'UserCircle',
    heading: "Recipients don't need an account.",
    body: 'They open the link in any browser. The decryption happens inside their browser, on their device. The file is reassembled locally and streamed straight to their Downloads folder.',
  },
  {
    icon: 'Lock',
    heading: 'Password-protected?',
    body: 'The password wraps the file key using the same Argon2id settings as your account login (64 MB memory, 3 iterations). We never see the password, and we cannot brute-force it even if we wanted to.',
  },
  {
    icon: 'Clock',
    heading: 'Time-bounded or relayed?',
    body: "We store only a short-lived pointer or encrypted blob — never your key, never your file's contents in readable form. Revoking is instant on both sides.",
  },
  {
    icon: 'ArrowsClockwise',
    heading: 'Rotation is automatic.',
    body: "Revoking a link doesn't just hide it — the underlying file gets a new key the next time you upload it, so old links become cryptographically useless.",
  },
];

export const SHARE_EXPLAINER_HEADER = 'End-to-end encrypted, even when shared.';
