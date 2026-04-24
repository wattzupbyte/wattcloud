/**
 * iosSave — shared thresholds, predicates, and user-facing strings for
 * the iOS-only buffered-save path. iOS Safari's download pipeline can't
 * consume slowly-filled Service Worker streams (it commits whatever tiny
 * prefix is buffered at response time, then fails the rest), so on iOS
 * every download buffers the decrypted plaintext into memory and hands
 * it off via navigator.share inside a fresh user-gesture click. That
 * buffer lives in the tab's heap, so we gate on plaintext size:
 *
 *   - below IOS_WARN_BYTES → silent, proceed
 *   - between WARN and BLOCK → advisory ("may run out of memory")
 *   - above IOS_BLOCK_BYTES → refuse ("use a desktop browser")
 *
 * Thresholds and text live here so the share recipient and the
 * owner-side dashboard stay consistent — when we revise copy or move
 * the ceiling, there's one place to edit.
 */

export {
  isIOSDevice,
  bufferForIOSSave,
  isOPFSSupported,
  probeOPFSQuota,
  sweepOPFSPending,
} from './streamToDisk';
export type {
  IOSSaveHandle,
  IOSPathChoice,
  StreamToDiskOptions,
  BufferForIOSSaveOptions,
} from './streamToDisk';

import { isOPFSSupported, probeOPFSQuota } from './streamToDisk';
import type { IOSPathChoice } from './streamToDisk';

/** RAM path ceilings — used when OPFS is unavailable or quota is tight.
 *  Above WARN we prompt, above BLOCK we refuse outright. These match
 *  the original static thresholds so iOS < 16.4 users see the same
 *  conservative gates they do today. */
export const IOS_RAM_WARN_BYTES = 200 * 1024 * 1024;
export const IOS_RAM_BLOCK_BYTES = 1_073_741_824;

/** OPFS path ceilings — peak memory during decrypt is one chunk
 *  (~64 KiB), so we only need to guard against the tab's disk quota.
 *  WARN is a big-file advisory (show progress UI); BLOCK is an upper
 *  clamp below `quota * OPFS_QUOTA_SAFETY_RATIO`. */
export const IOS_OPFS_WARN_BYTES = 5 * 1024 * 1024 * 1024;
export const IOS_OPFS_BLOCK_BYTES = 20 * 1024 * 1024 * 1024;
/** How much of the remaining quota we're willing to spend on a single
 *  download. Leaves headroom for the OS, other tabs' OPFS entries, and
 *  the user saving the file out to "Files" after we're done. */
const OPFS_QUOTA_SAFETY_RATIO = 0.8;
/** Extra multiplier applied to the expected payload when checking the
 *  free-quota against `expected * headroom`. Guards against block
 *  alignment, filesystem overhead, and small miscounts in the meta. */
const OPFS_QUOTA_HEADROOM = 1.5;

/** Synchronous RAM-only predicates — the caller already knows OPFS is
 *  out. For the full decision including OPFS/quota, await pickIosPath. */
export function iosShouldBlock(bytes: number): boolean {
  return Number.isFinite(bytes) && bytes > IOS_RAM_BLOCK_BYTES;
}

export function iosShouldWarn(bytes: number): boolean {
  return (
    Number.isFinite(bytes) &&
    bytes > IOS_RAM_WARN_BYTES &&
    bytes <= IOS_RAM_BLOCK_BYTES
  );
}

export interface IOSPathDecision {
  /** Which tier bufferForIOSSave should use. Pass this through as
   *  `{ path }` so the tier choice matches the gate that just ran. */
  path: IOSPathChoice;
  /** Refuse the download — show iosBlockMessage and don't queue. */
  block: boolean;
  /** Advisory — show iosWarnMessage and confirm before queueing. */
  warn: boolean;
  /** Informational: free OPFS quota at probe time (bytes). Missing
   *  when the OPFS path wasn't taken. */
  availableQuota?: number;
}

/**
 * Pick the save tier for a payload of `bytes` bytes.
 *
 * Runs the OPFS feature check + quota estimate once. If OPFS is
 * available and the free quota covers `bytes * OPFS_QUOTA_HEADROOM`,
 * returns the OPFS tier with a much higher ceiling than the RAM path.
 * Otherwise falls back to the RAM tier with the original 200 MB / 1 GB
 * gates — same behaviour as before OPFS existed.
 *
 * Idempotent and side-effect-free — safe to call multiple times per
 * download flow (e.g. once to drive a banner, again to drive the
 * buffer call itself).
 */
export async function pickIosPath(bytes: number): Promise<IOSPathDecision> {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return { path: 'ram', block: false, warn: false };
  }

  if (isOPFSSupported()) {
    const free = await probeOPFSQuota();
    if (typeof free === 'number') {
      const required = bytes * OPFS_QUOTA_HEADROOM;
      if (free >= required) {
        const usable = free * OPFS_QUOTA_SAFETY_RATIO;
        const opfsBlockCeiling = Math.min(usable, IOS_OPFS_BLOCK_BYTES);
        return {
          path: 'opfs',
          block: bytes > opfsBlockCeiling,
          warn: bytes > IOS_OPFS_WARN_BYTES && bytes <= opfsBlockCeiling,
          availableQuota: free,
        };
      }
      // OPFS is supported but quota too tight — fall through to RAM
      // so the user still has a chance for smaller payloads and a
      // clear block message for the oversized ones.
    }
  }

  return {
    path: 'ram',
    block: bytes > IOS_RAM_BLOCK_BYTES,
    warn: bytes > IOS_RAM_WARN_BYTES && bytes <= IOS_RAM_BLOCK_BYTES,
  };
}

/** `share` = recipient landing page; `owner` = vault-authenticated app. */
export type IOSSurface = 'share' | 'owner';
/** `archive` switches the noun from "file" to "archive" in messaging. */
export type IOSPayloadKind = 'file' | 'archive';

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Copy shown on BLOCK. OPFS path blocks on disk quota; RAM path
 *  blocks on tab memory — the user-facing reason differs, so we tailor
 *  the message to the path the gate chose. */
export function iosBlockMessage(
  bytes: number,
  surface: IOSSurface,
  _kind: IOSPayloadKind = 'file',
  path: IOSPathChoice = 'ram',
): string {
  const size = formatBytes(bytes);
  if (path === 'opfs') {
    // Quota-limited — tell the user the action item is to free storage.
    if (surface === 'share') {
      return `Not enough iPhone storage (${size}). Free up space or open this link on a desktop browser.`;
    }
    return `Not enough iPhone storage (${size}). Free up space or use a desktop browser.`;
  }
  if (surface === 'share') {
    return `Too large for iOS (${size}). Open this link on a desktop browser.`;
  }
  return `Too large for iOS (${size}). Use a desktop browser to download.`;
}

/** Copy shown on WARN. OPFS path warn reads as an advisory about time
 *  and storage; RAM path warn reads as a memory OOM risk. */
export function iosWarnMessage(
  bytes: number,
  surface: IOSSurface,
  kind: IOSPayloadKind = 'file',
  path: IOSPathChoice = 'ram',
): string {
  const size = formatBytes(bytes);
  const noun = kind === 'archive' ? 'archive' : 'file';
  if (path === 'opfs') {
    return `Large ${noun} (${size}) — this may take a while and use significant iPhone storage.`;
  }
  if (surface === 'share') {
    return `Large ${noun} (${size}) — iOS may run out of memory. Open this link on a desktop browser for reliability.`;
  }
  return `Large ${noun} (${size}) — iOS may run out of memory. A desktop browser is more reliable.`;
}
