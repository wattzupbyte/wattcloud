/**
 * Streaming ZIP builder. Thin wrapper around `client-zip`'s `makeZip` so
 * the rest of the codebase has a stable surface: caller yields entries
 * (an async iterable of name + stream), receives a
 * `ReadableStream<Uint8Array>` of zip bytes that it can pipe through
 * `streamToDisk` or the download Service Worker.
 *
 * The goal is memory-bounded operation: each file's bytes flow from the
 * source stream directly into the zip's compress/store path without
 * materialising the whole file in memory. Folder bundle shares (many
 * files) and owner-side folder downloads both use this.
 */

import { makeZip, predictLength } from 'client-zip';

/**
 * A single file that lands inside the zip.
 *
 * `input` is the source bytes — prefer a `ReadableStream` so nothing
 * buffers; `Blob`, `Uint8Array`, `ArrayBuffer` and `string` work too.
 * `name` is the in-zip path, forward-slash separated so subdirectories
 * materialise correctly (e.g. `"MyFolder/Sub/file.txt"`).
 */
export interface ZipEntry {
  name: string;
  input: ReadableStream<Uint8Array> | Blob | ArrayBuffer | Uint8Array | string;
  /** Plaintext byte length, when known — populates the zip's local-file
   *  header size field so tooling that reads the zip without parsing the
   *  full stream gets accurate metadata. Optional. */
  size?: number | bigint;
  /** Modification timestamp; defaults to the current time. */
  lastModified?: Date;
}

/**
 * Build a streaming zip from an iterable of {@link ZipEntry}.
 *
 * Consumers typically wrap an async generator that knows how to
 * enumerate + decrypt each file on demand; the generator's entries are
 * pulled one at a time as the reader drains the zip stream.
 */
export function createZipStream(
  entries: AsyncIterable<ZipEntry> | Iterable<ZipEntry>,
): ReadableStream<Uint8Array> {
  return makeZip(entries as Parameters<typeof makeZip>[0]);
}

/**
 * Predict the exact byte length of the zip stream {@link createZipStream}
 * would produce for these entries. Caller must supply name + size for
 * every entry. The result is precise (zip uses STORE method here, no
 * compression to vary the output), so it's safe to use as Content-Length
 * on a streaming Response — that's what fixes Firefox's download-manager
 * `.part → final` rename failure for SW-streamed bundles.
 */
export function predictZipLength(
  entries: Array<{ name: string; size: number | bigint; lastModified?: Date }>,
): number {
  // client-zip's predictLength wants its `JustMeta` shape (name + size).
  // It returns a bigint; coerce to a regular number — the response's
  // Content-Length stays well within Number.MAX_SAFE_INTEGER for any
  // realistic share (≤ 2 ** 53 bytes).
  return Number(predictLength(entries));
}
