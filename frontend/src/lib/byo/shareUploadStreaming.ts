/**
 * Helpers for streaming the V7 ciphertext of an owned file straight into
 * a `fetch(...)` body when creating a share. Replaces the prior "drain to
 * Uint8Array then POST" pattern so a multi-gigabyte share doesn't
 * materialise the whole ciphertext in JS heap before the upload starts.
 *
 * Two browser paths:
 *   1. `fetch(url, { body: readable, duplex: 'half' })` — true streaming
 *      POST. Default-on in Chrome 105+ and Safari 17.4+. Firefox has the
 *      implementation but gates it behind the `network.fetch.upload_streams`
 *      pref (off by default through current stable releases).
 *   2. Buffer-and-forward fallback — drains the V7 ciphertext into a
 *      contiguous Uint8Array first, then POSTs that. Correctness-equivalent
 *      to path 1 (same wire bytes); cost is JS heap proportional to the
 *      share size during the upload window. ShareLinkSheet shows a
 *      one-time hint when this path will fire so the user knows what to
 *      expect (and how to flip the Firefox pref if they want streaming).
 *
 * Regular file uploads to a storage provider (StorageProvider.upload_stream)
 * never hit this code path — they chunk through WASM with bounded per-POST
 * bodies, so heap stays at one chunk regardless of file size.
 */

/**
 * One-shot feature test for `fetch(..., { body: ReadableStream, duplex: 'half' })`.
 *
 * Recipe from Chrome team (web.dev/fetch-upload-streaming): probes for the
 * `duplex` getter being read (spec-compliant browsers) and verifies the
 * body-to-Content-Type auto-inference isn't firing (older browsers treat
 * the stream as the kind of Blob-esque body that gets a content-type set).
 */
let cachedSupport: boolean | null = null;
export function supportsRequestStreams(): boolean {
  if (cachedSupport !== null) return cachedSupport;
  try {
    let duplexAccessed = false;
    const init: RequestInit & { duplex?: string } = {
      method: 'POST',
      body: new ReadableStream(),
    };
    // Use a getter so we can observe whether the browser reads it.
    Object.defineProperty(init, 'duplex', {
      get() {
        duplexAccessed = true;
        return 'half';
      },
      enumerable: true,
    });
    const hasContentType = new Request('https://example.invalid/', init).headers.has(
      'Content-Type',
    );
    cachedSupport = duplexAccessed && !hasContentType;
  } catch {
    cachedSupport = false;
  }
  return cachedSupport;
}

/**
 * Consume the first `size` bytes of `source` and return them as a `Uint8Array`.
 * The returned `body` stream re-emits those header bytes followed by the rest
 * of `source`, so it can be used as the request body of an `fetch(...)` call
 * without losing the prefix.
 *
 * Throws if `source` terminates before yielding `size` bytes.
 */
export async function peekHeaderAndResume(
  source: ReadableStream<Uint8Array>,
  size: number,
): Promise<{ header: Uint8Array; body: ReadableStream<Uint8Array> }> {
  const reader = source.getReader();
  const parts: Uint8Array[] = [];
  let collected = 0;
  let leftover: Uint8Array | null = null;

  while (collected < size) {
    const { value, done } = await reader.read();
    if (done) {
      reader.releaseLock();
      throw new Error(`stream ended after ${collected} bytes, need ${size}`);
    }
    if (!value) continue;
    if (collected + value.byteLength <= size) {
      parts.push(value);
      collected += value.byteLength;
    } else {
      const need = size - collected;
      parts.push(value.subarray(0, need));
      leftover = value.subarray(need);
      collected = size;
    }
  }

  const header = new Uint8Array(size);
  {
    let off = 0;
    for (const p of parts) {
      header.set(p, off);
      off += p.byteLength;
    }
  }

  // Note: the header bytes captured above are NOT re-yielded through `body`.
  // Callers that need the full ciphertext on the wire (share uploads) must
  // prepend `header` to `body` themselves. That's the shape the share upload
  // path wants — it uses `header` for WASM decryption-fragment computation
  // and resumes the rest of the stream into fetch.
  const body = new ReadableStream<Uint8Array>({
    async start(controller) {
      if (leftover && leftover.byteLength > 0) controller.enqueue(leftover);
    },
    async pull(controller) {
      const { value, done } = await reader.read();
      if (done) {
        controller.close();
        reader.releaseLock();
        return;
      }
      if (value) controller.enqueue(value);
    },
    cancel(reason) {
      reader.cancel(reason).catch(() => {
        /* best-effort */
      });
      reader.releaseLock();
    },
  });

  return { header, body };
}

/**
 * Prepend `prefix` bytes to `body` so a downstream consumer sees the full
 * ciphertext (header + body tail) in one stream. The prefix is emitted in a
 * single `enqueue` call before `body` starts flowing.
 */
export function prependBytes(
  prefix: Uint8Array,
  body: ReadableStream<Uint8Array>,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let headerYielded = false;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!headerYielded) {
        headerYielded = true;
        controller.enqueue(prefix);
        return;
      }
      const { value, done } = await reader.read();
      if (done) {
        controller.close();
        reader.releaseLock();
        return;
      }
      if (value) controller.enqueue(value);
    },
    cancel(reason) {
      reader.cancel(reason).catch(() => {
        /* best-effort */
      });
      reader.releaseLock();
    },
  });
}

/**
 * Pass-through TransformStream that counts bytes flowing through it and
 * exposes the running total via a closure.
 */
export function countingTap(source: ReadableStream<Uint8Array>): {
  body: ReadableStream<Uint8Array>;
  bytes: () => number;
} {
  let total = 0;
  const ts = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, ctrl) {
      total += chunk.byteLength;
      ctrl.enqueue(chunk);
    },
  });
  return {
    body: source.pipeThrough(ts),
    bytes: () => total,
  };
}

/**
 * Drain a ReadableStream into a single Uint8Array. Used as the feature-flag
 * fallback path when the browser doesn't support streaming request bodies.
 */
export async function drainToBuffer(
  source: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const reader = source.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) {
        parts.push(value);
        total += value.byteLength;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}
