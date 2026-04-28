/*
 * Download Service Worker — serves ReadableStream-backed downloads so the
 * browser can stream a file to disk without buffering it in RAM.
 *
 * Why this exists:
 *   - `showSaveFilePicker` (File System Access API) covers Chrome/Edge/Opera
 *     but NOT Safari or Firefox as of April 2026.
 *   - We still need streaming save on those browsers, otherwise a 10 GB
 *     share materialises in a Blob and OOMs the tab.
 *   - A scoped Service Worker can intercept a fetch to a URL we control
 *     and respond with Content-Disposition: attachment; the browser then
 *     routes that response through its native download pipeline — which
 *     writes bytes to disk as they arrive.
 *
 * Scope: /dl/ (implicit from this file's path). Only fetches inside /dl/
 * are intercepted. Everything else falls through to the network.
 *
 * Protocol with the main thread:
 *   1. Page posts `{ type: 'register', id, filename, mime }` via a
 *      MessageChannel.
 *   2. SW allocates a ReadableStream slot keyed by `id`, stores its controller,
 *      and replies `{ type: 'ready', id }` on the provided port.
 *   3. Page triggers a download via an `<a download href="/dl/<id>">` click.
 *      (We avoid a hidden iframe — Firefox doesn't reliably route iframe
 *      navigation fetches through a same-origin SW's fetch handler, but
 *      anchor-initiated fetches route correctly.)
 *   4. SW intercepts, attaches Content-Disposition headers, pipes the
 *      stream as the response body. The browser downloads it while the
 *      page concurrently pushes chunks via `{ type: 'chunk', id, data }`
 *      postMessages and finally `{ type: 'done', id }`.
 *   5. The entry is deleted on completion; a 30 s auto-cleanup timer
 *      catches abandoned registrations.
 */

const STREAMS = new Map();
/** ms after register() before an orphan entry is GC'd. */
const REGISTRATION_TTL_MS = 30_000;

self.addEventListener('install', (event) => {
  // Take over as soon as installed — no reload required for first use.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data.type !== 'string' || typeof data.id !== 'string') return;
  const id = data.id;

  if (data.type === 'register') {
    // Build a stream whose chunks are fed in from follow-up postMessages.
    // `start()` captures the controller synchronously so incoming `chunk`
    // messages can enqueue without racing.
    let controllerRef = null;
    let pending = [];
    let closed = false;
    let errorMsg = null;
    const stream = new ReadableStream({
      start(c) {
        controllerRef = c;
        for (const p of pending) c.enqueue(p);
        pending = null;
        if (errorMsg !== null) c.error(new Error(errorMsg));
        else if (closed) c.close();
      },
    });
    // Hold the SW alive until the transfer completes (done/error/timeout).
    // Without this, Firefox aggressively stops idle SWs between events —
    // the `STREAMS` map is top-level state that gets recreated on restart,
    // so register's entry would vanish before the iframe's /dl/<id> fetch
    // arrives, and the fetch handler would fall through to the network.
    let lifetimeResolve;
    const lifetime = new Promise((resolve) => {
      lifetimeResolve = resolve;
    });
    event.waitUntil(lifetime);
    STREAMS.set(id, {
      stream,
      filename: typeof data.filename === 'string' ? data.filename : 'download.bin',
      mime: typeof data.mime === 'string' ? data.mime : 'application/octet-stream',
      // Exact total byte length when the page knows it up-front (e.g. zip
      // predictLength for bundle downloads). Drives Content-Length on the
      // response — without it Firefox's download manager fails the
      // .part → final rename for larger SW-streamed bundles even though
      // the bytes drained cleanly on the page side. undefined → omit
      // header entirely (chunked transfer; works for size-known streams
      // in Chrome/Safari but is the failure mode in Firefox).
      contentLength:
        typeof data.contentLength === 'number' && data.contentLength >= 0
          ? data.contentLength
          : undefined,
      registeredAt: Date.now(),
      bytes: 0,
      chunks: 0,
      // Orphan-only flag: true until the corresponding /dl/<id> fetch
      // is intercepted. The 30s safety timer below errors the entry
      // ONLY when this is still false at fire time, so legitimate
      // downloads slower than 30s aren't killed mid-stream. Without
      // this distinction, a 10 MB bundle on residential uplink (the
      // user's reproducer) trips the timer at byte ~8 MB and Firefox's
      // download manager reports the .part as unreadable.
      fetchAttached: false,
      enqueue(chunk) {
        if (controllerRef) controllerRef.enqueue(chunk);
        else if (pending) pending.push(chunk);
      },
      close() {
        if (controllerRef) controllerRef.close();
        else closed = true;
      },
      error(msg) {
        const err = new Error(msg || 'stream error');
        if (controllerRef) controllerRef.error(err);
        else errorMsg = msg;
      },
      releaseLifetime() {
        if (lifetimeResolve) { lifetimeResolve(); lifetimeResolve = null; }
      },
    });
    const port = Array.isArray(event.ports) ? event.ports[0] : undefined;
    if (port) port.postMessage({ type: 'ready', id });

    // Orphan reaper: if the page never triggered the /dl/<id> fetch
    // within 30s of register (page navigated away, click swallowed,
    // etc.), error the entry so its lifetime promise resolves and the
    // SW can be evicted. Active downloads are not affected — once
    // fetchAttached flips to true, the reaper is a no-op regardless of
    // how long the actual byte transfer takes.
    setTimeout(() => {
      const entry = STREAMS.get(id);
      if (!entry) return;
      if (entry.fetchAttached) return;
      try { entry.error('registration timed out'); } catch (_) { /* drop */ }
      try { entry.releaseLifetime(); } catch (_) { /* drop */ }
      STREAMS.delete(id);
    }, REGISTRATION_TTL_MS);
    return;
  }

  if (data.type === 'chunk') {
    const entry = STREAMS.get(id);
    if (!entry) return;
    const buf = data.data;
    if (!(buf instanceof ArrayBuffer) || buf.byteLength === 0) return;
    entry.enqueue(new Uint8Array(buf));
    entry.bytes += buf.byteLength;
    entry.chunks++;
    if (entry.chunks <= 3 || entry.chunks % 100 === 0) {
      console.log('[sw-dl]', 'chunk ingested', { id, chunks: entry.chunks, bytes: entry.bytes });
    }
    return;
  }

  if (data.type === 'done') {
    const entry = STREAMS.get(id);
    if (!entry) return;
    console.log('[sw-dl]', 'done', { id, chunks: entry.chunks, bytes: entry.bytes });
    entry.close();
    // Keep the entry around briefly so the iframe fetch still finds it.
    setTimeout(() => {
      try { entry.releaseLifetime(); } catch (_) { /* drop */ }
      STREAMS.delete(id);
    }, 60_000);
    return;
  }

  if (data.type === 'error') {
    const entry = STREAMS.get(id);
    if (!entry) return;
    console.error('[sw-dl]', 'error', { id, message: data.message });
    entry.error(typeof data.message === 'string' ? data.message : 'stream error');
    setTimeout(() => {
      try { entry.releaseLifetime(); } catch (_) { /* drop */ }
      STREAMS.delete(id);
    }, 60_000);
    return;
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // Only intercept our own scope. /dl/sw-download.js passes through as a
  // normal script load; /dl/<hex-id> is the download trigger.
  const match = url.pathname.match(/^\/dl\/([a-f0-9]{16,64})$/);
  if (!match) return;

  const id = match[1];
  const entry = STREAMS.get(id);
  if (!entry) {
    // SW was evicted between register and fetch, or the id is unknown.
    // Fall through to the network, which will 404.
    return;
  }
  // The orphan reaper must NOT fire on this entry now that the fetch
  // has arrived — see `fetchAttached` comment in the register handler.
  entry.fetchAttached = true;

  const { stream, filename, mime, contentLength } = entry;

  const dispositionFilename = buildContentDisposition(filename);
  const headers = new Headers({
    'Content-Type': mime,
    'Content-Disposition': dispositionFilename,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    // Defense-in-depth: if Content-Disposition ever fails to force the
    // download path and the body is rendered as a document, default-src
    // 'none' blocks any script / style / image / subresource execution.
    // CSP has no effect on the native download manager draining the
    // Response body to disk.
    'Content-Security-Policy': "default-src 'none'",
  });
  // Set Content-Length when the page told us the exact total. Skipping
  // this for unknown sizes is fine — the response is just chunked. But
  // setting it when known materially helps Firefox finalize the download
  // (otherwise the .part → final rename fails with "source file could
  // not be read").
  if (typeof contentLength === 'number' && contentLength >= 0) {
    headers.set('Content-Length', String(contentLength));
  }
  event.respondWith(new Response(stream, { status: 200, headers }));
});

/**
 * RFC 5987-compliant Content-Disposition builder:
 *  - `filename="..."` with an ASCII fallback for legacy UAs.
 *  - `filename*=UTF-8''...` with the real (possibly Unicode) name for modern ones.
 * Strips filesystem-unsafe characters from both variants.
 */
function buildContentDisposition(name) {
  const safe = name.replace(/[\r\n\0\/\\]/g, '_');
  const asciiFallback = safe.replace(/[^\x20-\x7E]/g, '_');
  const encoded = encodeURIComponent(safe);
  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}
