/**
 * streamToDisk — save a ReadableStream to the user's filesystem without
 * buffering the whole payload in memory.
 *
 * Tiered fallback:
 *   1. File System Access API (`showSaveFilePicker` → `FileSystemWritableFileStream`)
 *      — Chrome/Edge/Opera/Samsung on desktop + Android. Native save dialog,
 *      zero memory overhead.
 *   2. Hand-rolled download Service Worker at `/dl/sw-download.js` — covers
 *      Firefox and Safari (desktop + iOS) which have not shipped the picker.
 *      The SW responds to an `<a download>`-triggered fetch with our stream
 *      tagged Content-Disposition: attachment, so the browser drives its
 *      native download pipeline.
 *   3. Legacy `Blob + <a download>` — only used when neither path above is
 *      available AND the payload is small enough (≤ SMALL_BLOB_LIMIT). For
 *      anything larger we reject loudly rather than silently OOM the tab.
 *
 * Intentionally the only way to persist a decrypted stream to disk across
 * the app — shared between the recipient page and owner-download flows
 * (Phase 2.5) so a latent memory ceiling in one place can't drift.
 */

/** Payload above this is refused in the legacy Blob path (~1 GiB). */
const SMALL_BLOB_LIMIT = 1_073_741_824;

/**
 * iOS Safari cannot stream Service Worker responses to its native
 * download manager — an `<a download>` navigation to a `/dl/<id>` URL
 * backed by a slowly-filled ReadableStream commits whatever tiny prefix
 * is buffered at response time and marks the rest as failed (observed:
 * 2 KB of a 4.9 MB payload). The File System Access API is absent on
 * iOS too, so both streaming tiers are unreachable. iOS callers must
 * buffer into memory, then hand the resulting File off inside a fresh
 * user gesture — see `bufferForIOSSave`.
 */
export function isIOSDevice(): boolean {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

export interface StreamToDiskOptions {
  /** Declared plaintext length if known (drives progress UI; informational). */
  sizeHint?: number;
  /**
   * Exact byte length of `stream` if known — sets the SW response's
   * Content-Length header. Critical for Firefox's download manager:
   * without it, larger SW-streamed downloads can finish on the page side
   * but fail to atomic-rename `.part` to the final filename ("source
   * file could not be read"). Set this only when you really know the
   * total — for zip bundles use client-zip's `predictLength`. Leaving
   * unset is safe; the response just won't carry Content-Length.
   */
  contentLength?: number;
  /** Progress callback invoked with bytes-so-far; may be called 0..N times. */
  onProgress?: (bytesWritten: number) => void;
  /** AbortSignal to cancel mid-stream. */
  signal?: AbortSignal;
}

export interface StreamToDiskResult {
  /** Which path ultimately handled the save. Useful for telemetry. */
  strategy: 'native' | 'service-worker' | 'blob';
  /** Bytes actually written to disk. */
  bytesWritten: number;
}

/**
 * Save `stream` as a file named `filename` (+ MIME `mime`). Rejects with
 * AbortError when the user cancels or `options.signal` fires.
 */
export async function streamToDisk(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string = 'application/octet-stream',
  options: StreamToDiskOptions = {},
): Promise<StreamToDiskResult> {
  // Tier 1: native picker. Skip on a browser that exposes the global but
  // can't actually drive it (some embedded WebViews).
  if (typeof (globalThis as any).showSaveFilePicker === 'function') {
    try {
      const result = await saveViaNativePicker(stream, filename, mime, options);
      return result;
    } catch (e) {
      if ((e as DOMException)?.name === 'AbortError') throw e;
      // Picker unavailable / denied / failed — fall through to SW. The
      // stream may have been partially read; the caller must pass a fresh
      // stream if they want to retry. For our call sites the stream is
      // tee()-ed or reconstructed before retry, so this is safe.
      console.warn('[streamToDisk] showSaveFilePicker failed; falling back', e);
    }
  }

  // Tier 2: Service Worker. We only use it if there's *already* an active
  // registration at click time — `navigator.serviceWorker.getRegistration`
  // is always fast, unlike `register()` which in Firefox can block for tens
  // of seconds on a first-ever install. `prewarmDownloadServiceWorker`
  // (called once at app boot) is the one place where we call `register()`;
  // if it completes in the background before the user clicks download,
  // this getRegistration check finds the active SW and we stream. If not,
  // we fall through to Blob with no visible wait and no console noise.
  if ('serviceWorker' in navigator) {
    const active = await getActiveDownloadServiceWorker();
    if (active) {
      try {
        return await saveViaServiceWorker(stream, filename, mime, options, active);
      } catch (e) {
        if ((e as DOMException)?.name === 'AbortError') throw e;
        console.warn('[streamToDisk] service worker path failed; falling back', e);
      }
    }
  }

  // Tier 3: last-ditch Blob. Only for small payloads.
  return saveViaBlob(stream, filename, mime, options);
}

// ── Tier 1: native File System Access API ──────────────────────────────────

async function saveViaNativePicker(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: StreamToDiskOptions,
): Promise<StreamToDiskResult> {
  const picker = (globalThis as any).showSaveFilePicker as (opts: {
    suggestedName: string;
    types: Array<{ accept: Record<string, string[]> }>;
  }) => Promise<FileSystemFileHandle>;

  const ext = filenameExtension(filename);
  const handle = await picker({
    suggestedName: filename,
    types: [{ accept: { [mime]: ext ? [ext] : [] } }],
  });
  const writable = await (handle as any).createWritable();

  const counted = countingTap(stream, options);
  try {
    await counted.stream.pipeTo(writable, { signal: options.signal });
  } catch (e) {
    try {
      await writable.abort();
    } catch {
      /* best-effort */
    }
    throw e;
  }
  return { strategy: 'native', bytesWritten: counted.bytesWritten() };
}

// ── Tier 2: Service Worker ─────────────────────────────────────────────────

let swRegistrationPromise: Promise<ServiceWorkerRegistration> | null = null;

/**
 * Kick off Service Worker registration before any user-visible download.
 * Fire-and-forget — intended to run at app boot so that by the time the
 * user clicks a download, `getRegistration('/dl/')` already returns an
 * active worker and `streamToDisk` can skip the register round-trip
 * entirely. Errors are logged once with diagnostic context so we can see
 * why install fails when it does — silent failure mode was hiding real
 * errors (parse/mime/scope rejection) behind the "Firefox is slow" story.
 */
export async function prewarmDownloadServiceWorker(): Promise<void> {
  if (!('serviceWorker' in navigator)) return;
  try {
    const existing = await navigator.serviceWorker.getRegistration('/dl/');
    if (existing) {
      console.info('[sw-prewarm] existing registration', {
        active: !!existing.active,
        installing: !!existing.installing,
        waiting: !!existing.waiting,
        scope: existing.scope,
      });
    }
    await ensureServiceWorker();
    const after = await navigator.serviceWorker.getRegistration('/dl/');
    console.info('[sw-prewarm] ready', {
      active: !!after?.active,
      state: after?.active?.state,
      scope: after?.scope,
    });
  } catch (err) {
    // Log the real reason — parse error, MIME rejection, scope rejection,
    // or a genuine timeout. Without this we were blind to install-phase
    // failures ("no SW in about:debugging" scenario).
    console.warn('[sw-prewarm] registration failed — downloads will use Blob fallback', err);
  }
}

/**
 * Return the active download Service Worker if one is already registered
 * for the `/dl/` scope. Unlike `register()`, `getRegistration()` is a cheap
 * lookup in the browser's SW database and never blocks on install — so we
 * can safely call it on every download click without risking a multi-second
 * UI pause. Returns null when nothing is registered yet (first visit with
 * prewarm still in flight) or when the registered worker hasn't activated.
 */
async function getActiveDownloadServiceWorker(): Promise<ServiceWorker | null> {
  try {
    const reg = await navigator.serviceWorker.getRegistration('/dl/');
    return reg?.active ?? null;
  } catch {
    return null;
  }
}

async function ensureServiceWorker(): Promise<ServiceWorkerRegistration> {
  if (!swRegistrationPromise) {
    swRegistrationPromise = (async () => {
      // Fast path: skip register() entirely if we already have an active
      // registration for the /dl/ scope. Firefox's register() call can
      // hang indefinitely when an update check is pending (common in dev
      // when the SW script content keeps changing), so avoiding the call
      // when it's unnecessary is the most reliable fix.
      //
      // BUT: we still need to pick up server-side changes to sw-download.js.
      // Explicitly call `update()` (fire-and-forget) so the browser issues
      // a byte-diff fetch for the script. If the script changed, Firefox
      // installs the new version as the waiting worker; our SW's install
      // handler calls `self.skipWaiting()` so it becomes active immediately.
      const existing = await navigator.serviceWorker.getRegistration('/dl/');
      if (existing?.active) {
        existing.update().catch(() => {
          /* update is best-effort; cached SW stays active if it fails */
        });
        return existing;
      }

      // Zombie registration: an entry exists but has no worker in any state
      // (active/installing/waiting all null). Firefox gets here when a
      // previous install failed mid-flight or the browser evicted the
      // worker but kept the registration shell. In that state a fresh
      // register() call hangs trying to update the empty shell — unregister
      // it first so we start from a clean slate.
      //
      // Every call here is time-bounded: unregister() and the follow-up
      // getRegistration() have been observed to hang indefinitely on a
      // corrupt Firefox profile. When that happens there's nothing JS can
      // do — the user must clear site data manually. We at least want
      // prewarm to finish so streamToDisk's Blob fallback keeps working.
      if (existing && !existing.active && !existing.installing && !existing.waiting) {
        console.debug('[sw-prewarm] clearing zombie /dl/ registration');
        await Promise.race([
          existing.unregister().catch(() => { /* best-effort */ }),
          new Promise((r) => setTimeout(r, 3_000)),
        ]);
        // Give Firefox a short grace period to actually reap the slot
        // before we register again. Without this, we've seen register()
        // bounce off a half-torn-down registration and hang.
        await new Promise((r) => setTimeout(r, 100));
      }

      // Default `updateViaCache` (unset → 'imports'): the browser bypasses
      // the HTTP cache when fetching the SW script itself. Previously we
      // set 'all' to avoid Firefox's update-check hang, but that same
      // option has been observed to trip Firefox into silent-install-fail
      // on first registration. Default gives us the cleanest install path.
      const registerP = navigator.serviceWorker.register('/dl/sw-download.js', {
        scope: '/dl/',
      });
      const registerTimeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('serviceWorker.register timed out (10s)')), 10_000),
      );
      const reg = await Promise.race([registerP, registerTimeout]);
      // Wait for activation so reg.active is non-null before we postMessage.
      if (!reg.active) {
        await new Promise<void>((resolve) => {
          const done = () => {
            if (reg.active) resolve();
          };
          const sw = reg.installing || reg.waiting;
          if (sw) {
            sw.addEventListener('statechange', () => done());
            done();
          } else {
            done();
          }
          // Safety timeout — don't hang forever.
          setTimeout(() => resolve(), 5_000);
        });
      }
      return reg;
    })();
    // If the registration ever rejects, clear the cached promise so the
    // next call retries rather than sharing a poisoned state.
    swRegistrationPromise.catch(() => {
      swRegistrationPromise = null;
    });
  }
  return swRegistrationPromise;
}

async function saveViaServiceWorker(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: StreamToDiskOptions,
  sw: ServiceWorker,
): Promise<StreamToDiskResult> {
  const id = randomDownloadId();

  // Register a stream slot with the SW (metadata + ack port). The stream
  // itself is pumped chunk-by-chunk via postMessage rather than
  // transferred — custom ReadableStreams with async-pipe chains don't
  // survive cross-realm transfer reliably in Firefox, so we keep the
  // stream main-thread-local and ship raw ArrayBuffer chunks to the SW
  // over postMessage with transferables.
  const channel = new MessageChannel();
  const ready = new Promise<void>((resolve, reject) => {
    channel.port1.onmessage = (event) => {
      if (event.data?.type === 'ready' && event.data?.id === id) {
        resolve();
      } else {
        reject(new Error('Unexpected SW response'));
      }
    };
    options.signal?.addEventListener(
      'abort',
      () => reject(new DOMException('Aborted', 'AbortError')),
      { once: true },
    );
    setTimeout(() => reject(new Error('Service Worker register timeout')), 5_000);
  });
  sw.postMessage(
    {
      type: 'register',
      id,
      filename,
      mime,
      contentLength:
        typeof options.contentLength === 'number' && options.contentLength >= 0
          ? options.contentLength
          : undefined,
    },
    [channel.port2],
  );
  await ready;

  // Trigger the download via an <a download> click. The SW intercepts
  // `/dl/<id>` and replies with Content-Disposition: attachment; the browser
  // routes that through its native download pipeline.
  //
  // We specifically avoid the StreamSaver-style hidden-iframe trigger: in
  // Firefox, iframe-initiated navigation fetches don't reliably route
  // through a same-origin SW's fetch handler, so the `/dl/<id>` request
  // misses the SW and falls through to the network (404). `<a download>`
  // clicks route correctly and are one fewer moving part besides.
  const link = document.createElement('a');
  link.href = `/dl/${id}`;
  link.download = filename;
  link.rel = 'noopener';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  setTimeout(() => link.remove(), 10_000);

  // Pump the stream to the SW. Re-chunk anything ≥ 256 KiB into 64 KiB
  // pieces so `onProgress` updates at a human-readable cadence.
  const reader = stream.getReader();
  const RECHUNK = 64 * 1024;
  const RECHUNK_THRESHOLD = 256 * 1024;
  let total = 0;
  try {
    while (true) {
      if (options.signal?.aborted) {
        sw.postMessage({ type: 'error', id, message: 'aborted' });
        throw new DOMException('Aborted', 'AbortError');
      }
      const { value, done } = await reader.read();
      if (done) {
        sw.postMessage({ type: 'done', id });
        break;
      }
      if (!value || value.byteLength === 0) continue;

      const pieces = value.byteLength >= RECHUNK_THRESHOLD
        ? rechunk(value, RECHUNK)
        : [value];
      for (const piece of pieces) {
        // Postmessage with Transferable ArrayBuffer — no copy.
        const buf = piece.buffer.slice(piece.byteOffset, piece.byteOffset + piece.byteLength);
        sw.postMessage({ type: 'chunk', id, data: buf }, [buf]);
        total += piece.byteLength;
        options.onProgress?.(total);
      }
    }
  } catch (err) {
    sw.postMessage({ type: 'error', id, message: (err as Error)?.message ?? 'unknown' });
    throw err;
  } finally {
    try { reader.releaseLock(); } catch { /* already detached */ }
  }

  console.info(`[sw] streamed ${total} bytes to disk`);
  return { strategy: 'service-worker', bytesWritten: total };
}

// ── iOS buffered-save path ─────────────────────────────────────────────────

export interface IOSSaveHandle {
  /** The buffered plaintext as a File, ready to hand to navigator.share. */
  file: File;
  /** Bytes actually buffered (same as file.size; kept for UI convenience). */
  bytes: number;
  /**
   * Persist the file to the user's filesystem. MUST be called from
   * inside a synchronous user-gesture handler (click/touchend) — iOS
   * rejects navigator.share and silently drops `<a download>` clicks
   * that aren't tied to a live gesture. Prefers Web Share API
   * (navigator.share with `files`), which opens the iOS share sheet
   * and lets the user pick "Save to Files" or any installed app.
   * Falls back to a blob URL `<a download>` click for iOS < 15 or when
   * canShare rejects the File (unsupported MIME, sandbox, etc.).
   */
  save: () => Promise<void>;
  /** Release any backing OPFS entry immediately (cancel / retry path).
   *  RAM-backed handles are a no-op; OPFS-backed ones delete the file. */
  cleanup: () => Promise<void>;
}

/** Which iOS save tier materialised the File. */
export type IOSPathChoice = 'ram' | 'opfs';

/** OPFS working files all live under this prefix so the boot sweep can
 *  reap orphans without touching anything else in OPFS. */
const OPFS_PENDING_PREFIX = 'wc-dl-';
/** Orphans older than this are unconditionally removed on boot. */
const OPFS_PENDING_MAX_AGE_MS = 60 * 60 * 1000;

export interface BufferForIOSSaveOptions extends StreamToDiskOptions {
  /** Explicit tier selection. When omitted, bufferForIOSSave picks RAM.
   *  Callers that want disk-backed OPFS (no tab-RAM ceiling) should pass
   *  'opfs' after running pickIosPath in iosSave.ts — which validates
   *  feature support + quota before returning that choice. */
  path?: IOSPathChoice;
}

/**
 * Buffer a stream and return a File + gesture-bound save() callback.
 * Two tiers:
 *
 *   - RAM ('ram', default): accumulate chunks in memory → Blob → File.
 *     Peak memory = payload size + one chunk. Simple, works on every
 *     iOS version that has Service Workers. Ceiling is the tab's
 *     memory limit (~500 MB on modern iPhones).
 *
 *   - OPFS ('opfs'): stream chunks into an Origin Private File System
 *     entry, return the File read back from the entry's FileHandle.
 *     Peak memory ≈ one chunk (~64 KiB). Ceiling is the origin's disk
 *     quota (usually 50 % of free device storage). Requires iOS Safari
 *     16.4+ and a completed pickIosPath quota check.
 *
 * Both tiers produce the same IOSSaveHandle shape — the UI code (iOS
 * Save pill, share recipient panel) doesn't need to know which won.
 */
export async function bufferForIOSSave(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: BufferForIOSSaveOptions = {},
): Promise<IOSSaveHandle> {
  if (options.path === 'opfs') {
    return saveViaOPFS(stream, filename, mime, options);
  }
  return saveViaIOSMemory(stream, filename, mime, options);
}

async function saveViaIOSMemory(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: StreamToDiskOptions,
): Promise<IOSSaveHandle> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      if (options.signal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (total + value.byteLength > SMALL_BLOB_LIMIT) {
        throw new Error(
          'File is too large to buffer on iOS. Open this link on a desktop browser.',
        );
      }
      chunks.push(value);
      total += value.byteLength;
      options.onProgress?.(total);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* reader already detached */
    }
  }
  const blob = new Blob(chunks as BlobPart[], { type: mime });
  const file = new File([blob], filename, { type: mime });

  const save = async (): Promise<void> => {
    // Tier A: Web Share API. iOS 15+ renders the native share sheet
    // with "Save to Files" as a first-class option.
    if (
      typeof navigator.share === 'function' &&
      typeof navigator.canShare === 'function'
    ) {
      try {
        if (navigator.canShare({ files: [file] })) {
          // Files-only payload. Passing `title` causes iOS's Save to
          // Files target to materialise a companion text file containing
          // the title and to dedup-suffix both names with " 2" even when
          // no collision exists in the destination folder.
          await navigator.share({ files: [file] });
          return;
        }
      } catch (e: any) {
        if (e?.name === 'AbortError') return; // user dismissed the sheet
        console.warn('[iosSave] navigator.share failed; falling back', e);
      }
    }
    // Tier B: blob URL + <a download>. Older iOS (< 15) and Safari
    // builds without File support in canShare land here. With a live
    // gesture, iOS opens the file in the downloads sheet.
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      URL.revokeObjectURL(url);
    }, 10_000);
  };

  return {
    file,
    bytes: total,
    save,
    // RAM buffer is freed when the handle is dropped — nothing to do
    // here, but the interface is shared with the OPFS tier.
    cleanup: async () => {},
  };
}

// ── iOS OPFS path ──────────────────────────────────────────────────────────

/**
 * Feature-detect OPFS + WritableStream support. Synchronous so callers
 * can short-circuit before paying for `navigator.storage.estimate()`.
 * iOS Safari 16.4+ satisfies all three checks; earlier versions are
 * missing either `getDirectory` or `FileSystemFileHandle.createWritable`.
 */
export function isOPFSSupported(): boolean {
  try {
    return (
      typeof navigator !== 'undefined' &&
      typeof navigator.storage !== 'undefined' &&
      typeof navigator.storage.getDirectory === 'function' &&
      typeof (globalThis as any).FileSystemFileHandle !== 'undefined' &&
      typeof (globalThis as any).FileSystemFileHandle.prototype?.createWritable ===
        'function'
    );
  } catch {
    return false;
  }
}

/** Free bytes available under the origin's OPFS quota, or null if the
 *  estimate API is unavailable or fails. Zero is a legitimate reading
 *  when the origin has burned through its quota. */
export async function probeOPFSQuota(): Promise<number | null> {
  try {
    if (typeof navigator?.storage?.estimate !== 'function') return null;
    const { quota, usage } = await navigator.storage.estimate();
    if (typeof quota !== 'number' || typeof usage !== 'number') return null;
    return Math.max(0, quota - usage);
  } catch {
    return null;
  }
}

function opfsPendingName(filename: string): string {
  const rand = Math.random().toString(36).slice(2, 10);
  // Preserve the trailing extension so the File read back from OPFS
  // has a sensible suggestedName for navigator.share.
  const ext = filenameExtension(filename) ?? '';
  return `${OPFS_PENDING_PREFIX}${Date.now()}-${rand}${ext}`;
}

async function saveViaOPFS(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: StreamToDiskOptions,
): Promise<IOSSaveHandle> {
  if (!isOPFSSupported()) {
    // Caller mis-routed — fall through to the RAM path rather than
    // hard-failing. The size gate at pickIosPath should make this
    // unreachable in production.
    return saveViaIOSMemory(stream, filename, mime, options);
  }

  const root = await navigator.storage.getDirectory();
  const pendingName = opfsPendingName(filename);
  const fileHandle = await root.getFileHandle(pendingName, { create: true });
  const writable = await (fileHandle as any).createWritable() as FileSystemWritableFileStream;

  // Count bytes + honour the abort signal while piping. Using a
  // TransformStream lets FileSystemWritableFileStream's native
  // backpressure apply to the source via pipeTo — we don't have to
  // buffer an entire chunk before writing.
  let total = 0;
  const counter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      total += chunk.byteLength;
      options.onProgress?.(total);
      controller.enqueue(chunk);
    },
  });

  const removeOPFSEntry = async () => {
    try {
      await root.removeEntry(pendingName);
    } catch {
      /* already gone or locked — nothing we can do */
    }
  };

  try {
    await stream.pipeThrough(counter).pipeTo(writable, { signal: options.signal });
  } catch (err) {
    // `pipeTo` closes `writable` on abort/error, so we don't need
    // writable.abort(); just drop the half-written file.
    await removeOPFSEntry();
    throw err;
  }
  // `pipeTo` closes writable on successful completion. Some Safari
  // builds leave it open in the abort path only — double-close is a
  // no-op, so be defensive.
  try { await writable.close(); } catch { /* already closed */ }

  // Read the finished file. iOS treats the returned Blob as
  // disk-backed: navigator.share copies it to the share-sheet target
  // without re-materialising the plaintext in tab RAM. The File
  // wrapper is what sets the filename the share sheet shows.
  const stored = await fileHandle.getFile();
  const file = new File([stored], filename, { type: mime });

  let cleaned = false;
  const doCleanup = async () => {
    if (cleaned) return;
    cleaned = true;
    await removeOPFSEntry();
  };

  const save = async (): Promise<void> => {
    // Same share/fallback ladder as the RAM path — but delay cleanup
    // a minute after the share sheet opens so iOS can read the
    // backing file while the user picks a target.
    const scheduleDelayedCleanup = () => {
      setTimeout(() => { void doCleanup(); }, 60_000);
    };
    if (
      typeof navigator.share === 'function' &&
      typeof navigator.canShare === 'function'
    ) {
      try {
        if (navigator.canShare({ files: [file] })) {
          await navigator.share({ files: [file] });
          scheduleDelayedCleanup();
          return;
        }
      } catch (e: any) {
        if (e?.name === 'AbortError') {
          scheduleDelayedCleanup();
          return;
        }
        console.warn('[opfsSave] navigator.share failed; falling back', e);
      }
    }
    const url = URL.createObjectURL(file);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      URL.revokeObjectURL(url);
    }, 10_000);
    scheduleDelayedCleanup();
  };

  return { file, bytes: total, save, cleanup: doCleanup };
}

/**
 * Boot-time sweep: remove OPFS pending-* entries older than the TTL.
 * Covers tabs that crashed or closed mid-download before their
 * per-handle cleanup could run. Fire-and-forget; errors are logged
 * but don't gate boot — an unsweepable orphan just lingers until the
 * next run or until the origin hits quota pressure.
 */
export async function sweepOPFSPending(): Promise<void> {
  if (!isOPFSSupported()) return;
  try {
    const root = await navigator.storage.getDirectory();
    const cutoff = Date.now() - OPFS_PENDING_MAX_AGE_MS;
    const entries = (root as any).entries ? (root as any).entries() : null;
    if (!entries) return;
    for await (const [name, handle] of entries as AsyncIterable<[string, FileSystemHandle]>) {
      if (!name.startsWith(OPFS_PENDING_PREFIX)) continue;
      if (handle.kind !== 'file') continue;
      // Name carries the creation timestamp so we don't need another
      // metadata round-trip. `wc-dl-<epochMs>-<rand><ext>`.
      const dashAfterPrefix = OPFS_PENDING_PREFIX.length;
      const firstDash = name.indexOf('-', dashAfterPrefix);
      const tsStr = firstDash >= 0 ? name.slice(dashAfterPrefix, firstDash) : '';
      const ts = Number(tsStr);
      if (!Number.isFinite(ts) || ts > cutoff) continue;
      try {
        await root.removeEntry(name);
      } catch {
        /* best-effort */
      }
    }
  } catch (err) {
    console.warn('[opfs-sweep] failed', err);
  }
}

function rechunk(value: Uint8Array, size: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let off = 0; off < value.byteLength; off += size) {
    out.push(value.subarray(off, Math.min(off + size, value.byteLength)));
  }
  return out;
}

// Blob path can reuse the same re-chunker; separate name to avoid the
// svelte-check "possibly-overridden" lint from duplicate decls.
const rechunkForBlob = rechunk;

// ── Tier 3: Blob fallback ──────────────────────────────────────────────────

async function saveViaBlob(
  stream: ReadableStream<Uint8Array>,
  filename: string,
  mime: string,
  options: StreamToDiskOptions,
): Promise<StreamToDiskResult> {
  // Re-chunk any source chunk ≥ 256 KiB into 64 KiB pieces so onProgress
  // fires at a human-readable cadence. SFTP (and other buffering
  // providers) can yield the entire file in a single Uint8Array; without
  // rechunking, the progress UI jumps 0 → 100 %.
  const RECHUNK = 64 * 1024;
  const RECHUNK_THRESHOLD = 256 * 1024;
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      if (options.signal?.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      const pieces = value.byteLength >= RECHUNK_THRESHOLD
        ? rechunkForBlob(value, RECHUNK)
        : [value];
      for (const piece of pieces) {
        total += piece.byteLength;
        if (total > SMALL_BLOB_LIMIT) {
          throw new Error(
            'File is too large to download in this browser. Try Chrome, Edge, or Safari 16.4+.',
          );
        }
        chunks.push(piece);
        options.onProgress?.(total);
        // Yield a macrotask between pieces so the browser actually
        // repaints the progress bar. Microtask yields (Promise.resolve)
        // let Svelte flush its store subscribers, but repaint requires
        // returning to the event loop (setTimeout). The prior
        // 16-ms-throttled yield was wrong: the synchronous slice loop
        // runs in <16 ms for files ≲10 MiB, so the yield never fired
        // and the bar jumped 0→100. setTimeout(0) per piece adds a few
        // hundred ms of total overhead for a 6.5 MiB download — fine.
        if (pieces.length > 1) {
          await new Promise((r) => setTimeout(r, 0));
        }
      }
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* reader may already be consumed */
    }
  }
  const blob = new Blob(chunks as BlobPart[], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5_000);
  return { strategy: 'blob', bytesWritten: total };
}

// ── Helpers ────────────────────────────────────────────────────────────────

interface CountingTap {
  stream: ReadableStream<Uint8Array>;
  bytesWritten: () => number;
}

/**
 * Wrap a source stream in a pass-through TransformStream that counts bytes
 * and fires `onProgress`. Returns a fresh transferable stream.
 */
function countingTap(
  source: ReadableStream<Uint8Array>,
  options: StreamToDiskOptions,
): CountingTap {
  let total = 0;
  const ts = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, ctrl) {
      total += chunk.byteLength;
      options.onProgress?.(total);
      ctrl.enqueue(chunk);
    },
  });
  const piped = source.pipeThrough(ts);
  return {
    stream: piped,
    bytesWritten: () => total,
  };
}

function filenameExtension(filename: string): string | null {
  const dot = filename.lastIndexOf('.');
  if (dot <= 0 || dot === filename.length - 1) return null;
  return filename.slice(dot);
}

function randomDownloadId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
