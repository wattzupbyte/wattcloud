<script lang="ts">
  /**
   * ShareRecipient — the /s/:share_id landing page.
   *
   * No vault, no login, no device enrollment. One-shot: fetch ciphertext from
   * the relay, decrypt using the content_key in the URL fragment, stream to
   * disk via streamToDisk (File System Access API → Service Worker → Blob).
   *
   * Fragment formats (frozen protocol):
   *   #k=<base64url(content_key)>           — public variant A
   *   #s=<salt>&e=<enc>                     — password-protected A+
   *
   * Flow:
   *   1. Parse share_id from pathname, fragment from location.hash.
   *   2. If A+, prompt for password → Argon2id 128 MiB / 3 iter / 4 parallel
   *      unwrap of content_key (WASM-side).
   *   3. Fetch /relay/share/:share_id/meta → { kind, blobs }.
   *   4. kind=file: stream /relay/share/:share_id/blob/main → V7 decrypt →
   *      streamToDisk. The original filename rides in the fragment as
   *      `&n=<percent-encoded>` (plaintext, never hits a server — the
   *      fragment already carries the key, so adding the name here is no
   *      weaker than the content_key itself).
   *   5. kind=folder|collection: fetch /relay/share/:share_id/blob/_manifest,
   *      decrypt with the bundle_key (fragment), parse JSON manifest. On
   *      Download, stream each blob through V7 decrypt → client-zip →
   *      streamToDisk so the recipient saves one zip with the tree
   *      preserved. No plaintext file list is rendered on the landing
   *      page; names only materialise inside the extracted zip.
   *
   * WASM streaming session (byoShareStreamInit/Push/Close) keeps the V7
   * decryptor alive across chunks so we never materialise the full
   * plaintext — mandatory for multi-GB shares.
   */
  import { onMount } from 'svelte';
  import {
    byoShareStreamInit,
    byoShareStreamPush,
    byoShareStreamClose,
    byo_share_decode_variant_a,
    byo_share_unwrap_key,
  } from '../../../pkg/wattcloud_sdk_wasm';
  import initWasm from '../../../pkg/wattcloud_sdk_wasm';
  import { streamToDisk } from '../../byo/streamToDisk';
  import {
    isIOSDevice,
    bufferForIOSSave,
    pickIosPath,
    iosBlockMessage,
    iosWarnMessage,
    type IOSSaveHandle,
    type IOSPathDecision,
  } from '../../byo/iosSave';
  import { parseShareLimitError } from '../../byo/shareLimitCopy';
  import { createZipStream, predictZipLength, type ZipEntry } from '@wattcloud/sdk';

  const iosDevice = isIOSDevice();

  type Variant = 'public' | 'password';

  interface ShareMeta {
    kind: 'file' | 'folder' | 'collection';
    expires_at: number;
    total_bytes: number;
    blob_count: number;
    blobs: Array<{ blob_id: string; bytes: number }>;
  }

  interface ManifestEntry {
    blob_id: string;
    rel_path: string;
    content_key_b64: string;
    size: number;
    ciphertext_size?: number;
    mime?: string;
  }

  interface ManifestV1 {
    version: 1;
    entries: ManifestEntry[];
  }

  // ── State ──────────────────────────────────────────────────────────────────

  let shareId = '';
  let variant: Variant = 'public';
  let fragmentParams: URLSearchParams = $state(new URLSearchParams());
  let loadingMeta = $state(true);
  let meta = $state<ShareMeta | null>(null);
  let metaError = $state('');
  let needPassword = $state(false);
  let password = $state('');
  let unwrapInProgress = $state(false);
  let unwrapError = $state('');
  let contentKeyB64: string | null = null; // decoded once variant A, or post-unwrap for A+
  let bundleEntries: ManifestEntry[] | null = $state(null);
  let bundleError = $state('');
  let downloadError = $state('');
  let downloading = $state(new Map<string, number>()); // blob_id → bytes written so far
  /** Bundle-share zip download state — separate from per-file tracking
   *  because a bundle is a single stream, not a list of actions. */
  let bundleDownloading = $state(false);
  let bundleBytesWritten = $state(0);

  /** iOS two-phase state. `iosSavePending` means we're currently
   *  buffering the decrypted plaintext; `iosSaveHandle` is set once the
   *  buffer is ready and holds the File + save() callback. The Save
   *  button binds to handle.save so the user's tap re-enters a fresh
   *  user-gesture window for navigator.share. */
  let iosSavePending = $state(false);
  let iosSaveHandle: IOSSaveHandle | null = $state(null);
  let iosSaveError = $state('');


  /** iOS path + block/warn decision, resolved async after meta loads.
   *  Null until the probe completes — the UI gates on `iosDecision !== null`
   *  so we don't flash a banner state before the OPFS quota is known. */
  let iosDecision = $state<IOSPathDecision | null>(null);

  async function refreshIosDecision(bytes: number) {
    try {
      iosDecision = await pickIosPath(bytes);
    } catch (e) {
      // Probe failure — fail closed to the RAM gate.
      console.warn('[share] pickIosPath failed; using RAM thresholds', e);
      iosDecision = {
        path: 'ram',
        block: bytes > 1_073_741_824,
        warn: bytes > 200 * 1024 * 1024 && bytes <= 1_073_741_824,
      };
    }
  }


  // Header buffer size = V7_HEADER_MIN. Hardcoded here to avoid importing
  // the Rust constant; must stay in sync with sdk-core.
  const V7_HEADER_SIZE = 1709;
  const V7_FOOTER_SIZE = 32;

  onMount(async () => {
    shareId = parseShareId(window.location.pathname);
    if (!shareId) {
      metaError = 'Invalid share URL.';
      loadingMeta = false;
      return;
    }
    const hash = window.location.hash.replace(/^#/, '');
    fragmentParams = new URLSearchParams(hash);
    if (fragmentParams.has('k')) {
      variant = 'public';
    } else if (fragmentParams.has('s') && fragmentParams.has('e')) {
      variant = 'password';
      needPassword = true;
    } else {
      metaError =
        'This share URL is missing its decryption key. Ask the sender to resend it.';
      loadingMeta = false;
      return;
    }

    try {
      await initWasm({ module_or_path: undefined });
    } catch (e) {
      console.error('[share] WASM init failed', e);
      metaError = 'Failed to load cryptography module.';
      loadingMeta = false;
      return;
    }

    if (variant === 'public') {
      const key = decodeFragmentKey();
      if (!key) {
        loadingMeta = false;
        return;
      }
      contentKeyB64 = key;
    }

    await loadMeta();
  });

  function parseShareId(pathname: string): string {
    const m = pathname.match(/^\/s\/([A-Za-z0-9-]{36})\/?$/);
    return m ? m[1] : '';
  }

  function decodeFragmentKey(): string | null {
    // WASM's decode_variant_a strips the "k=" prefix and base64url-decodes
    // the rest as-is, so any trailing params (e.g. "&n=<filename>") would
    // poison the decode. Pull just the `k` value via URLSearchParams and
    // rebuild the `k=<value>` shape WASM expects.
    const kValue = fragmentParams.get('k');
    if (!kValue) {
      metaError = 'Bad share URL.';
      return null;
    }
    try {
      const result = byo_share_decode_variant_a(`k=${kValue}`) as any;
      if (typeof result === 'string') return result;
      metaError = result?.error || 'Bad share URL.';
      return null;
    } catch (e) {
      console.error('[share] decode fragment failed', e);
      metaError = 'Could not decode share URL.';
      return null;
    }
  }

  async function submitPassword() {
    unwrapError = '';
    if (!password) {
      unwrapError = 'Enter the password.';
      return;
    }
    unwrapInProgress = true;
    try {
      const salt = fragmentParams.get('s') || '';
      const enc = fragmentParams.get('e') || '';
      // Argon2id runs 128 MiB — may take a few seconds on low-end phones.
      const result = byo_share_unwrap_key(salt, enc, password) as any;
      if (typeof result !== 'string') {
        unwrapError = result?.error || 'Wrong password.';
        return;
      }
      contentKeyB64 = result;
      needPassword = false;
      await loadMeta();
    } catch (e) {
      console.error('[share] unwrap failed', e);
      unwrapError = 'Wrong password or share is invalid.';
    } finally {
      unwrapInProgress = false;
    }
  }

  async function loadMeta() {
    loadingMeta = true;
    metaError = '';
    try {
      const resp = await fetch(`/relay/share/${encodeURIComponent(shareId)}/meta`);
      if (resp.status === 404) {
        metaError = 'This share has expired or is no longer available.';
        return;
      }
      if (!resp.ok) {
        // Relay-emitted abuse-protection rejections carry a
        // reason header we can turn into specific copy.
        const limit = parseShareLimitError(resp);
        metaError = limit
          ? limit.message
          : `Unexpected response from relay (${resp.status}).`;
        return;
      }
      meta = (await resp.json()) as ShareMeta;
      if (meta.kind !== 'file') {
        // Bundle: fetch + decrypt manifest so the user sees the file list.
        await loadManifest();
      }
    } catch (e) {
      console.error('[share] meta fetch failed', e);
      metaError = 'Network error. Try again in a moment.';
    } finally {
      loadingMeta = false;
    }
  }

  async function loadManifest() {
    if (!contentKeyB64) return;
    bundleError = '';
    try {
      const resp = await fetch(`/relay/share/${encodeURIComponent(shareId)}/blob/_manifest`);
      if (!resp.ok || !resp.body) {
        const limit = parseShareLimitError(resp);
        bundleError = limit ? limit.message : 'Manifest unavailable.';
        return;
      }
      const plaintext = await decryptStreamToBytes(resp.body, contentKeyB64);
      const text = new TextDecoder().decode(plaintext);
      const parsed = JSON.parse(text) as ManifestV1;
      if (parsed?.version !== 1 || !Array.isArray(parsed.entries)) {
        bundleError = 'Manifest format is unsupported by this version.';
        return;
      }
      bundleEntries = parsed.entries;
    } catch (e) {
      console.error('[share] manifest decrypt failed', e);
      bundleError = 'Could not decrypt the manifest (wrong key?).';
    }
  }

  /**
   * Fetch + decrypt a complete blob into memory. Used for the manifest
   * (always small) — do NOT use this for content blobs. Content blobs go
   * through decryptStreamToSink below which never materialises plaintext.
   */
  async function decryptStreamToBytes(
    body: ReadableStream<Uint8Array>,
    keyB64: string,
  ): Promise<Uint8Array> {
    const reader = body.getReader();
    const buffered: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) {
          buffered.push(value);
          total += value.byteLength;
        }
      }
    } finally {
      reader.releaseLock();
    }
    const all = new Uint8Array(total);
    let off = 0;
    for (const c of buffered) {
      all.set(c, off);
      off += c.byteLength;
    }
    if (all.byteLength < V7_HEADER_SIZE + V7_FOOTER_SIZE) {
      throw new Error('Ciphertext too short for V7.');
    }
    const header = all.subarray(0, V7_HEADER_SIZE);
    const body_bytes = all.subarray(V7_HEADER_SIZE, all.byteLength - V7_FOOTER_SIZE);
    const footer = all.subarray(all.byteLength - V7_FOOTER_SIZE);
    const { sessionId } = byoShareStreamInit(header, keyB64) as any;
    const plaintext = byoShareStreamPush(sessionId, body_bytes) as unknown as Uint8Array;
    byoShareStreamClose(sessionId, footer);
    return plaintext;
  }

  /**
   * Streaming download path: pipes relay ciphertext → WASM decrypt →
   * streamToDisk without buffering the whole plaintext. The header is
   * buffered (1709 bytes) before decrypt can start; the footer is held
   * back from pushes and handed to close() on stream end.
   */
  async function downloadBlob(
    blobId: string,
    keyB64: string,
    filename: string,
    mime: string,
    sizeHint?: number,
  ) {
    downloadError = '';
    bundleError = '';
    downloading = new Map(downloading).set(blobId, 0);
    try {
      const resp = await fetch(
        `/relay/share/${encodeURIComponent(shareId)}/blob/${encodeURIComponent(blobId)}`,
      );
      if (resp.status === 404) {
        throw new Error('Blob expired or revoked.');
      }
      if (!resp.ok || !resp.body) {
        const limit = parseShareLimitError(resp);
        throw new Error(limit ? limit.message : `Unexpected relay response (${resp.status}).`);
      }
      const plaintextStream = await buildDecryptStream(resp.body, keyB64);
      await streamToDisk(plaintextStream, filename, mime, {
        sizeHint,
        // Same Firefox-finalize fix as the bundle path: when we know the
        // exact plaintext size up front, set Content-Length on the SW
        // response so the download manager can rename .part → final
        // cleanly. For single-file shares the plaintext size came in
        // through `sizeHint` from the manifest's plaintext_size field.
        contentLength:
          typeof sizeHint === 'number' && sizeHint >= 0 ? sizeHint : undefined,
        onProgress: (n) => {
          downloading = new Map(downloading).set(blobId, n);
        },
      });
    } catch (e: any) {
      console.error('[share] download failed', e);
      const msg = e?.message || 'Download failed.';
      downloadError = msg;
      bundleError = msg;
    } finally {
      downloading = new Map(downloading);
      downloading.delete(blobId);
      downloading = new Map(downloading);
    }
  }

  /**
   * Wrap a ciphertext stream in a plaintext stream using the owner-side
   * push-based pattern: a `start()` callback drives an async generator that
   * fully decouples ciphertext reads from consumer pulls. The prior pull()
   * variant stalled after pull#2 on the recipient — re-entering pull while
   * the previous one was still waiting on the relay response starved the
   * V7 frame accumulator of more bytes even though the network was still
   * delivering. Push-based keeps one long-running decrypt loop that stays
   * inside a single event-loop context.
   */
  async function buildDecryptStream(
    body: ReadableStream<Uint8Array>,
    keyB64: string,
  ): Promise<ReadableStream<Uint8Array>> {
    return new ReadableStream<Uint8Array>({
      start(controller) {
        const reader = body.getReader();
        let sessionId: string | null = null;

        async function* decryptStream(): AsyncGenerator<Uint8Array, void, undefined> {
          let headerBuf: Uint8Array = new Uint8Array(0);
          let tail: Uint8Array = new Uint8Array(0);

          // Phase 1: accumulate V7 header.
          while (sessionId === null) {
            const { value, done } = await reader.read();
            if (done) throw new Error('Stream ended before V7 header complete.');
            if (!value) continue;
            headerBuf = concat(headerBuf, value);
            if (headerBuf.byteLength >= V7_HEADER_SIZE) {
              const header = headerBuf.subarray(0, V7_HEADER_SIZE);
              const post = headerBuf.subarray(V7_HEADER_SIZE);
              const init = byoShareStreamInit(header, keyB64) as any;
              if (!init?.sessionId) {
                throw new Error(init?.error || 'Could not initialise decryptor.');
              }
              sessionId = init.sessionId;
              headerBuf = new Uint8Array(0);
              if (post.byteLength > 0) {
                tail = post.slice();
              }
            }
          }

          // Phase 2: body chunks. Retain the trailing V7_FOOTER_SIZE bytes
          // in `tail` and push the rest through the decryptor as soon as
          // it's known-body (i.e. not part of the footer).
          for (;;) {
            const { value, done } = await reader.read();
            if (done) {
              if (tail.byteLength < V7_FOOTER_SIZE) {
                throw new Error('Stream ended before V7 footer arrived.');
              }
              const footer = tail.subarray(tail.byteLength - V7_FOOTER_SIZE);
              try {
                byoShareStreamClose(sessionId!, footer) as any;
              } catch (e: any) {
                throw new Error(e?.message || 'HMAC verification failed.');
              }
              return;
            }
            if (!value || value.byteLength === 0) continue;

            const combined = concat(tail, value);
            const pushCut = Math.max(0, combined.byteLength - V7_FOOTER_SIZE);
            const toPush = combined.subarray(0, pushCut);
            const tailSlice = combined.subarray(pushCut);
            tail = new Uint8Array(tailSlice.byteLength);
            tail.set(tailSlice);
            if (toPush.byteLength > 0) {
              const pt = byoShareStreamPush(sessionId!, toPush) as any;
              if (pt instanceof Uint8Array && pt.byteLength > 0) {
                yield pt;
              }
            }
          }
        }

        (async () => {
          try {
            for await (const chunk of decryptStream()) {
              controller.enqueue(chunk);
            }
            controller.close();
          } catch (err) {
            if (sessionId !== null) {
              try {
                byoShareStreamClose(sessionId, new Uint8Array(V7_FOOTER_SIZE));
              } catch {
                /* already dropped */
              }
            }
            controller.error(err);
          } finally {
            try {
              reader.releaseLock();
            } catch {
              /* already detached */
            }
          }
        })();
      },
    });
  }

  function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    // Always allocate a fresh buffer. Returning `a` or `b` unchanged would
    // widen the return's ArrayBuffer generic (ArrayBufferLike) and poison
    // every downstream assignment; a fresh `new Uint8Array(n)` is typed
    // `Uint8Array<ArrayBuffer>`.
    const out = new Uint8Array(a.byteLength + b.byteLength);
    if (a.byteLength > 0) out.set(a, 0);
    if (b.byteLength > 0) out.set(b, a.byteLength);
    return out;
  }

  // ── User actions ───────────────────────────────────────────────────────────

  async function downloadFileShare() {
    if (!contentKeyB64 || iosBlocked) return;
    // Filename rides in the fragment as `n=<percent-encoded>`. The creator
    // embeds the original decrypted name so the recipient saves the file
    // under its real name. The fragment never reaches a server; anyone
    // with the link already has the decryption key, so exposing the name
    // alongside it adds no privacy surface.
    const nameParam = fragmentParams.get('n');
    const filename = nameParam && nameParam.length > 0
      ? nameParam
      : 'wattcloud-share.bin';
    if (iosDevice) {
      await downloadFileShareIOS(filename);
      return;
    }
    await downloadBlob(
      'main',
      contentKeyB64,
      filename,
      'application/octet-stream',
      meta?.total_bytes,
    );
  }

  /**
   * iOS single-file path — decrypt the blob into a memory-held File, then
   * expose a Save button bound to `handle.save` so the user's second tap
   * is a fresh gesture navigator.share can honour. iOS Safari's download
   * pipeline cannot consume slowly-filled Service Worker streams, so the
   * desktop SW path (saveViaServiceWorker) would truncate to a few KB.
   */
  async function downloadFileShareIOS(filename: string) {
    if (!contentKeyB64) return;
    downloadError = '';
    iosSaveError = '';
    iosSaveHandle = null;
    iosSavePending = true;
    downloading = new Map(downloading).set('main', 0);
    try {
      const resp = await fetch(
        `/relay/share/${encodeURIComponent(shareId)}/blob/main`,
      );
      if (resp.status === 404) throw new Error('Blob expired or revoked.');
      if (!resp.ok || !resp.body) {
        const limit = parseShareLimitError(resp);
        throw new Error(limit ? limit.message : `Unexpected relay response (${resp.status}).`);
      }
      const plaintextStream = await buildDecryptStream(resp.body, contentKeyB64);
      iosSaveHandle = await bufferForIOSSave(
        plaintextStream,
        filename,
        'application/octet-stream',
        {
          path: iosDecision?.path ?? 'ram',
          onProgress: (n) => {
            downloading = new Map(downloading).set('main', n);
          },
        },
      );
    } catch (e: any) {
      console.error('[share] iOS buffer failed', e);
      downloadError = e?.message || 'Download failed.';
    } finally {
      iosSavePending = false;
      downloading = new Map(downloading);
      downloading.delete('main');
      downloading = new Map(downloading);
    }
  }

  /**
   * iOS Save-button handler. Must run synchronously inside the click
   * event so the gesture propagates into navigator.share / <a download>.
   */
  function onIOSSaveTap() {
    if (!iosSaveHandle) return;
    iosSaveError = '';
    iosSaveHandle.save().catch((e: any) => {
      console.error('[share] iOS save failed', e);
      iosSaveError = e?.message || 'Could not open the share sheet.';
    });
  }

  /**
   * Bundle download — streams every blob's ciphertext → V7 decrypt →
   * client-zip → streamToDisk as a single zip. Preserves rel_path so
   * subfolders materialise inside the archive. No plaintext file list
   * is ever rendered on the landing page; names only appear inside the
   * zip the recipient extracts.
   */
  async function downloadBundleAsZip() {
    if (!contentKeyB64 || !bundleEntries) return;
    if (bundleDownloading || iosBlocked) return;
    downloadError = '';
    bundleError = '';
    iosSaveError = '';
    iosSaveHandle = null;
    bundleDownloading = true;
    bundleBytesWritten = 0;

    const entries = bundleEntries;
    const sid = shareId;

    async function* zipInputs(): AsyncIterable<ZipEntry> {
      for (const entry of entries) {
        const resp = await fetch(
          `/relay/share/${encodeURIComponent(sid)}/blob/${encodeURIComponent(entry.blob_id)}`,
        );
        if (resp.status === 404) {
          throw new Error(`Blob expired or revoked (${entry.rel_path}).`);
        }
        if (!resp.ok || !resp.body) {
          const limit = parseShareLimitError(resp);
          throw new Error(limit ? limit.message : `Unexpected relay response (${resp.status}).`);
        }
        const plaintext = await buildDecryptStream(resp.body, entry.content_key_b64);
        yield {
          name: entry.rel_path,
          input: plaintext,
          size: entry.size,
        };
      }
    }

    // Prefer the display name from the fragment when present so the
    // recipient gets a download titled "MyFolder.zip" instead of a
    // generic share-id blob.
    const base = displayName
      ? displayName.replace(/[\r\n\0\/\\]/g, '_')
      : `wattcloud-share-${sid.slice(0, 8)}`;
    const filename = base.toLowerCase().endsWith('.zip') ? base : `${base}.zip`;

    try {
      const zipStream = createZipStream(zipInputs());
      // Compute the exact zip output size up front from the manifest
      // entries — client-zip uses STORE method (no compression) so the
      // result is a precise number we can hand to streamToDisk as
      // Content-Length. Without it Firefox's download manager fails the
      // .part → final rename for SW-streamed bundles ("source file
      // could not be read"), even though the page-side pump completes.
      // predictLength's name+size pair must match what zipInputs()
      // actually emits, which is `entry.rel_path` + `entry.size`.
      let zipContentLength: number | undefined;
      try {
        zipContentLength = predictZipLength(
          entries.map((e) => ({ name: e.rel_path, size: e.size })),
        );
      } catch (predErr) {
        // Predictor failure is non-fatal — drop Content-Length and let
        // the download proceed via chunked transfer (Chrome/Safari fine,
        // Firefox finalize may fail, but no worse than before).
        console.warn('[share] predictZipLength failed; falling back to chunked', predErr);
      }
      if (iosDevice) {
        // iOS: buffer the zip (RAM or OPFS, depending on feature
        // support + quota probe), then wait for the user's Save tap.
        // On OPFS the peak memory during zip assembly is a single
        // chunk (~64 KiB); on RAM it's the whole archive.
        iosSavePending = true;
        iosSaveHandle = await bufferForIOSSave(
          zipStream,
          filename,
          'application/zip',
          {
            path: iosDecision?.path ?? 'ram',
            onProgress: (n) => {
              bundleBytesWritten = n;
            },
          },
        );
      } else {
        await streamToDisk(zipStream, filename, 'application/zip', {
          contentLength: zipContentLength,
          onProgress: (n) => {
            bundleBytesWritten = n;
          },
        });
      }
    } catch (e: any) {
      console.error('[share] zip download failed', e);
      const msg = e?.message || 'Zip download failed.';
      downloadError = msg;
      bundleError = msg;
    } finally {
      bundleDownloading = false;
      iosSavePending = false;
    }
  }

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

  function formatExpiry(unix: number): string {
    const secs = unix - Math.floor(Date.now() / 1000);
    if (secs <= 0) return 'expired';
    const days = Math.floor(secs / 86_400);
    if (days > 0) return `expires in ${days}d`;
    const hours = Math.floor(secs / 3_600);
    if (hours > 0) return `expires in ${hours}h`;
    const mins = Math.ceil(secs / 60);
    return `expires in ${mins}m`;
  }

  /** Plaintext size — used for iOS warning/block decisions. */
  let totalBytes = $derived(meta?.total_bytes ?? 0);
  $effect(() => {
    if (iosDevice && meta !== null) {
      void refreshIosDecision(totalBytes);
    }
  });
  let iosBlocked = $derived(iosDecision?.block === true);
  let iosWarn = $derived(iosDecision?.warn === true);
  /** Landing-page display name. Pulled from the fragment's `n=` field
   *  (fragment is client-only, never transmitted to the relay), so both
   *  single-file and bundle shares can show a real title. Falls back to
   *  a generic placeholder in the template when absent. */
  let displayName = $derived(fragmentParams.get('n') || '');
</script>

<main class="share-page">
  <header class="hdr">
    <div class="brand" aria-hidden="true">
      <svg viewBox="0 0 48 48" width="40" height="40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path
          d="M30 7.5 a16.5 16.5 0 0 0 -14.76 9.13 A12 12 0 1 0 13.5 40.5 H30 a16.5 16.5 0 0 0 0 -33 Z"
          stroke="hsl(142,60%,45%)"
          stroke-width="2.5"
          fill="none"
          stroke-linejoin="round"
        />
      </svg>
      <span class="brand-name">Wattcloud</span>
    </div>
    <h1 class="title">Encrypted share</h1>
    <p class="sub">
      This file was encrypted in your sender's browser. Decryption happens
      here in yours — Wattcloud's relay never sees your content or the key.
    </p>
  </header>

  {#if metaError}
    <section class="notice error" role="alert">
      <p>{metaError}</p>
    </section>
  {:else if needPassword}
    <section class="panel">
      <label for="share-password" class="lbl">Password</label>
      <input
        id="share-password"
        type="password"
        autocomplete="current-password"
        bind:value={password}
        onkeydown={(e) => {
          if (e.key === 'Enter') submitPassword();
        }}
        disabled={unwrapInProgress}
        placeholder="Enter the password the sender shared with you"
      />
      {#if unwrapError}<p class="input-err" role="alert">{unwrapError}</p>{/if}
      <button
        type="button"
        class="btn primary"
        disabled={unwrapInProgress || !password}
        onclick={submitPassword}
      >
        {unwrapInProgress ? 'Unlocking…' : 'Unlock'}
      </button>
      <p class="hint">
        This may take a few seconds — we deliberately slow password checks
        down so an attacker with the link still can't brute-force it.
      </p>
    </section>
  {:else if loadingMeta}
    <section class="panel">
      <p class="hint">Loading share…</p>
    </section>
  {:else if meta && meta.kind === 'file'}
    <!-- Display name rides in the fragment as &n=<name> — never
         transmitted to the relay, so showing it here is the same
         privacy boundary as the decryption key that sits alongside. -->
    <section class="panel">
      {#if iosBlocked}
        <p class="ios-note ios-note-block" role="alert">
          {iosBlockMessage(totalBytes, 'share', 'file', iosDecision?.path ?? 'ram')}
        </p>
      {:else if iosWarn}
        <p class="ios-note" role="note">
          {iosWarnMessage(totalBytes, 'share', 'file', iosDecision?.path ?? 'ram')}
        </p>
      {/if}
      <div class="row">
        <div>
          <p class="pri">{displayName || 'Single file'}</p>
          <p class="sec">
            {formatBytes(meta.total_bytes)} · {formatExpiry(meta.expires_at)}
          </p>
        </div>
        {#if iosSaveHandle}
          <button type="button" class="btn primary" onclick={onIOSSaveTap}>
            Save file
          </button>
        {:else}
          <button
            type="button"
            class="btn primary"
            onclick={downloadFileShare}
            disabled={iosBlocked || iosSavePending}
          >
            {iosSavePending ? 'Decrypting…' : 'Download'}
          </button>
        {/if}
      </div>
      {#if downloadError}
        <p class="input-err" role="alert">{downloadError}</p>
      {:else if iosSaveError}
        <p class="input-err" role="alert">{iosSaveError}</p>
      {:else if iosSaveHandle}
        <p class="hint">Ready ({formatBytes(iosSaveHandle.bytes)}). Tap "Save file" to choose where to store it.</p>
      {:else if downloading.get('main') !== undefined}
        <p class="hint">Decrypted {formatBytes(downloading.get('main') || 0)} so far…</p>
      {/if}
    </section>
  {:else if meta && (meta.kind === 'folder' || meta.kind === 'collection')}
    <!-- Bundle share — same panel shape as the single-file case. No
         plaintext file list: the recipient downloads a single zip and
         names (folder + inner files) materialise only on extraction. -->
    <section class="panel">
      {#if iosBlocked}
        <p class="ios-note ios-note-block" role="alert">
          {iosBlockMessage(totalBytes, 'share', 'archive', iosDecision?.path ?? 'ram')}
        </p>
      {:else if iosWarn}
        <p class="ios-note" role="note">
          {iosWarnMessage(totalBytes, 'share', 'archive', iosDecision?.path ?? 'ram')}
        </p>
      {/if}
      <div class="row">
        <div>
          <p class="pri">
            {displayName || (meta.kind === 'folder' ? 'Folder' : 'Collection')}
          </p>
          <p class="sec">
            {meta.blob_count > 0 ? meta.blob_count - 1 : 0} file{meta.blob_count - 1 === 1 ? '' : 's'}
            · {formatBytes(meta.total_bytes)} · {formatExpiry(meta.expires_at)}
          </p>
        </div>
        {#if iosSaveHandle}
          <button type="button" class="btn primary" onclick={onIOSSaveTap}>
            Save archive
          </button>
        {:else}
          <button
            type="button"
            class="btn primary"
            onclick={downloadBundleAsZip}
            disabled={!bundleEntries || bundleDownloading || iosBlocked}
          >
            {bundleDownloading ? (iosDevice ? 'Decrypting…' : 'Downloading…') : 'Download'}
          </button>
        {/if}
      </div>
      {#if bundleError && !bundleDownloading}
        <p class="input-err" role="alert">{bundleError}</p>
      {:else if iosSaveError}
        <p class="input-err" role="alert">{iosSaveError}</p>
      {:else if iosSaveHandle}
        <p class="hint">Ready ({formatBytes(iosSaveHandle.bytes)}). Tap "Save archive" to choose where to store it.</p>
      {:else if bundleEntries === null}
        <p class="hint">Preparing archive…</p>
      {:else if bundleDownloading}
        <p class="hint">Streamed {formatBytes(bundleBytesWritten)} so far…</p>
      {/if}
    </section>
  {/if}

  <footer class="foot">
    <p class="foot-line">
      Wattcloud · <a href="/">wattcloud.de</a>
    </p>
  </footer>
</main>

<style>
  .share-page {
    max-width: 640px;
    margin: 0 auto;
    padding: 2rem 1rem;
    color: var(--text-primary, #ededed);
    font-family: Inter, system-ui, sans-serif;
  }
  .hdr { text-align: center; margin-bottom: 2rem; }
  .brand { display: inline-flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
  .brand-name {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--accent-text, #5FDB8A);
  }
  .title { margin: 0.25rem 0 0.5rem; font-size: 1.5rem; font-weight: 600; }
  .sub {
    margin: 0;
    font-size: 0.9rem;
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }
  .notice {
    padding: 1rem;
    border-radius: 12px;
    background: var(--danger-muted, #3D1F1F);
    color: var(--danger, #D64545);
  }
  .notice p { margin: 0; }
  .panel {
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: 16px;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }
  .pri {
    margin: 0;
    font-size: 1rem;
    font-weight: 500;
  }
  .sec {
    margin: 0;
    font-size: 0.8125rem;
    color: var(--text-secondary, #999);
  }
  .hint {
    margin: 0;
    font-size: 0.8125rem;
    color: var(--text-secondary, #999);
  }
  .lbl {
    font-size: 0.8125rem;
    color: var(--text-secondary, #999);
  }
  input[type='password'] {
    background: var(--surface-1, #121212);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: 12px;
    color: var(--text-primary, #ededed);
    font-size: 0.9rem;
    padding: 0.625rem 0.875rem;
    width: 100%;
    box-sizing: border-box;
  }
  input[type='password']:focus {
    outline: none;
    border-color: var(--accent, #2EB860);
  }
  .input-err {
    margin: 0;
    font-size: 0.8125rem;
    color: var(--danger, #D64545);
  }
  .btn {
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-primary, #ededed);
    padding: 0.5rem 1.1rem;
    border-radius: 9999px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 120ms;
  }
  .btn:hover:not(:disabled) { background: var(--bg-surface-hover, #2E2E2E); }
  .btn.primary {
    background: var(--accent, #2EB860);
    border-color: var(--accent, #2EB860);
    color: #fff;
    font-weight: 600;
  }
  .btn.primary:hover:not(:disabled) { opacity: 0.92; }
  .btn:disabled { opacity: 0.55; cursor: not-allowed; }
  .ios-note {
    margin: 0;
    padding: 0.625rem 0.75rem;
    border-radius: 10px;
    background: rgba(255, 180, 60, 0.08);
    border: 1px solid rgba(255, 180, 60, 0.28);
    color: var(--text-secondary, #b5b5b5);
    font-size: 0.8125rem;
    line-height: 1.4;
  }
  .ios-note-block {
    background: var(--danger-muted, #3D1F1F);
    border-color: rgba(214, 69, 69, 0.4);
    color: var(--danger, #D64545);
  }
  .foot {
    margin-top: 2rem;
    text-align: center;
    font-size: 0.75rem;
    color: var(--text-secondary, #999);
  }
  .foot a { color: inherit; }
</style>
