/*
 * Share-receive Service Worker — handles inbound Web Share Target POSTs.
 *
 * The PWA manifest's `share_target` block at /manifest.json declares
 *   action: "/share-receive", method: "POST", enctype: multipart/form-data.
 * Any chat / mail / OS app on the user's device can then offer Wattcloud
 * as a share destination. When the user picks Wattcloud, the OS POSTs
 * the share payload here.
 *
 * This SW reads the multipart body once, stages each file into an OPFS
 * directory under /share-staging/<sessionId>/, drops a meta.json sidecar
 * for the title/text/url form fields, and replies with a 303 redirect
 * to /share-receive?session=<sessionId>. The browser then navigates the
 * (auto-opened, standalone) PWA to that URL where the page-side flow
 * picks up the staged files and walks the user through unlock +
 * destination picker + upload.
 *
 * Scope: /share-receive/ (implicit from this file's path). Distinct
 * scope from /dl/ so a regression in one can't brick the other.
 *
 * Plaintext only ever sits in OPFS — never posted back through
 * postMessage to clients — to keep the JS heap clean during the SW →
 * page handoff. OPFS entries are origin-scoped and not visible to the
 * source app. Stale sessions are reaped by the page on next boot
 * (1 hour TTL).
 */

const STAGING_DIR_NAME = 'share-staging';
const SESSION_TTL_MS = 60 * 60 * 1000;

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'POST') return;
  if (url.pathname !== '/share-receive') return;
  event.respondWith(handleShareReceive(event.request));
});

async function handleShareReceive(request) {
  let sessionId = '';
  try {
    const formData = await request.formData();
    sessionId = randomSessionId();
    const dir = await ensureStagingDir(sessionId);

    const meta = {
      schema: 1,
      createdAt: Date.now(),
      title: stringField(formData, 'title'),
      text: stringField(formData, 'text'),
      url: stringField(formData, 'url'),
      files: [],
    };

    let i = 0;
    for (const value of formData.getAll('files')) {
      if (!(value instanceof Blob)) continue;
      const safeName = sanitizeFilename(value.name || `file_${i}`);
      const stagedAs = `${i}-${safeName}`;
      const fh = await dir.getFileHandle(stagedAs, { create: true });
      const writable = await fh.createWritable();
      // Stream the blob through pipeTo so very large attachments don't
      // materialise as one ArrayBuffer in the SW heap.
      await value.stream().pipeTo(writable);
      meta.files.push({
        name: value.name || `file_${i}`,
        type: value.type || 'application/octet-stream',
        size: value.size,
        stagedAs,
      });
      i++;
    }

    await writeMeta(dir, meta);

    // 303 forces the browser to GET the redirect target — the receive
    // page then opens the staged session.
    return Response.redirect(`/share-receive?session=${sessionId}`, 303);
  } catch (err) {
    console.error('[sw-share-receive] failed', err);
    if (sessionId) {
      // Best-effort cleanup of partial staging.
      cleanupSession(sessionId).catch(() => {});
    }
    return new Response('Share receive failed.', { status: 500 });
  }
}

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  if (data.type === 'share-cleanup' && typeof data.sessionId === 'string') {
    event.waitUntil(cleanupSession(data.sessionId));
    return;
  }

  if (data.type === 'share-sweep') {
    event.waitUntil(sweepStaleSessions());
    return;
  }
});

async function ensureStagingDir(sessionId) {
  const root = await navigator.storage.getDirectory();
  const stage = await root.getDirectoryHandle(STAGING_DIR_NAME, { create: true });
  return stage.getDirectoryHandle(sessionId, { create: true });
}

async function writeMeta(dir, meta) {
  const fh = await dir.getFileHandle('meta.json', { create: true });
  const writable = await fh.createWritable();
  await writable.write(JSON.stringify(meta));
  await writable.close();
}

async function cleanupSession(sessionId) {
  try {
    const root = await navigator.storage.getDirectory();
    const stage = await root.getDirectoryHandle(STAGING_DIR_NAME);
    await stage.removeEntry(sessionId, { recursive: true });
  } catch {
    /* best-effort */
  }
}

async function sweepStaleSessions() {
  try {
    const root = await navigator.storage.getDirectory();
    const stage = await root.getDirectoryHandle(STAGING_DIR_NAME);
    const cutoff = Date.now() - SESSION_TTL_MS;
    // Use the .entries() async iterator; older Safaris lack it, but
    // this SW only fires on Chromium (per browser matrix in plan).
    for await (const [name, handle] of stage.entries()) {
      if (handle.kind !== 'directory') continue;
      let stale = true;
      try {
        const metaHandle = await handle.getFileHandle('meta.json');
        const file = await metaHandle.getFile();
        const meta = JSON.parse(await file.text());
        if (typeof meta.createdAt === 'number' && meta.createdAt >= cutoff) {
          stale = false;
        }
      } catch {
        // Missing or corrupt meta.json → orphan. Reap.
      }
      if (stale) {
        try { await stage.removeEntry(name, { recursive: true }); } catch { /* drop */ }
      }
    }
  } catch {
    /* no staging dir yet, or other transient — try again on next boot */
  }
}

function stringField(form, key) {
  const v = form.get(key);
  return typeof v === 'string' ? v : '';
}

/**
 * Trim a user-supplied filename to a small ASCII-safe slug. The original
 * filename is preserved in meta.json — this is just the on-disk name to
 * keep OPFS happy and avoid path traversal issues.
 */
function sanitizeFilename(name) {
  const stripped = String(name).replace(/[^A-Za-z0-9._-]/g, '_');
  return stripped.slice(0, 100) || 'file';
}

function randomSessionId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}
