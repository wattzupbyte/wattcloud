<script lang="ts">
  /**
   * ShareReceive — landing view for the Web Share Target flow.
   *
   * The /share-receive Service Worker has already accepted the
   * multipart POST from the source app and staged each attachment
   * into OPFS under /share-staging/<sessionId>/. This component reads
   * the staging directory back out, shows the user what was received
   * (title/text/url + filenames + sizes), and gives them two paths:
   *
   *   - Open Wattcloud to upload — leaves the staging directory intact
   *     and navigates to the main app at `/?share-session=<id>`. ByoApp
   *     reads that param, runs the normal vault-unlock flow if needed,
   *     then ByoDashboard pops a destination-picker sheet that drains
   *     the staged files into the standard upload pipeline.
   *   - Discard — sends the share-cleanup message to the SW, which
   *     deletes the entire staging directory, then returns home.
   *
   * The receive page is mounted standalone (no vault context, no
   * device cookie, no relay calls) so it works whether or not the
   * user is currently signed into Wattcloud. Plaintext stays in OPFS
   * — this component does not pull file bytes into the JS heap.
   */
  import { onMount } from 'svelte';
  import { shareReceiveCleanupSession } from '../../byo/shareReceiveSW';
  import PaperPlaneTilt from 'phosphor-svelte/lib/PaperPlaneTilt';
  import Trash from 'phosphor-svelte/lib/Trash';
  import ArrowSquareOut from 'phosphor-svelte/lib/ArrowSquareOut';

  interface StagedFile {
    name: string;
    type: string;
    size: number;
    stagedAs: string;
  }

  interface ShareMeta {
    schema: number;
    createdAt: number;
    title: string;
    text: string;
    url: string;
    files: StagedFile[];
  }

  let { session = '' }: { session?: string } = $props();

  let loading = $state(true);
  let meta: ShareMeta | null = $state(null);
  let error: string | null = $state(null);

  onMount(() => {
    void loadStagedSession();
  });

  async function loadStagedSession() {
    if (!session) {
      error = 'No share session in URL.';
      loading = false;
      return;
    }
    if (typeof navigator === 'undefined' || !navigator.storage?.getDirectory) {
      error = 'This browser cannot read the staged share. Open Wattcloud on a Chromium-based browser to receive shares.';
      loading = false;
      return;
    }
    try {
      const root = await navigator.storage.getDirectory();
      const stage = await root.getDirectoryHandle('share-staging');
      const dir = await stage.getDirectoryHandle(session);
      const metaHandle = await dir.getFileHandle('meta.json');
      const metaFile = await metaHandle.getFile();
      const parsed = JSON.parse(await metaFile.text()) as ShareMeta;
      meta = parsed;
    } catch (e: any) {
      console.warn('[share-receive] could not load session', session, e);
      error = 'This share has already been processed or expired.';
    } finally {
      loading = false;
    }
  }

  async function discard() {
    if (session) {
      try { await shareReceiveCleanupSession(session); } catch { /* best-effort */ }
    }
    window.location.href = '/';
  }

  function openWattcloud() {
    // Hand the session id to ByoApp via the URL — its boot reads
    // `?share-session=<id>` and once the vault unlocks ByoDashboard
    // pops a destination-picker sheet that drains OPFS staging into
    // the upload queue.
    if (session) {
      const u = new URL('/', window.location.origin);
      u.searchParams.set('share-session', session);
      window.location.href = u.pathname + u.search;
      return;
    }
    window.location.href = '/';
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
</script>

<div class="share-receive">
  <header class="head">
    <div class="icon-wrap">
      <PaperPlaneTilt size={32} />
    </div>
    <h1>Wattcloud received your share</h1>
  </header>

  {#if loading}
    <p class="muted">Reading staged share…</p>
  {:else if error}
    <p class="error">{error}</p>
    <div class="actions">
      <button class="btn-primary" onclick={() => (window.location.href = '/')}>
        <ArrowSquareOut size={16} /> Go to Wattcloud
      </button>
    </div>
  {:else if meta}
    {#if meta.title || meta.text || meta.url}
      <section class="prompt">
        {#if meta.title}<div class="prompt-title">{meta.title}</div>{/if}
        {#if meta.text}<p class="prompt-text">{meta.text}</p>{/if}
        {#if meta.url}<a class="prompt-url" href={meta.url} rel="noopener noreferrer">{meta.url}</a>{/if}
      </section>
    {/if}

    <section class="files">
      <h2>{meta.files.length} {meta.files.length === 1 ? 'file' : 'files'}</h2>
      <ul>
        {#each meta.files as f}
          <li>
            <span class="file-name" title={f.name}>{f.name}</span>
            <span class="file-meta">{f.type || 'application/octet-stream'} · {formatBytes(f.size)}</span>
          </li>
        {/each}
      </ul>
    </section>

    <p class="note">
      Open Wattcloud to pick a destination folder and upload these
      files end-to-end encrypted, or discard the staged copy.
    </p>

    <div class="actions">
      <button class="btn-secondary" onclick={discard}>
        <Trash size={16} /> Discard
      </button>
      <button class="btn-primary" onclick={openWattcloud}>
        <ArrowSquareOut size={16} /> Open Wattcloud
      </button>
    </div>
  {/if}
</div>

<style>
  .share-receive {
    max-width: 520px;
    margin: 64px auto;
    padding: 24px;
    color: var(--text-primary, #c9d1d9);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
    color: var(--accent, #2ea043);
  }
  .head h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 600;
    color: var(--text-primary, #c9d1d9);
  }
  .icon-wrap {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    background: var(--accent-muted, rgba(46, 160, 67, 0.15));
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .muted {
    color: var(--text-secondary, #8b949e);
    font-size: 14px;
  }
  .error {
    color: var(--danger, #f85149);
    font-size: 14px;
    margin-bottom: 16px;
  }
  .prompt {
    background: var(--bg-surface-raised, #161b22);
    border: 1px solid var(--border, #30363d);
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 20px;
  }
  .prompt-title { font-weight: 600; margin-bottom: 4px; }
  .prompt-text {
    margin: 4px 0;
    font-size: 14px;
    color: var(--text-secondary, #8b949e);
    white-space: pre-wrap;
  }
  .prompt-url {
    display: inline-block;
    margin-top: 4px;
    color: var(--accent, #2ea043);
    text-decoration: none;
    font-size: 13px;
    word-break: break-all;
  }
  .files h2 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary, #8b949e);
    margin: 0 0 8px;
    font-weight: 600;
  }
  .files ul {
    list-style: none;
    padding: 0;
    margin: 0 0 24px;
    border: 1px solid var(--border, #30363d);
    border-radius: 8px;
    overflow: hidden;
  }
  .files li {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border, #30363d);
  }
  .files li:last-child { border-bottom: 0; }
  .file-name {
    font-size: 14px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .file-meta {
    font-size: 12px;
    color: var(--text-secondary, #8b949e);
  }
  .note {
    font-size: 13px;
    color: var(--text-secondary, #8b949e);
    line-height: 1.5;
    margin: 0 0 20px;
  }
  .actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .btn-primary, .btn-secondary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 10px 16px;
    border: 0;
    border-radius: 6px;
    font-size: 14px;
    cursor: pointer;
    font-weight: 500;
  }
  .btn-primary {
    background: var(--accent, #2ea043);
    color: white;
  }
  .btn-secondary {
    background: transparent;
    color: var(--text-secondary, #8b949e);
    border: 1px solid var(--border, #30363d);
  }
  .btn-secondary:hover { color: var(--text-primary, #c9d1d9); }
</style>
