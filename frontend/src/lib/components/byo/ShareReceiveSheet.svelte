<script lang="ts">
  /**
   * ShareReceiveSheet — destination picker + auto-upload for inbound
   * Web Share Target sessions.
   *
   * The /share-receive landing page bounces the user here with a
   * `?share-session=<id>` URL param. ByoApp captures the id, waits for
   * the vault to unlock, then mounts this sheet so the user can pick a
   * provider + folder and trigger uploads. The flow:
   *
   *   1. Read the staged session from OPFS (meta.json + each staged
   *      file). Files come back as real `File` objects suitable for
   *      `dataProvider.uploadFile`.
   *   2. Show a provider switcher (multi-provider vaults only) and a
   *      flat folder picker scoped to the active provider.
   *   3. On "Upload here", drop each file into the existing
   *      byoUploadQueue + dataProvider.uploadFile pipeline so progress
   *      shows in the same toast/seal as a normal `<input type="file">`
   *      upload. Per-file success records the share_audit row and a
   *      ShareOsInbound stats event.
   *   4. After all uploads finish (or user cancels / discards), the
   *      OPFS staging directory is purged via the share-receive SW.
   *
   * Plaintext lives in OPFS only; the staged files are read once into
   * memory (as File objects backed by the OPFS handles) and passed
   * straight into `uploadFile`, which streams them into the V7 worker
   * encryption pipeline. No new plaintext-at-rest surface.
   */

  import { onMount } from 'svelte';
  import { vaultStore, type ProviderMeta } from '../../byo/stores/vaultStore';
  import { byoUploadQueue } from '../../byo/stores/byoUploadQueue';
  import { byoToast } from '../../byo/stores/byoToasts';
  import { shareReceiveCleanupSession } from '../../byo/shareReceiveSW';
  import { recordEvent } from '@wattcloud/sdk';
  import type { DataProvider, FolderEntry } from '../../byo/DataProvider';
  import BottomSheet from '../BottomSheet.svelte';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import House from 'phosphor-svelte/lib/House';
  import HardDrives from 'phosphor-svelte/lib/HardDrives';
  import CloudArrowUp from 'phosphor-svelte/lib/CloudArrowUp';
  import Trash from 'phosphor-svelte/lib/Trash';

  interface StagedFileMeta {
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
    files: StagedFileMeta[];
  }

  interface Props {
    open: boolean;
    sessionId: string | null;
    dataProvider: DataProvider;
    onClose: () => void;
  }

  let { open, sessionId, dataProvider, onClose }: Props = $props();

  let meta: ShareMeta | null = $state(null);
  let stagedFiles: File[] = $state([]);
  let loadError: string | null = $state(null);
  let loading = $state(false);

  let folders: FolderEntry[] = $state([]);
  let folderSearch = $state('');
  let selectedFolderId: number | null = $state(null);
  let selectRoot = $state(false);
  let foldersLoading = $state(false);

  let uploading = $state(false);
  let activeProviderId = $derived($vaultStore.activeProviderId);
  let providers = $derived($vaultStore.providers);

  let hasDestination = $derived(selectRoot || selectedFolderId !== null);
  let filteredFolders = $derived((() => {
    const q = folderSearch.trim().toLowerCase();
    const list = q
      ? folders.filter((f) => (f.decrypted_name || '').toLowerCase().includes(q))
      : folders.slice();
    return list.sort((a, b) =>
      (a.decrypted_name || '').localeCompare(b.decrypted_name || ''),
    );
  })());

  // Re-fetch the folder list whenever the active provider changes,
  // because listAllFolders is provider-scoped and the user is allowed
  // to switch destinations from inside the sheet.
  $effect(() => {
    if (!open) return;
    void activeProviderId; // track
    void loadFolders();
  });

  $effect(() => {
    if (open && sessionId) void loadStagedSession(sessionId);
    if (!open) {
      meta = null;
      stagedFiles = [];
      loadError = null;
      selectedFolderId = null;
      selectRoot = false;
      folderSearch = '';
    }
  });

  async function loadStagedSession(id: string) {
    loading = true;
    try {
      if (typeof navigator === 'undefined' || !navigator.storage?.getDirectory) {
        loadError = 'This browser cannot read the staged share.';
        return;
      }
      const root = await navigator.storage.getDirectory();
      const stage = await root.getDirectoryHandle('share-staging');
      const dir = await stage.getDirectoryHandle(id);
      const metaHandle = await dir.getFileHandle('meta.json');
      const metaFile = await metaHandle.getFile();
      const parsed = JSON.parse(await metaFile.text()) as ShareMeta;

      const files: File[] = [];
      for (const entry of parsed.files) {
        const fh = await dir.getFileHandle(entry.stagedAs);
        const raw = await fh.getFile();
        // Replace the OPFS-sanitized name with the original filename so
        // the uploaded vault row reads naturally.
        files.push(new File([raw], entry.name || entry.stagedAs, {
          type: entry.type || raw.type || 'application/octet-stream',
          lastModified: raw.lastModified,
        }));
      }
      meta = parsed;
      stagedFiles = files;
    } catch (e: any) {
      console.warn('[share-receive-sheet] could not load session', id, e);
      loadError = 'This share has already been processed or expired.';
    } finally {
      loading = false;
    }
  }

  async function loadFolders() {
    foldersLoading = true;
    try {
      folders = await dataProvider.listAllFolders();
    } catch (e) {
      console.warn('[share-receive-sheet] listAllFolders failed', e);
      folders = [];
    } finally {
      foldersLoading = false;
    }
  }

  function pickFolder(id: number) {
    selectedFolderId = id;
    selectRoot = false;
  }

  function pickRoot() {
    selectRoot = true;
    selectedFolderId = null;
  }

  async function handleUpload() {
    if (!hasDestination || stagedFiles.length === 0 || !sessionId) return;
    const folderId = selectRoot ? null : selectedFolderId;
    uploading = true;

    let successes = 0;
    let failures = 0;
    for (const file of stagedFiles) {
      const itemId = byoUploadQueue.addFile(file, folderId);
      byoUploadQueue.setStatus(itemId, 'encrypting');
      byoUploadQueue.setPhase(itemId, 'encrypting');
      try {
        const row = await dataProvider.uploadFile(
          folderId,
          file,
          (bytes) => {
            const progress = file.size > 0 ? Math.round((bytes / file.size) * 90) : 45;
            byoUploadQueue.updateProgress(itemId, progress);
            byoUploadQueue.updateBytes(itemId, bytes, file.size);
            byoUploadQueue.setStatus(itemId, 'uploading');
            byoUploadQueue.setPhase(itemId, 'uploading');
          },
          { pauseSignal: byoUploadQueue.getPauseSignal(itemId) },
        );
        byoUploadQueue.updateProgress(itemId, 100);
        byoUploadQueue.updateBytes(itemId, file.size, file.size);
        byoUploadQueue.setStatus(itemId, 'completed');
        byoUploadQueue.setPhase(itemId, 'idle');
        successes += 1;
        // Audit + stats per uploaded file. The hint carries the source
        // app's optional `url` field if present (chat apps often pass
        // a deeplink there); otherwise null. Fire-and-forget — neither
        // path should block the next upload on failure.
        const hint = meta?.url ? meta.url.slice(0, 256) : null;
        dataProvider
          .recordShareAudit('inbound', String(row.id), hint)
          .catch((e) => console.warn('[share-receive-sheet] audit failed', e));
        recordEvent('share_os_inbound');
      } catch (e: any) {
        byoUploadQueue.setStatus(itemId, 'error', e?.message ?? 'Upload failed');
        byoUploadQueue.setPhase(itemId, 'idle');
        failures += 1;
      }
    }

    uploading = false;
    if (failures === 0) {
      byoToast.show(
        successes === 1
          ? 'Shared file uploaded.'
          : `${successes} shared files uploaded.`,
        { icon: 'seal' },
      );
    } else {
      byoToast.show(
        `${successes}/${stagedFiles.length} shared files uploaded — see queue for failures.`,
        { icon: 'warn' },
      );
    }

    // Always purge OPFS staging once the loop is done — partial
    // failures stay visible in byoUploadQueue (with retry), they don't
    // need to keep the staged copy around.
    await shareReceiveCleanupSession(sessionId).catch(() => {});
    onClose();
  }

  async function handleDiscard() {
    if (sessionId) {
      await shareReceiveCleanupSession(sessionId).catch(() => {});
    }
    onClose();
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

  function selectProvider(id: string) {
    if (id === activeProviderId) return;
    vaultStore.setActiveProviderId(id);
    selectedFolderId = null;
    selectRoot = false;
  }

  // Defensive: warn the user if the open call slipped through with a
  // missing session id (defensive against URL tampering or a stale
  // ?share-session=<id> param after staging was already swept).
  onMount(() => {
    if (open && !sessionId) onClose();
  });
</script>

<BottomSheet
  open={open}
  title="Save shared files to Wattcloud"
  subtitle={meta?.text || meta?.title || ''}
  variant="wide"
  onClose={uploading ? () => {} : handleDiscard}
>
  <div class="body">
    {#if loading}
      <p class="muted">Reading staged share…</p>
    {:else if loadError}
      <p class="error">{loadError}</p>
      <div class="actions">
        <button class="btn-primary" onclick={onClose}>Close</button>
      </div>
    {:else if meta}
      <section class="files" aria-label="Shared files">
        <h3>{stagedFiles.length} {stagedFiles.length === 1 ? 'file' : 'files'} from another app</h3>
        <ul>
          {#each meta.files as f}
            <li>
              <span class="file-name" title={f.name}>{f.name}</span>
              <span class="file-meta">{f.type || 'application/octet-stream'} · {formatBytes(f.size)}</span>
            </li>
          {/each}
        </ul>
      </section>

      {#if providers.length > 1}
        <section class="picker" aria-label="Pick a provider">
          <h3><HardDrives size={14} /> Provider</h3>
          <div class="provider-row">
            {#each providers as p (p.providerId)}
              <button
                type="button"
                class="provider-pill"
                class:active={p.providerId === activeProviderId}
                disabled={uploading}
                onclick={() => selectProvider(p.providerId)}
              >
                {p.displayName}
              </button>
            {/each}
          </div>
        </section>
      {/if}

      <section class="picker" aria-label="Pick a folder">
        <h3><FolderSimple size={14} /> Destination folder</h3>
        <input
          type="search"
          class="search"
          placeholder="Search folders…"
          bind:value={folderSearch}
          disabled={uploading}
        />
        <ul class="folder-list">
          <li>
            <button
              type="button"
              class="folder-row"
              class:selected={selectRoot}
              disabled={uploading}
              onclick={pickRoot}
            >
              <House size={16} />
              <span>Vault root</span>
            </button>
          </li>
          {#if foldersLoading}
            <li class="muted">Loading folders…</li>
          {:else if filteredFolders.length === 0 && folderSearch}
            <li class="muted">No folders match “{folderSearch}”.</li>
          {:else}
            {#each filteredFolders as folder (folder.id)}
              <li>
                <button
                  type="button"
                  class="folder-row"
                  class:selected={folder.id === selectedFolderId}
                  disabled={uploading}
                  onclick={() => pickFolder(folder.id)}
                >
                  <FolderSimple size={16} />
                  <span>{folder.decrypted_name || '—'}</span>
                </button>
              </li>
            {/each}
          {/if}
        </ul>
      </section>

      <div class="actions">
        <button
          type="button"
          class="btn-secondary"
          onclick={handleDiscard}
          disabled={uploading}
        >
          <Trash size={16} /> Discard
        </button>
        <button
          type="button"
          class="btn-primary"
          onclick={handleUpload}
          disabled={!hasDestination || uploading || stagedFiles.length === 0}
        >
          <CloudArrowUp size={16} />
          {uploading
            ? 'Uploading…'
            : `Upload ${stagedFiles.length} ${stagedFiles.length === 1 ? 'file' : 'files'}`}
        </button>
      </div>
    {/if}
  </div>
</BottomSheet>

<style>
  .body {
    padding: 4px 4px 16px;
    color: var(--text-primary, #c9d1d9);
    display: flex;
    flex-direction: column;
    gap: 18px;
  }
  .muted { color: var(--text-secondary, #8b949e); font-size: 13px; }
  .error { color: var(--danger, #f85149); font-size: 14px; }

  .files h3, .picker h3 {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary, #8b949e);
    margin: 0 0 8px;
    font-weight: 600;
  }
  .files ul {
    list-style: none;
    padding: 0;
    margin: 0;
    border: 1px solid var(--border, #30363d);
    border-radius: 8px;
    overflow: hidden;
    max-height: 160px;
    overflow-y: auto;
  }
  .files li {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border, #30363d);
  }
  .files li:last-child { border-bottom: 0; }
  .file-name {
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .file-meta { font-size: 11px; color: var(--text-secondary, #8b949e); }

  .provider-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .provider-pill {
    background: transparent;
    border: 1px solid var(--border, #30363d);
    color: var(--text-secondary, #8b949e);
    border-radius: 999px;
    padding: 6px 12px;
    font-size: 13px;
    cursor: pointer;
  }
  .provider-pill.active {
    background: var(--accent-muted, rgba(46, 160, 67, 0.15));
    border-color: var(--accent, #2ea043);
    color: var(--text-primary, #c9d1d9);
  }
  .provider-pill:disabled { opacity: 0.6; cursor: not-allowed; }

  .search {
    width: 100%;
    background: var(--bg-surface, #0d1117);
    border: 1px solid var(--border, #30363d);
    color: var(--text-primary, #c9d1d9);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 13px;
    margin-bottom: 8px;
  }

  .folder-list {
    list-style: none;
    padding: 0;
    margin: 0;
    border: 1px solid var(--border, #30363d);
    border-radius: 8px;
    overflow: hidden;
    max-height: 240px;
    overflow-y: auto;
  }
  .folder-list li { border-bottom: 1px solid var(--border, #30363d); }
  .folder-list li:last-child { border-bottom: 0; }
  .folder-list li.muted { padding: 10px 12px; }

  .folder-row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    text-align: left;
    background: transparent;
    border: 0;
    padding: 10px 12px;
    color: var(--text-primary, #c9d1d9);
    cursor: pointer;
    font-size: 13px;
  }
  .folder-row:hover:not(:disabled) {
    background: var(--bg-surface-raised, #161b22);
  }
  .folder-row.selected {
    background: var(--accent-muted, rgba(46, 160, 67, 0.15));
  }
  .folder-row:disabled { cursor: not-allowed; opacity: 0.6; }

  .actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 4px;
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
  .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
  .btn-secondary {
    background: transparent;
    color: var(--text-secondary, #8b949e);
    border: 1px solid var(--border, #30363d);
  }
  .btn-secondary:hover:not(:disabled) { color: var(--text-primary, #c9d1d9); }
  .btn-secondary:disabled { opacity: 0.6; cursor: not-allowed; }
</style>
