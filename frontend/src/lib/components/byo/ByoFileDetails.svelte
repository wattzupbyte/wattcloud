<script lang="ts">
  import Star from 'phosphor-svelte/lib/Star';
  import type { FileEntry, FolderEntry } from '../../byo/DataProvider';
  import BottomSheet from '../BottomSheet.svelte';

  export let file: FileEntry | null = null;
  export let isOpen: boolean = false;
  export let isFavorite: boolean = false;
  export let folders: FolderEntry[] = [];
  export let onClose: () => void = () => {};

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }

  function formatDate(s: string): string {
    const d = new Date(s);
    if (isNaN(d.getTime())) return s;
    return d.toLocaleString();
  }

  function folderPath(folderId: number | null): string {
    if (folderId === null) return '/';
    const segments: string[] = [];
    let id: number | null = folderId;
    const byId = new Map(folders.map((f) => [f.id, f]));
    while (id !== null) {
      const f = byId.get(id);
      if (!f) break;
      segments.unshift(f.decrypted_name);
      id = f.parent_id;
    }
    return '/' + segments.join('/');
  }
</script>

<BottomSheet open={isOpen && !!file} title="File Details" on:close={onClose}>
  {#if file}
    <div class="details-body">
      <div class="row">
        <span class="label">Name</span>
        <span class="value name" title={file.decrypted_name}>{file.decrypted_name}</span>
      </div>
      <div class="row">
        <span class="label">Size</span>
        <span class="value">{formatSize(file.size)}</span>
      </div>
      <div class="row">
        <span class="label">Type</span>
        <span class="value">{file.mime_type || 'unknown'}</span>
      </div>
      <div class="row">
        <span class="label">Category</span>
        <span class="value">{file.file_type || '—'}</span>
      </div>
      <div class="row">
        <span class="label">Modified</span>
        <span class="value">{formatDate(file.updated_at || file.created_at)}</span>
      </div>
      <div class="row">
        <span class="label">Created</span>
        <span class="value">{formatDate(file.created_at)}</span>
      </div>
      <div class="row">
        <span class="label">Folder</span>
        <span class="value mono">{folderPath(file.folder_id)}</span>
      </div>
      <div class="row">
        <span class="label">File ID</span>
        <span class="value mono">{file.id}</span>
      </div>
      <div class="row">
        <span class="label">Provider ref</span>
        <span class="value mono ref" title={file.storage_ref}>{file.storage_ref}</span>
      </div>
      <div class="row">
        <span class="label">Favorite</span>
        <span class="value fav" class:on={isFavorite}>
          <Star size={14} weight={isFavorite ? 'fill' : 'regular'} />
          {isFavorite ? 'Yes' : 'No'}
        </span>
      </div>
    </div>
  {/if}
</BottomSheet>

<style>
  .details-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    padding: 0 var(--sp-md, 16px) var(--sp-md, 16px);
  }

  .row {
    display: grid;
    grid-template-columns: 100px 1fr;
    gap: var(--sp-sm, 8px);
    align-items: start;
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .label { color: var(--text-secondary, #999999); }

  .value {
    color: var(--text-primary, #EDEDED);
    word-break: break-word;
  }

  .value.name { font-weight: 600; }
  .value.mono { font-family: var(--font-mono, monospace); font-size: 0.75rem; }
  .value.ref { overflow-wrap: anywhere; }

  .fav {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    color: var(--text-secondary, #999);
  }
  .fav.on { color: var(--accent-warm, #E0A320); }
</style>
