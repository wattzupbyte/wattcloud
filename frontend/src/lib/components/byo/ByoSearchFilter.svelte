<script lang="ts">
  import {
    byoSearchQuery,
    byoSearchFilters,
    byoSearchResults,
    isByoSearching,
    hasByoActiveFilters,
    setByoSearchQuery,
    setByoFileTypeFilter,
    clearByoSearch,
  } from '../../byo/stores/byoSearch';
  import type { FileEntry } from '../../byo/DataProvider';
  import MagnifyingGlass from 'phosphor-svelte/lib/MagnifyingGlass';
  import X from 'phosphor-svelte/lib/X';
  import Funnel from 'phosphor-svelte/lib/Funnel';
  import Files from 'phosphor-svelte/lib/Files';
  import Image from 'phosphor-svelte/lib/Image';
  import FileText from 'phosphor-svelte/lib/FileText';
  import VideoCamera from 'phosphor-svelte/lib/VideoCamera';
  import MusicNote from 'phosphor-svelte/lib/MusicNote';
  import FileZip from 'phosphor-svelte/lib/FileZip';
  import FileCode from 'phosphor-svelte/lib/FileCode';

  export let onResultsChange: ((results: FileEntry[]) => void) | null = null;

  $: if (onResultsChange) onResultsChange($byoSearchResults);

  const FILE_TYPE_OPTIONS: Array<{ value: string; label: string; Icon: any }> = [
    { value: '', label: 'All types', Icon: Files },
    { value: 'image', label: 'Images', Icon: Image },
    { value: 'document', label: 'Documents', Icon: FileText },
    { value: 'video', label: 'Videos', Icon: VideoCamera },
    { value: 'audio', label: 'Audio', Icon: MusicNote },
    { value: 'archive', label: 'Archives', Icon: FileZip },
    { value: 'code', label: 'Code', Icon: FileCode },
  ];

  let showFilters = false;
</script>

<div class="search-filter">
  <div class="search-row">
    <div class="search-input-wrap">
      <MagnifyingGlass size={18} class="search-icon" />
      <input
        type="text"
        placeholder="Search files…"
        value={$byoSearchQuery}
        on:input={(e) => setByoSearchQuery(e.currentTarget.value)}
        class="search-input"
        aria-label="Search files"
      />
      {#if $byoSearchQuery}
        <button class="clear-btn" on:click={clearByoSearch} aria-label="Clear search">
          <X size={16} />
        </button>
      {/if}
    </div>

    <button
      class="filter-btn"
      class:active={$hasByoActiveFilters}
      on:click={() => showFilters = !showFilters}
      aria-label="Toggle filters"
    >
      <Funnel size={18} />
    </button>
  </div>

  {#if showFilters}
    <div class="filter-row">
      <div class="filter-chips">
        {#each FILE_TYPE_OPTIONS as opt}
          <button
            class="chip"
            class:active={($byoSearchFilters.fileType ?? '') === opt.value}
            on:click={() => setByoFileTypeFilter(opt.value || null)}
            title={opt.label}
          >
            <svelte:component this={opt.Icon} size={14} />
            <span class="chip-label">{opt.label}</span>
          </button>
        {/each}
      </div>
    </div>
  {/if}

  {#if $isByoSearching}
    <p class="search-status">Searching…</p>
  {:else if $hasByoActiveFilters && $byoSearchResults.length > 0}
    <p class="search-status">{$byoSearchResults.length} result{$byoSearchResults.length !== 1 ? 's' : ''}</p>
  {:else if $hasByoActiveFilters && !$isByoSearching}
    <p class="search-status">No results</p>
  {/if}
</div>

<style>
  .search-filter {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px);
    background: var(--glass-bg, rgba(28, 28, 28, 0.65));
    backdrop-filter: var(--glass-blur-light, blur(12px));
    -webkit-backdrop-filter: var(--glass-blur-light, blur(12px));
    border: var(--glass-border, 1px solid rgba(255, 255, 255, 0.08));
    border-radius: var(--r-input, 12px);
    box-shadow: var(--glass-shadow, 0 8px 32px rgba(0, 0, 0, 0.4));
  }

  .search-row {
    display: flex;
    gap: var(--sp-xs, 4px);
    align-items: center;
  }

  .search-input-wrap {
    flex: 1;
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: 0 var(--sp-sm, 8px);
    background: var(--bg-input, #212121);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    min-height: 44px;
    color: var(--text-disabled, #616161);
  }

  .search-input {
    flex: 1;
    background: transparent;
    border: none;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    outline: none;
  }

  .search-input::placeholder { color: var(--text-disabled, #616161); }

  .clear-btn {
    background: none;
    border: none;
    color: var(--text-disabled, #616161);
    cursor: pointer;
    padding: 0;
    display: flex;
    align-items: center;
  }

  .clear-btn:hover { color: var(--text-secondary, #999999); }

  .filter-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 44px;
    height: 44px;
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-secondary, #999999);
    cursor: pointer;
    transition: all 150ms;
  }

  .filter-btn.active {
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
    background: var(--accent-muted, #1B3627);
  }

  .filter-btn:hover:not(.active) {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }

  .filter-row {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .filter-chips {
    display: flex;
    gap: var(--sp-xs, 4px);
    flex-wrap: wrap;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    background: var(--bg-surface, #1C1C1C);
    color: var(--text-secondary, #999999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    transition: all 150ms;
    white-space: nowrap;
  }

  .chip:hover { background: var(--bg-surface-hover, #2E2E2E); color: var(--text-primary, #EDEDED); }
  .chip.active { background: var(--accent, #2EB860); border-color: var(--accent, #2EB860); color: var(--text-inverse, #0A0A0A); }

  @media (max-width: 599px) {
    .chip .chip-label { display: none; }
    .chip.active .chip-label { display: inline; }
  }

  .search-status {
    margin: 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    padding: 0 var(--sp-sm, 8px);
  }
</style>
