<script lang="ts">
  import { createEventDispatcher, tick, onMount } from 'svelte';
  import { fly } from 'svelte/transition';
  import { searchIn, type PlaceBounds, type PlaceType } from '../data/placeBounds';
  import { placesStore, loadPlaces } from '../stores/placeBounds';
  import MagnifyingGlass from 'phosphor-svelte/lib/MagnifyingGlass';
  import MapPin from 'phosphor-svelte/lib/MapPin';
  import X from 'phosphor-svelte/lib/X';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';

  export let placeholder = 'Search country, city, region...';
  export let selected: PlaceBounds | null = null;

  const dispatch = createEventDispatcher<{ select: PlaceBounds; clear: void }>();

  let query = '';
  let results: PlaceBounds[] = [];
  let activeIndex = -1;
  let inputEl: HTMLInputElement;
  let listEl: HTMLUListElement;
  let open = false;

  onMount(() => { loadPlaces(); });

  $: {
    if (query.trim().length >= 1) {
      results = searchIn($placesStore, query, 8);
      open = results.length > 0;
      activeIndex = -1;
    } else {
      results = [];
      open = false;
    }
  }

  function select(place: PlaceBounds) { selected = place; query = ''; open = false; dispatch('select', place); }
  function clearSelection() { selected = null; query = ''; open = false; dispatch('clear'); tick().then(() => inputEl?.focus()); }
  function handleKeydown(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); activeIndex = Math.min(activeIndex + 1, results.length - 1); scrollActiveIntoView(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); activeIndex = Math.max(activeIndex - 1, 0); scrollActiveIntoView(); }
    else if (e.key === 'Enter' && activeIndex >= 0) { e.preventDefault(); select(results[activeIndex]); }
    else if (e.key === 'Escape') { open = false; activeIndex = -1; }
  }
  function scrollActiveIntoView() { tick().then(() => { const el = listEl?.querySelector(`[data-idx="${activeIndex}"]`) as HTMLElement | null; el?.scrollIntoView({ block: 'nearest' }); }); }
  function handleBlur() { setTimeout(() => { open = false; }, 150); }
  function typeBadgeLabel(type: PlaceType): string { if (type === 'country') return 'Country'; if (type === 'region') return 'Region'; return 'City'; }
</script>

<div class="place-search" class:has-selection={selected !== null}>
  {#if selected}
    <div class="selection-pill">
      {#if selected.flag}
        <span class="pill-flag">{selected.flag}</span>
      {:else}
        <MapPin size={14} />
      {/if}
      <span class="pill-name">{selected.display}</span>
      <span class="pill-badge pill-badge-{selected.type}">{typeBadgeLabel(selected.type)}</span>
      <button class="pill-clear" on:click={clearSelection} aria-label="Clear location filter"><X size={14} /></button>
    </div>
  {:else}
    <div class="input-wrap" class:open>
      <span class="input-icon"><MagnifyingGlass size={16} /></span>
      <input bind:this={inputEl} bind:value={query} {placeholder} type="text" autocomplete="off" spellcheck="false" on:keydown={handleKeydown} on:blur={handleBlur} aria-label="Search place" aria-autocomplete="list" role="combobox" aria-expanded={open} aria-controls="place-search-listbox" />
      {#if query}
        <button class="input-clear" on:click={() => { query = ''; open = false; }} aria-label="Clear search"><X size={14} /></button>
      {/if}
    </div>

    {#if open}
      <ul bind:this={listEl} class="results-list" role="listbox" id="place-search-listbox" transition:fly={{ y: -6, duration: 140 }}>
        {#each results as place, i}
          <li class="result-item" class:active={i === activeIndex} role="option" aria-selected={i === activeIndex} data-idx={i} on:mousedown|preventDefault={() => select(place)} on:mouseover={() => activeIndex = i} on:focus={() => activeIndex = i}>
            <span class="result-flag">
              {#if place.flag}{place.flag}{:else}<FolderSimple size={14} />{/if}
            </span>
            <span class="result-name">{place.display}</span>
            {#if place.parent}<span class="result-parent">{place.parent}</span>{/if}
            <span class="result-badge result-badge-{place.type}">{typeBadgeLabel(place.type)}</span>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</div>

<style>
  .place-search { position: relative; width: 100%; }

  .input-wrap {
    display: flex; align-items: center; gap: var(--sp-sm);
    padding: 0 var(--sp-md); min-height: var(--touch-target);
    background: var(--bg-input); border: 1px solid var(--border);
    border-radius: var(--r-input); transition: border-color var(--duration-normal) ease;
  }
  .input-wrap:focus-within { border-color: var(--accent); background: var(--bg-input); }
  .input-wrap.open { border-radius: var(--r-input) var(--r-input) 0 0; border-bottom-color: transparent; }
  .input-icon { color: var(--text-disabled); flex-shrink: 0; display: flex; align-items: center; }
  input {
    flex: 1; background: transparent; border: none; font-size: var(--t-body-sm-size);
    color: var(--text-primary); min-width: 0; height: var(--touch-target);
    outline: none; font-family: var(--font-sans);
  }
  input::placeholder { color: var(--text-disabled); }
  .input-clear {
    background: none; border: none; color: var(--text-disabled); cursor: pointer; padding: 0;
    display: flex; align-items: center; flex-shrink: 0; border-radius: var(--r-thumbnail);
    transition: color var(--duration-normal) ease;
  }
  .input-clear:hover { color: var(--text-primary); }

  .results-list {
    position: absolute; top: 100%; left: 0; right: 0; list-style: none;
    margin: 0; padding: var(--sp-xs) 0;
    background: var(--bg-surface-raised); border: 1px solid var(--border);
    border-top: none; border-radius: 0 0 var(--r-input) var(--r-input);
    box-shadow: var(--shadow-dropdown); max-height: 280px; overflow-y: auto; z-index: 10;
  }
  .result-item {
    display: flex; align-items: center; gap: var(--sp-sm);
    padding: var(--sp-sm) var(--sp-md); min-height: var(--touch-target);
    cursor: pointer; transition: background var(--duration-normal) ease;
    font-size: var(--t-body-sm-size);
  }
  .result-item:hover, .result-item.active { background: var(--accent-muted); }
  .result-flag { font-size: 1.1em; flex-shrink: 0; width: 1.4em; text-align: center; color: var(--text-secondary); }
  .result-name { flex: 1; font-weight: 500; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .result-parent { font-size: var(--t-label-size); color: var(--text-disabled); flex-shrink: 0; white-space: nowrap; }

  .result-badge, .pill-badge {
    font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: var(--r-pill);
    flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.04em;
  }
  .result-badge-country, .pill-badge-country { background: var(--accent-muted); color: var(--accent-text); }
  .result-badge-region, .pill-badge-region { background: var(--accent-muted); color: var(--accent-text); }
  .result-badge-city, .pill-badge-city { background: var(--accent-warm-muted); color: var(--accent-warm-text); }

  .selection-pill {
    display: flex; align-items: center; gap: var(--sp-sm);
    padding: 0 var(--sp-md); min-height: var(--touch-target);
    background: var(--accent-muted); border: 1px solid var(--accent);
    border-radius: var(--r-input); font-size: var(--t-body-sm-size); min-width: 0;
  }
  .pill-flag { font-size: 1.1em; flex-shrink: 0; }
  .pill-name { flex: 1; font-weight: 500; color: var(--accent-text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .pill-clear {
    background: none; border: none; color: var(--accent-text); cursor: pointer;
    padding: 2px; display: flex; align-items: center; flex-shrink: 0;
    border-radius: var(--r-thumbnail); transition: color var(--duration-normal) ease;
  }
  .pill-clear:hover { color: var(--text-primary); }
</style>
