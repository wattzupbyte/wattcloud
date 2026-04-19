<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';
  import {
    byoPhotoTimeline,
    byoPhotosLoading,
    byoThumbnailCache,
    loadByoPhotoTimeline,
    loadByoThumbnail,
    resetByoPhotos,
  } from '../../byo/stores/byoPhotos';
  import type { FileEntry } from '../../byo/DataProvider';
  import FilePreview from '../FilePreview.svelte';

  export let loadFileData: ((fileId: number) => Promise<Blob>) | null = null;

  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const DAY_NAMES = ['SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'];
  const MONTH_SHORT = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  const MONTH_LONG = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];

  type TabId = 'timeline' | 'collections';
  let activeTab: TabId = 'timeline';

  let previewFile: FileEntry | null = null;
  let previewOpen = false;
  $: previewFileAny = previewFile as unknown as any;

  // Calendar strip — active month key (year-month)
  let activeMonthKey = '';
  let calendarEl: HTMLElement | null = null;
  let groupEls: Map<string, HTMLElement> = new Map();

  // Unique months in the timeline (for calendar strip)
  $: monthKeys = (() => {
    const seen = new Set<string>();
    const result: { key: string; year: number; month: number }[] = [];
    for (const g of $byoPhotoTimeline) {
      const k = `${g.year}-${g.month}`;
      if (!seen.has(k)) {
        seen.add(k);
        result.push({ key: k, year: g.year, month: g.month });
      }
    }
    return result;
  })();

  $: if (monthKeys.length > 0 && !activeMonthKey) {
    activeMonthKey = monthKeys[0].key;
  }

  function dayKey(g: { year: number; month: number; day: number }) {
    return `${g.year}-${g.month}-${g.day}`;
  }

  function monthKey(g: { year: number; month: number }) {
    return `${g.year}-${g.month}`;
  }

  function formatDayHeader(year: number, month: number, day: number): string {
    const date = new Date(year, month - 1, day);
    return `${DAY_NAMES[date.getDay()]}, ${MONTH_SHORT[month - 1]} ${day}, ${year}`;
  }

  // Scroll to month section
  function scrollToMonth(key: string) {
    activeMonthKey = key;
    // Find the first day group for this month
    const firstGroup = $byoPhotoTimeline.find((g) => monthKey(g) === key);
    if (!firstGroup) return;
    const el = groupEls.get(dayKey(firstGroup));
    if (el) el.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
    // Scroll the chip into view in the calendar strip
    tick().then(() => {
      const chip = calendarEl?.querySelector(`[data-month="${key}"]`) as HTMLElement | null;
      chip?.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest', inline: 'center' });
    });
  }

  // Intersection observer — update active month chip on scroll
  let sectionObserver: IntersectionObserver | null = null;

  function setupObserver() {
    sectionObserver?.disconnect();
    if (activeTab !== 'timeline') return;
    sectionObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const key = (entry.target as HTMLElement).dataset.monthKey ?? '';
            if (key) activeMonthKey = key;
          }
        }
      },
      { rootMargin: '-10% 0px -80% 0px', threshold: 0 },
    );
    for (const [, el] of groupEls) {
      sectionObserver.observe(el);
    }
  }

  async function ensureThumbnail(file: FileEntry) {
    if (!$byoThumbnailCache.has(file.id)) {
      await loadByoThumbnail(file);
    }
  }

  onMount(() => {
    loadByoPhotoTimeline();
  });

  onDestroy(() => {
    sectionObserver?.disconnect();
    resetByoPhotos();
  });

  // Re-setup observer when groups change (timeline tab only)
  $: if (activeTab === 'timeline' && $byoPhotoTimeline.length > 0) {
    tick().then(setupObserver);
  }

  // Disconnect observer when leaving timeline tab
  $: if (activeTab !== 'timeline') {
    sectionObserver?.disconnect();
  }

  function openPreview(file: FileEntry) {
    previewFile = file as any;
    previewOpen = true;
  }

  async function loadPreviewBlob(fileId: number): Promise<Blob> {
    if (loadFileData) return loadFileData(fileId);
    throw new Error('No loadFileData provided');
  }

  function registerGroupEl(node: HTMLElement, key: { day: string; month: string }) {
    groupEls.set(key.day, node);
    return {
      destroy() { groupEls.delete(key.day); },
    };
  }
</script>

<div class="photo-timeline">
  <!-- Timeline / Collections tabs -->
  <div class="tabs" role="tablist">
    <button
      class="tab-btn"
      class:active={activeTab === 'timeline'}
      role="tab"
      aria-selected={activeTab === 'timeline'}
      on:click={() => activeTab = 'timeline'}
    >Timeline</button>
    <button
      class="tab-btn"
      class:active={activeTab === 'collections'}
      role="tab"
      aria-selected={activeTab === 'collections'}
      on:click={() => activeTab = 'collections'}
    >Collections</button>
  </div>

  {#if activeTab === 'collections'}
    <div class="empty">
      <div aria-hidden="true">
        <svg viewBox="0 0 72 72" width="72" height="72" fill="none">
          <path d="M36 6 L60 19 L60 47 L36 60 L12 47 L12 19 Z"
            stroke="var(--text-disabled,#444)" stroke-width="2" stroke-linejoin="round" fill="none"/>
          <rect x="20" y="28" width="14" height="14" rx="2"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
          <rect x="38" y="28" width="14" height="14" rx="2"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
          <rect x="20" y="45" width="14" height="8" rx="2"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
          <rect x="38" y="45" width="14" height="8" rx="2"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
        </svg>
      </div>
      <p class="empty-heading">Coming soon</p>
      <p class="empty-sub">Collections let you organize photos into albums.</p>
    </div>

  {:else if $byoPhotosLoading && $byoPhotoTimeline.length === 0}
    <div class="loading">
      <div class="spinner"></div>
      <p>Loading photos…</p>
    </div>

  {:else if $byoPhotoTimeline.length === 0}
    <div class="empty">
      <div aria-hidden="true">
        <svg viewBox="0 0 72 72" width="72" height="72" fill="none">
          <path d="M36 6 L60 19 L60 47 L36 60 L12 47 L12 19 Z"
            stroke="var(--text-disabled,#444)" stroke-width="2" stroke-linejoin="round" fill="none"/>
          <rect x="22" y="26" width="28" height="22" rx="2"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
          <circle cx="29" cy="33" r="3" stroke="var(--text-disabled,#444)" stroke-width="1.5" fill="none"/>
          <path d="M22 42 L31 34 L38 40 L44 35 L50 42"
            stroke="var(--text-disabled,#444)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
        </svg>
      </div>
      <p class="empty-heading">No memories yet</p>
      <p class="empty-sub">Photos you upload will appear here.</p>
    </div>

  {:else}
    <!-- Calendar strip -->
    <div class="calendar-strip" bind:this={calendarEl} role="navigation" aria-label="Jump to month">
      {#each monthKeys as m (m.key)}
        <button
          class="month-chip"
          class:active={activeMonthKey === m.key}
          data-month={m.key}
          on:click={() => scrollToMonth(m.key)}
          aria-pressed={activeMonthKey === m.key}
        >
          {MONTH_SHORT[m.month - 1]} {m.year}
        </button>
      {/each}
    </div>

    <!-- Day groups -->
    {#each $byoPhotoTimeline as group (dayKey(group))}
      <section
        class="timeline-group"
        data-month-key={monthKey(group)}
        use:registerGroupEl={{ day: dayKey(group), month: monthKey(group) }}
      >
        <h3 class="group-label">{formatDayHeader(group.year, group.month, group.day)}</h3>
        <div class="photo-grid">
          {#each group.files as file (file.id)}
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <div
              class="photo-tile"
              role="button"
              tabindex="0"
              on:click={() => openPreview(file)}
              on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), openPreview(file))}
              use:lazyThumbnail={file}
            >
              {#if $byoThumbnailCache.has(file.id)}
                <img src={$byoThumbnailCache.get(file.id)} alt="" class="thumb" />
              {:else}
                <div class="thumb-placeholder">
                  <div class="spinner-sm"></div>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {/each}
  {/if}
</div>

<!-- File preview overlay -->
{#if previewOpen && previewFile}
  <FilePreview
    file={previewFileAny}
    isOpen={previewOpen}
    {loadFileData}
    onClose={() => { previewOpen = false; previewFile = null; }}
  />
{/if}

<script lang="ts" context="module">
  function lazyThumbnail(node: HTMLElement, file: import('../../byo/DataProvider').FileEntry) {
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting) {
          import('../../byo/stores/byoPhotos').then(({ loadByoThumbnail }) => {
            loadByoThumbnail(file);
          });
          observer.disconnect();
        }
      },
      { rootMargin: '100px' },
    );
    observer.observe(node);
    return { destroy() { observer.disconnect(); } };
  }
</script>

<style>
  .photo-timeline {
    padding: 0;
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  /* Tabs */
  .tabs {
    display: flex;
    gap: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) 0;
    border-bottom: 1px solid var(--border, #2E2E2E);
    flex-shrink: 0;
  }

  .tab-btn {
    background: none;
    border: none;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--text-secondary, #999);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: color 120ms, border-color 120ms;
  }

  .tab-btn.active {
    color: var(--text-primary, #EDEDED);
    border-bottom-color: var(--accent, #2EB860);
  }

  .loading, .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px) var(--sp-md, 16px);
    text-align: center;
    color: var(--text-secondary, #999999);
  }

  .empty-heading {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .empty-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    margin: 0;
  }

  .spinner {
    width: 36px;
    height: 36px;
    border: 3px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* Calendar strip */
  .calendar-strip {
    display: flex;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    overflow-x: auto;
    scrollbar-width: none;
    flex-shrink: 0;
  }
  .calendar-strip::-webkit-scrollbar { display: none; }

  .month-chip {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    white-space: nowrap;
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-secondary, #999);
    cursor: pointer;
    transition: background 120ms, color 120ms, border-color 120ms;
    flex-shrink: 0;
  }

  .month-chip.active, .month-chip:hover {
    background: var(--accent-muted, rgba(46,184,96,0.12));
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  /* Day groups */
  .timeline-group {
    margin-bottom: 0;
  }

  .group-label {
    position: sticky;
    top: 0;
    margin: 0;
    padding: 6px var(--sp-md, 16px);
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    letter-spacing: 0.04em;
    color: var(--text-secondary, #999999);
    background: var(--bg-base, #141414);
    z-index: 2;
  }

  /* Grid — §16.2: 3-col default, 5-col at ≥600px, 2px gap, no border-radius */
  .photo-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 2px;
  }

  @media (min-width: 600px) {
    .photo-grid {
      grid-template-columns: repeat(5, 1fr);
    }
  }

  .photo-tile {
    position: relative;
    aspect-ratio: 1;
    overflow: hidden;
    cursor: pointer;
    background: var(--bg-surface-raised, #262626);
  }

  .photo-tile:focus-visible {
    outline: 2px solid var(--accent, #2EB860);
    outline-offset: -2px;
    z-index: 1;
  }

  .thumb {
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }

  .thumb-placeholder {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .spinner-sm {
    width: 20px;
    height: 20px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
</style>
