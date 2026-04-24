<script context="module" lang="ts">
  export type ViewType = 'files' | 'photos' | 'favorites' | 'settings';
</script>

<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import Image from 'phosphor-svelte/lib/Image';
  import Star from 'phosphor-svelte/lib/Star';
  import GearSix from 'phosphor-svelte/lib/GearSix';
  export let activeView: ViewType = 'files';

  const dispatch = createEventDispatcher();

  const navItems: { id: ViewType; label: string; icon: any }[] = [
    { id: 'files', label: 'Files', icon: FolderSimple },
    { id: 'photos', label: 'Photos', icon: Image },
    { id: 'favorites', label: 'Favorites', icon: Star },
    { id: 'settings', label: 'Settings', icon: GearSix },
  ];

  function handleNavClick(id: ViewType) {
    dispatch('navigate', { view: id });
  }
</script>

<nav class="bottom-nav" aria-label="Main navigation">
  {#each navItems as item}
    <button
      class="nav-item"
      class:active={activeView === item.id}
      on:click={() => handleNavClick(item.id)}
      aria-label={item.label}
      aria-current={activeView === item.id ? 'page' : undefined}
    >
      <svelte:component
        this={item.icon}
        size={24}
        weight={activeView === item.id ? 'fill' : 'regular'}
        color={activeView === item.id ? 'var(--accent)' : 'var(--text-secondary)'}
      />
      <span
        class="nav-item-label"
        style:color={activeView === item.id ? 'var(--accent)' : 'var(--text-secondary)'}
      >{item.label}</span>
    </button>
  {/each}
</nav>
