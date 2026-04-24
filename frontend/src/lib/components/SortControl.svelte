<script lang="ts">
	import type { SortingState, SortBy, SortDirection } from '../stores/sorting';
	import CalendarBlank from 'phosphor-svelte/lib/CalendarBlank';
	import TextAa from 'phosphor-svelte/lib/TextAa';
	import ArrowDown from 'phosphor-svelte/lib/ArrowDown';
	import ArrowUp from 'phosphor-svelte/lib/ArrowUp';

	export let sorting: SortingState;
	export let onByChange: (by: SortBy) => void;
	export let onToggleDirection: () => void;

	const sortByOptions: { value: SortBy; label: string; icon: 'calendar' | 'name' }[] = [
		{ value: 'date', label: 'Date', icon: 'calendar' },
		{ value: 'name', label: 'Name', icon: 'name' }
	];
</script>

<div class="sort-control">
	<!-- Sort By Toggle -->
	<div class="sort-by">
		{#each sortByOptions as option}
			<button
				class="sort-option"
				class:active={sorting.by === option.value}
				on:click={() => onByChange(option.value)}
				title={`Sort by ${option.label}`}
			>
				{#if option.icon === 'calendar'}
					<CalendarBlank size={16} />
				{:else}
					<TextAa size={16} />
				{/if}
				<span class="sort-label">{option.label}</span>
			</button>
		{/each}
	</div>

	<!-- Sort Direction Toggle -->
	<button
		class="sort-direction"
		on:click={onToggleDirection}
		title={sorting.direction === 'down' ? 'Descending (newest first)' : 'Ascending (oldest first)'}
	>
		{#if sorting.direction === 'down'}
			<ArrowDown size={16} />
		{:else}
			<ArrowUp size={16} />
		{/if}
	</button>
</div>

<style>
	.sort-control {
		display: flex;
		align-items: center;
		gap: var(--sp-xs);
		background-color: var(--bg-input);
		border: 1px solid var(--border);
		border-radius: var(--r-pill);
		padding: var(--sp-xs);
		height: 36px;
	}

	.sort-by {
		display: flex;
		gap: 2px;
	}

	.sort-option {
		display: flex;
		align-items: center;
		gap: var(--sp-xs);
		padding: var(--sp-xs) var(--sp-sm);
		background: transparent;
		border: none;
		border-radius: var(--r-pill);
		color: var(--text-secondary);
		font-size: var(--t-body-sm-size);
		font-family: var(--font-sans);
		cursor: pointer;
		transition: all var(--duration-fast) ease;
		white-space: nowrap;
		height: 28px;
	}

	.sort-option:hover {
		background-color: var(--bg-surface-hover);
		color: var(--text-primary);
	}

	.sort-option.active {
		background-color: var(--accent);
		color: var(--text-inverse);
	}

	.sort-label {
		display: none;
	}

	@media (min-width: 600px) {
		.sort-label {
			display: inline;
		}
	}

	.sort-direction {
		width: 28px;
		height: 28px;
		display: flex;
		align-items: center;
		justify-content: center;
		background: transparent;
		border: none;
		border-radius: var(--r-pill);
		color: var(--text-secondary);
		cursor: pointer;
		transition: all var(--duration-fast) ease;
		flex-shrink: 0;
	}

	.sort-direction:hover {
		background-color: var(--bg-surface-hover);
		color: var(--text-primary);
	}
</style>
