<!--
  CloudBadge — The Vault motif (DESIGN.md §29.1)
  Phosphor-style cloud silhouette. Two variants:
    outline — duotone body (tinted fill) under a crisp outline stroke.
              The default; used as the brand motif.
    solid   — saturated fill + stroke. Used for small inline badges.

  No composite variants: the cloud is never drawn with another icon inside
  it. Callers that need to communicate "locked", "encrypted", or "sealed"
  use the relevant Phosphor icon on its own, not layered over this badge.
-->
<script lang="ts">
  export let size: number = 24;
  export let variant: 'outline' | 'solid' = 'outline';
  export let color: string = 'var(--accent)';
  export let fillColor: string = 'var(--accent-muted)';

  // Phosphor-style cloud path on a 48x48 viewBox.
  // pathLength=100 normalises the path so stroke-dash animations in
  // VaultLockAnimation / PullToRefresh can animate dashoffset 100→0
  // regardless of any future path tweaks.
  const cloudPath = 'M30 7.5 a16.5 16.5 0 0 0 -14.76 9.13 A12 12 0 1 0 13.5 40.5 H30 a16.5 16.5 0 0 0 0 -33 Z';
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 48 48"
  fill="none"
  xmlns="http://www.w3.org/2000/svg"
  class="cloud-badge"
  aria-hidden="true"
>
  {#if variant === 'solid'}
    <path
      d={cloudPath}
      fill={fillColor}
      stroke={color}
      stroke-width="2"
      stroke-linejoin="round"
    />
  {:else}
    <!-- Duotone: tinted body under a crisp outline. One shape, two passes. -->
    <path d={cloudPath} fill={fillColor} opacity="0.45" />
    <path
      d={cloudPath}
      stroke={color}
      stroke-width="2.5"
      stroke-linejoin="round"
      fill="none"
    />
  {/if}
</svg>

<style>
  .cloud-badge {
    display: inline-block;
    vertical-align: middle;
    flex-shrink: 0;
    max-width: 128px;
    max-height: 128px;
  }
</style>
