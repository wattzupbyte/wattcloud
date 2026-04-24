<!--
  CloudEncBadge — 16dp encryption indicator (DESIGN.md §29.1)
  Overlay on the bottom-right corner of encrypted file/photo thumbnails.
  A small filled cloud silhouette — the motif reads as "stored in your
  encrypted vault". No nested icon: the cloud IS the indicator.
-->
<script lang="ts">
  export let size: number = 16;
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 16 16"
  fill="none"
  xmlns="http://www.w3.org/2000/svg"
  class="cloud-enc-badge"
  aria-label="Encrypted"
  role="img"
>
  <path
    d="M10 2.5 a5.5 5.5 0 0 0 -4.92 3.04 A4 4 0 1 0 4.5 13.5 H10 a5.5 5.5 0 0 0 0 -11 Z"
    fill="var(--accent, #2EB860)"
    stroke="var(--accent, #2EB860)"
    stroke-width="1"
    stroke-linejoin="round"
  />
</svg>

<style>
  .cloud-enc-badge {
    display: block;
    flex-shrink: 0;
  }
</style>
