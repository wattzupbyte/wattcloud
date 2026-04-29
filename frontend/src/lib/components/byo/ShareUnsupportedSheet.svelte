<script lang="ts">
  /**
   * ShareUnsupportedSheet — explainer + remediation when the OS share
   * sheet is unreachable.
   *
   * The "Send to..." affordance is shown unconditionally so self-hosters
   * with hardened browsers (RFP, fingerprinting protection, uBlock) get
   * a discoverable feature instead of a silently-missing one. When the
   * Web Share API is missing — or `canShare({files})` rejects on per-MIME
   * grounds — this sheet tells the user *why* and what to flip to enable
   * it.
   *
   * Detection runs at sheet open time (not boot) so it reflects the live
   * state after a user re-enables a setting and reloads.
   */
  import BottomSheet from '../BottomSheet.svelte';
  import Warning from 'phosphor-svelte/lib/Warning';
  import ShieldCheck from 'phosphor-svelte/lib/ShieldCheck';
  import Browser from 'phosphor-svelte/lib/Browser';
  import Lightning from 'phosphor-svelte/lib/Lightning';

  interface Props {
    open: boolean;
    /** What kind of failure are we explaining?
     *   - 'missing-api': navigator.share is absent (most common — privacy gates)
     *   - 'files-rejected': share() exists but canShare({files}) returned false
     *     for the actual selection (Safari MIME gate, FF Linux, etc.) */
    reason: 'missing-api' | 'files-rejected';
    onClose: () => void;
  }

  const { open, reason, onClose }: Props = $props();

  // Best-effort UA classification for tailored steps. We never gate
  // behavior on this — the steps for all browsers are listed; this just
  // controls which section comes first.
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  const isFirefox = /Firefox\//.test(ua) && !/Seamonkey\//.test(ua);
  const isSafari = /Safari\//.test(ua) && !/Chrome|Chromium|Edg\//.test(ua);
  const isChromium = /Chrome|Chromium|Edg\//.test(ua);

  // Live snapshot for the diagnostic line at the bottom of the sheet.
  // Refreshed each time the sheet opens (the values are read in template
  // expressions and Svelte re-evaluates on prop change).
  function snapshot() {
    return {
      share: typeof navigator !== 'undefined' && typeof navigator.share === 'function',
      canShare: typeof navigator !== 'undefined' && typeof navigator.canShare === 'function',
      secure: typeof window !== 'undefined' ? window.isSecureContext : false,
    };
  }
  let diag = $derived(open ? snapshot() : { share: false, canShare: false, secure: false });
</script>

<BottomSheet
  {open}
  variant="wide"
  title={reason === 'missing-api' ? 'Send to… isn’t available here' : 'Browser refused these files'}
  {onClose}
>
  {#if reason === 'missing-api'}
    <p class="lead">
      Wattcloud uses your browser’s <strong>Web Share API</strong> to hand
      files to the OS share sheet. Your browser isn’t exposing that API
      right now, so this gesture can’t open. Common causes — pick the one
      that matches your setup:
    </p>

    {#if isFirefox}
      <section class="cause">
        <h3><ShieldCheck size={20} weight="duotone" /> Firefox fingerprinting protection</h3>
        <p>
          Firefox strips the Web Share API in Strict tracking-protection
          mode and when <code>privacy.resistFingerprinting</code> is on,
          to reduce browser fingerprintability. Either of these will
          remove <code>navigator.share</code> entirely.
        </p>
        <ol>
          <li>Open <code>about:preferences#privacy</code> → Browser
            Privacy. If you’re on <strong>Strict</strong>, switch to
            <strong>Standard</strong> (or <strong>Custom</strong> with
            “Block fingerprinters” unchecked) and reload this tab.</li>
          <li>If <code>about:config</code> is reachable, check
            <code>privacy.resistFingerprinting</code> and
            <code>privacy.fingerprintingProtection</code> — both should
            be <code>false</code> for the Web Share API to surface.</li>
        </ol>
      </section>
    {/if}

    <section class="cause">
      <h3><Lightning size={20} weight="duotone" /> Browser extension</h3>
      <p>
        uBlock Origin (with the “Annoyances/Privacy” lists), Privacy
        Badger, NoScript, and a few others inject overrides that delete
        <code>navigator.share</code>. Whitelisting Wattcloud restores it.
      </p>
      <ol>
        <li>Click your blocker’s toolbar icon and pause it for this
          site, or add Wattcloud to its allow-list.</li>
        <li>Reload the page.</li>
      </ol>
    </section>

    <section class="cause">
      <h3><Browser size={20} weight="duotone" /> Private / incognito window</h3>
      <p>
        Some browsers gate Web Share in private mode. Try a regular
        window, or try a different browser:
      </p>
      <ul>
        <li><strong>Chromium-based</strong> (Chrome, Edge, Brave, Vivaldi) — broad support, and required for inbound shares <em>into</em> Wattcloud.</li>
        <li><strong>Safari</strong> on macOS / iOS — outbound works; inbound is unsupported by Apple.</li>
        <li><strong>Firefox</strong> — outbound works once the fingerprinting protections above are relaxed; inbound is unsupported.</li>
      </ul>
    </section>

    {#if !isFirefox}
      <section class="cause">
        <h3><ShieldCheck size={20} weight="duotone" /> Privacy-hardened browser?</h3>
        <p>
          If you’re running a custom user.js (Arkenfox, Betterfox), Tor
          Browser, or LibreWolf, the same fingerprinting prefs apply
          there too — see the Firefox steps above for the relevant
          toggles.
        </p>
      </section>
    {/if}
  {:else}
    <p class="lead">
      Your browser supports the Web Share API but refused this specific
      selection. Most often this is a per-file-type restriction:
    </p>
    <ul>
      <li><strong>Safari (macOS / iOS)</strong> only allows sharing certain MIME types — images and PDFs reliably; many other types are rejected. There’s no per-site fix; downloading the file and sharing it from the OS file picker is the workaround.</li>
      <li><strong>Firefox on Linux</strong> doesn’t support file shares at all (only text/url shares).</li>
      <li>Some desktop builds reject very large payloads (&gt;~200&nbsp;MB).</li>
    </ul>
  {/if}

  <p class="why">
    <Warning size={16} /> <strong>Why does Wattcloud need Web Share?</strong>
    The “Send to…” gesture is the only way a browser can hand a file to
    the OS share sheet without first writing it to disk — keeping your
    plaintext off your local filesystem. There is no fallback that
    preserves that property; if Web Share is blocked, downloading the
    file and re-attaching from the file picker is the alternative.
  </p>

  <p class="diag">
    <small>
      Diagnostics: <code>share={diag.share ? 'function' : 'undefined'}</code>
      · <code>canShare={diag.canShare ? 'function' : 'undefined'}</code>
      · <code>secureContext={String(diag.secure)}</code>
      {#if isFirefox}· Firefox{:else if isChromium}· Chromium{:else if isSafari}· Safari{/if}
    </small>
  </p>
</BottomSheet>

<style>
  .lead {
    margin: 0 0 16px;
    color: var(--text-primary, #c9d1d9);
    line-height: 1.5;
  }
  .cause {
    margin: 0 0 18px;
    padding: 14px 16px;
    border: 1px solid var(--border, #30363d);
    border-radius: 8px;
    background: var(--bg-surface-raised, #161b22);
  }
  .cause h3 {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0 0 8px;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary, #c9d1d9);
  }
  .cause p,
  .cause ol,
  .cause ul {
    margin: 6px 0;
    color: var(--text-secondary, #8b949e);
    font-size: 13px;
    line-height: 1.5;
  }
  .cause ol,
  .cause ul {
    padding-left: 20px;
  }
  .cause code,
  .why code,
  .diag code {
    background: var(--bg-canvas, #0d1117);
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 12px;
    color: var(--text-primary, #c9d1d9);
  }
  .why {
    margin: 16px 0 8px;
    padding: 12px 14px;
    border-left: 3px solid var(--accent, #2ea043);
    background: var(--bg-canvas, #0d1117);
    color: var(--text-secondary, #8b949e);
    font-size: 13px;
    line-height: 1.5;
    display: flex;
    gap: 8px;
    align-items: flex-start;
  }
  .why :global(svg) {
    flex-shrink: 0;
    margin-top: 2px;
    color: var(--accent, #2ea043);
  }
  .diag {
    margin: 8px 0 0;
    color: var(--text-secondary, #8b949e);
    font-size: 12px;
  }
</style>
