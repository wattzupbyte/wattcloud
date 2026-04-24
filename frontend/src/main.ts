// Inter font — self-hosted via @fontsource to avoid CSP/CORS issues with Google Fonts
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';

import './lib/styles/design-system.css';
import './lib/styles/component-classes.css';

import { initRuntimeConfig } from '@wattcloud/sdk';
import ByoApp from './lib/components/byo/ByoApp.svelte';
import BootstrapClaim from './lib/components/byo/BootstrapClaim.svelte';
import InviteEntry from './lib/components/byo/InviteEntry.svelte';
import ShareRecipient from './lib/components/share/ShareRecipient.svelte';
import { prewarmDownloadServiceWorker, sweepOPFSPending } from './lib/byo/streamToDisk';
import { fetchMe, fetchRelayInfo, hasEnrolledHint } from './lib/byo/accessControl';

function showError(element: HTMLElement, message: string): void {
  const errorDiv = document.createElement('div');
  errorDiv.style.cssText = 'padding: 20px; color: red;';
  const heading = document.createElement('h1');
  heading.textContent = 'Error';
  errorDiv.appendChild(heading);
  const pre = document.createElement('pre');
  pre.textContent = message || 'Unknown error';
  errorDiv.appendChild(pre);
  element.appendChild(errorDiv);
}

async function boot(): Promise<void> {
  const appElement = document.getElementById('app');
  if (!appElement) {
    console.error('CRITICAL: #app element not found in DOM');
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'padding: 20px; color: red;';
    errorDiv.textContent = 'Error: App container not found';
    document.body.appendChild(errorDiv);
    return;
  }
  try {
    // /s/<share_id> = recipient landing page. Mount a standalone component
    // that has no vault, no login, no device enrollment — one-shot download
    // flow only. initRuntimeConfig is skipped because the recipient never
    // speaks to a provider OAuth endpoint.
    if (window.location.pathname.startsWith('/s/')) {
      new ShareRecipient({ target: appElement });
      void prewarmDownloadServiceWorker();
      // Safety net for tabs that closed mid-download while writing to
      // OPFS. Leftover entries lie outside our per-flow cleanup, so
      // sweep on every boot — TTL-gated, no-op on non-OPFS platforms.
      void sweepOPFSPending();
      return;
    }
    // Fail-closed runtime config load. Any validation error aborts mount.
    await initRuntimeConfig();

    // Restricted-enrollment gate. On boot we probe /relay/info + the
    // identity endpoint /relay/admin/me. Three outcomes when mode is
    // `restricted`:
    //   - not bootstrapped → BootstrapClaim takes over the DOM.
    //   - bootstrapped + no device cookie → InviteEntry.
    //   - bootstrapped + valid cookie → fall through to normal ByoApp.
    // In `open` mode (default on existing installs) the probe is fast and
    // the result is ignored. If either call fails (transient network,
    // older relay without the endpoints) we fall through to ByoApp so a
    // relay hiccup doesn't block the whole SPA.
    let gated = false;
    try {
      const [info, me] = await Promise.all([fetchRelayInfo(), fetchMe()]);
      if (info.mode === 'restricted') {
        if (!info.bootstrapped) {
          new BootstrapClaim({ target: appElement });
          gated = true;
        } else if (!me.device) {
          // Expired variant: this browser was enrolled once before. Show the
          // session-expired explanation so the user understands what happened,
          // not just "enter an invite."
          new InviteEntry({
            target: appElement,
            props: { expired: hasEnrolledHint() },
          });
          gated = true;
        }
      }
    } catch (e) {
      console.warn('[main] access-control probe failed — continuing with normal boot', e);
    }
    if (gated) return;

    new ByoApp({ target: appElement });
    void prewarmDownloadServiceWorker();
    void sweepOPFSPending();
  } catch (e) {
    console.error('Failed to mount Wattcloud app:', e);
    showError(appElement, e instanceof Error ? e.message : String(e));
  }
}

void boot();
