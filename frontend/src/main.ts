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
import { detectByoCapabilities } from './lib/byo/stores/byoCapabilities';
import {
  registerShareReceiveSW,
  shareReceiveSweepStale,
  shareReceiveCleanupSession,
} from './lib/byo/shareReceiveSW';
import { fetchMe, fetchRelayInfo, hasEnrolledHint } from './lib/byo/accessControl';
import { mount } from "svelte";

/** Stand-in /share-receive view rendered while the full inbound-share
 *  flow ships in a follow-up PR. The Web Share Target SW already stages
 *  the payload into OPFS; this view acknowledges receipt and offers to
 *  discard it so nothing lingers on the device. PR 5 replaces this with
 *  ShareReceive.svelte (unlock prompt → destination picker → upload). */
function mountShareReceivePlaceholder(target: HTMLElement, session: string): void {
  target.replaceChildren();
  const wrap = document.createElement('div');
  wrap.style.cssText =
    'max-width: 480px; margin: 64px auto; padding: 24px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #c9d1d9;';
  const h = document.createElement('h1');
  h.textContent = 'Wattcloud received your share';
  h.style.cssText = 'font-size: 20px; margin: 0 0 12px; font-weight: 600;';
  const p = document.createElement('p');
  p.textContent =
    'The receive flow is still being built — the file(s) you sent are queued in this browser only. Discard them or come back when the upload UI ships.';
  p.style.cssText = 'font-size: 14px; line-height: 1.5; color: #8b949e; margin: 0 0 16px;';
  const meta = document.createElement('p');
  meta.textContent = session ? `session: ${session}` : 'no session id present';
  meta.style.cssText = 'font-size: 12px; color: #6e7681; font-family: monospace; margin: 0 0 24px;';
  const btn = document.createElement('button');
  btn.textContent = 'Discard and go home';
  btn.style.cssText =
    'padding: 10px 16px; background: #238636; color: white; border: 0; border-radius: 6px; font-size: 14px; cursor: pointer;';
  btn.onclick = async () => {
    if (session) {
      try { await shareReceiveCleanupSession(session); } catch { /* best-effort */ }
    }
    window.location.href = '/';
  };
  wrap.appendChild(h);
  wrap.appendChild(p);
  wrap.appendChild(meta);
  wrap.appendChild(btn);
  target.appendChild(wrap);
}

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
      mount(ShareRecipient, { target: appElement });
      void prewarmDownloadServiceWorker();
      // Safety net for tabs that closed mid-download while writing to
      // OPFS. Leftover entries lie outside our per-flow cleanup, so
      // sweep on every boot — TTL-gated, no-op on non-OPFS platforms.
      void sweepOPFSPending();
      return;
    }

    // /share-receive = Web Share Target landing page. The
    // share-receive Service Worker accepted a multipart POST from
    // another app, staged the files into OPFS, and 303-redirected
    // here with ?session=<id>. Until the full PR-5 flow lands the
    // page just reports the session id and provides cleanup so the
    // staged data does not linger on the device.
    if (window.location.pathname === '/share-receive') {
      const session = new URLSearchParams(window.location.search).get('session') ?? '';
      mountShareReceivePlaceholder(appElement, session);
      void registerShareReceiveSW();
      void shareReceiveSweepStale();
      return;
    }
    // Fail-closed runtime config load. Any validation error aborts mount.
    await initRuntimeConfig();

    // Restricted-enrollment gate. On boot we probe /relay/info + the
    // identity endpoint /relay/admin/me. Outcomes when mode is `restricted`:
    //   - not bootstrapped → BootstrapClaim takes over the DOM.
    //   - bootstrapped + no device cookie + ?claim flag → BootstrapClaim
    //     in recovery mode (operator minted a fresh token via
    //     `wattcloud regenerate-claim-token` to add a new owner alongside
    //     existing ones; reached via a link on InviteEntry).
    //   - bootstrapped + no device cookie → InviteEntry.
    //   - bootstrapped + valid cookie → fall through to normal ByoApp.
    // In `open` mode (default on existing installs) the probe is fast and
    // the result is ignored. If either call fails (transient network,
    // older relay without the endpoints) we fall through to ByoApp so a
    // relay hiccup doesn't block the whole SPA.
    const wantBootstrap = new URLSearchParams(window.location.search).has('claim');
    let gated = false;
    try {
      const [info, me] = await Promise.all([fetchRelayInfo(), fetchMe()]);
      if (info.mode === 'restricted') {
        if (!info.bootstrapped) {
          mount(BootstrapClaim, { target: appElement, props: { bootstrapped: false } });
          gated = true;
        } else if (!me.device) {
          if (wantBootstrap) {
            mount(BootstrapClaim, { target: appElement, props: { bootstrapped: true } });
          } else {
            // Expired variant: this browser was enrolled once before. Show the
            // session-expired explanation so the user understands what happened,
            // not just "enter an invite."
            mount(InviteEntry, {
              target: appElement,
              props: { expired: hasEnrolledHint() },
            });
          }
          gated = true;
        }
      }
    } catch (e) {
      console.warn('[main] access-control probe failed — continuing with normal boot', e);
    }
    if (gated) return;

    mount(ByoApp, { target: appElement });
    detectByoCapabilities();
    void prewarmDownloadServiceWorker();
    void sweepOPFSPending();
    void registerShareReceiveSW();
    void shareReceiveSweepStale();
  } catch (e) {
    console.error('Failed to mount Wattcloud app:', e);
    showError(appElement, e instanceof Error ? e.message : String(e));
  }
}

void boot();
