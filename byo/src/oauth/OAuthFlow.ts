/**
 * Browser-based OAuth2 PKCE flow for BYO storage providers.
 *
 * Uses a popup window + postMessage pattern:
 *   1. Generate PKCE challenge (via sdk-core Rust)
 *   2. Build auth URL (via sdk-core Rust)
 *   3. Open popup with auth URL (includes code_challenge + state for CSRF)
 *   4. User authenticates with provider
 *   5. Provider redirects to /oauth/callback with authorization code
 *   6. Callback page posts code to opener via window.postMessage
 *   7. Exchange code for tokens using PKCE verifier (form body via sdk-core Rust)
 *
 * URL/form building and JSON parsing are delegated to the BYO worker (sdk-core Rust)
 * so Android and browser share the same logic. window.open, postMessage, and fetch()
 * stay here as they are platform-specific.
 */

import { OAUTH_CONFIGS, getEffectiveClientId, validateOAuthConfig } from './OAuthConfig';
import * as Worker from '../worker/byoWorkerClient';
import type { ProviderType } from '../types';

export interface OAuthResult {
  accessToken: string;
  refreshToken: string;
  /** Seconds until the access token expires. */
  expiresIn: number;
}

const OAUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Initiate the OAuth2 PKCE flow for a provider.
 * Opens a popup window for the user to authenticate.
 * Returns the access token, refresh token, and expiry.
 */
export async function initiateOAuthFlow(
  provider: 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud',
  clientIdOverride?: string,
): Promise<OAuthResult> {
  validateOAuthConfig(provider, clientIdOverride);

  const config = OAUTH_CONFIGS[provider];
  const clientId = getEffectiveClientId(provider, clientIdOverride);

  // Generate PKCE verifier+state inside the worker — verifier never touches main thread.
  await Worker.initByoWorker();
  const { state, authUrl } = await Worker.oauthBeginFlow(provider, clientId, config.redirectUri);

  // Open popup and wait for authorization code.
  // On any error (blocked popup, timeout, user close, CSRF) abort the worker flow entry.
  let code: string;
  try {
    code = await waitForAuthCode(authUrl, provider, state);
  } catch (err) {
    await Worker.oauthAbortFlow(state).catch(() => {});
    throw err;
  }

  // Build exchange form body in worker (looks up verifier by state, drops entry).
  return exchangeCodeForTokens(provider, code, state, clientId);
}

/**
 * Refresh an expired access token using a refresh token.
 * Falls back to full re-auth on invalid_grant (refresh token expired).
 */
export async function refreshAccessToken(
  provider: 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud',
  refreshToken: string,
  clientIdOverride?: string,
): Promise<OAuthResult> {
  const config = OAUTH_CONFIGS[provider];
  const clientId = getEffectiveClientId(provider, clientIdOverride);

  // Build form body via sdk-core
  await Worker.initByoWorker();
  const body = await Worker.buildRefreshForm(refreshToken, clientId);

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  // If refresh token is expired or revoked, re-auth
  if (response.status === 400 || response.status === 401) {
    return initiateOAuthFlow(provider, clientIdOverride);
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token refresh failed for ${provider}: ${text}`);
  }

  const raw = new Uint8Array(await response.arrayBuffer());
  const data = await Worker.parseTokenResponse(raw);

  return {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken || refreshToken, // Some providers don't rotate
    expiresIn: data.expiresIn ?? 3600,
  };
}

/**
 * Wait for the OAuth callback via postMessage from the popup window.
 * The popup redirects to /oauth/callback which posts the code back.
 * Validates the `state` parameter to prevent CSRF.
 */
function waitForAuthCode(authUrl: string, provider: string, expectedState: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const popup = window.open(authUrl, `byo_oauth_${provider}`, 'width=600,height=700,scrollbars=yes');

    if (!popup) {
      reject(new Error('OAuth popup blocked. Please allow popups for authentication.'));
      return;
    }

    const timeout = setTimeout(() => {
      popup.close();
      reject(new Error('OAuth flow timed out'));
    }, OAUTH_TIMEOUT_MS);

    const handleMessage = (event: MessageEvent) => {
      // Security: only accept messages from same origin (rules out cross-origin
      // attackers entirely).
      if (event.origin !== window.location.origin) return;
      // OA1: must also originate from the popup we opened. A same-origin
      // script (compromised dependency, iframe) can postMessage the page
      // and would otherwise bypass origin-only filtering.
      if (event.source !== popup) return;

      if (event.data?.type === 'byo_oauth_callback') {
        clearTimeout(timeout);
        window.removeEventListener('message', handleMessage);
        clearInterval(checkClosed);

        // OA3: CSRF check. The previous `state && state !== expected` guard
        // was truthy-gated: a payload without a `state` field would silently
        // bypass the check because `event.data.state` evaluated falsy. We
        // now require strict equality, so a missing/empty state is a reject.
        if (event.data.state !== expectedState) {
          popup.close();
          reject(new Error('OAuth state mismatch — possible CSRF attack'));
          return;
        }

        if (event.data.error) {
          reject(new Error(`OAuth error: ${event.data.error}`));
        } else if (event.data.code) {
          resolve(event.data.code);
        } else {
          reject(new Error('OAuth callback missing authorization code'));
        }
        popup.close();
      }
    };

    window.addEventListener('message', handleMessage);

    // Detect if user closes popup manually
    const checkClosed = setInterval(() => {
      if (popup.closed) {
        clearInterval(checkClosed);
        clearTimeout(timeout);
        window.removeEventListener('message', handleMessage);
        reject(new Error('OAuth popup was closed before completing authentication'));
      }
    }, 500);
  });
}

/**
 * Exchange an authorization code for access and refresh tokens.
 * The worker looks up the PKCE verifier by state and drops it after use.
 */
async function exchangeCodeForTokens(
  provider: 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud',
  code: string,
  state: string,
  _clientId: string,
): Promise<OAuthResult> {
  const config = OAUTH_CONFIGS[provider];

  // Build form body in worker — verifier never leaves worker memory.
  const { formBody: body } = await Worker.oauthBuildExchangeForm(state, code);

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token exchange failed for ${provider}: ${text}`);
  }

  const raw = new Uint8Array(await response.arrayBuffer());
  const data = await Worker.parseTokenResponse(raw);

  return {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken ?? '',
    expiresIn: data.expiresIn ?? 3600,
  };
}
