/**
 * OAuth2 configuration for BYO storage providers.
 *
 * Client IDs + base URL come from the runtime config (see runtimeConfig.ts),
 * which is fetched from `/config.json` at SPA boot. No server-side secrets
 * are needed — all flows use PKCE.
 *
 * The redirect URI points to a callback page in the BYO SPA that posts the
 * authorization code back to the opener via window.postMessage.
 */

import { getRuntimeConfig } from '../runtimeConfig';

export interface OAuthProviderConfig {
  clientId: string;
  authUrl: string;
  tokenUrl: string;
  scope: string;
  /** Redirect URI — must match the OAuth app configuration. */
  redirectUri: string;
  /** Extra params appended to the auth URL (e.g., access_type=offline). */
  extraAuthParams?: Record<string, string>;
}

type ProviderKey = 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud';

/**
 * OAuth2 configuration per provider. Client IDs + base URL are resolved from
 * the runtime config each call so hot-reload scenarios (tests) see fresh values.
 */
function buildConfigs(): Record<ProviderKey, OAuthProviderConfig> {
  const { baseUrl, clientIds } = getRuntimeConfig();
  const redirectUri = `${baseUrl}/oauth/callback`;
  return {
    gdrive: {
      clientId: clientIds.gdrive,
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      scope: 'https://www.googleapis.com/auth/drive.file',
      redirectUri,
      extraAuthParams: {
        access_type: 'offline',
        prompt: 'consent',
      },
    },
    dropbox: {
      clientId: clientIds.dropbox,
      authUrl: 'https://www.dropbox.com/oauth2/authorize',
      tokenUrl: 'https://api.dropboxapi.com/oauth2/token',
      scope: 'files.content.write files.content.read',
      redirectUri,
      extraAuthParams: {
        token_access_type: 'offline',
      },
    },
    onedrive: {
      clientId: clientIds.onedrive,
      authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      scope: 'Files.ReadWrite offline_access',
      redirectUri,
    },
    box: {
      clientId: clientIds.box,
      authUrl: 'https://account.box.com/api/oauth2/authorize',
      tokenUrl: 'https://api.box.com/oauth2/token',
      scope: 'root_readwrite',
      redirectUri,
    },
    pcloud: {
      clientId: clientIds.pcloud,
      // pCloud has separate US and EU auth endpoints. Default to US.
      // EU users must configure the region during setup; the EU endpoint is
      // https://eapi.pcloud.com/oauth2/authorize with token at https://eapi.pcloud.com/oauth2_token
      authUrl: 'https://my.pcloud.com/oauth2/authorize',
      tokenUrl: 'https://api.pcloud.com/oauth2_token',
      scope: '',
      redirectUri,
    },
  };
}

/**
 * Proxy that reads from `buildConfigs()` on every property access. Existing
 * callers (`OAUTH_CONFIGS[provider]`) continue to work, but the underlying
 * client IDs now come from `/config.json` instead of build-time env vars.
 */
export const OAUTH_CONFIGS: Record<ProviderKey, OAuthProviderConfig> =
  new Proxy({} as Record<ProviderKey, OAuthProviderConfig>, {
    get(_target, prop: string) {
      if (prop === 'gdrive' || prop === 'dropbox' || prop === 'onedrive' ||
          prop === 'box' || prop === 'pcloud') {
        return buildConfigs()[prop as ProviderKey];
      }
      return undefined;
    },
  });

/**
 * Return the effective OAuth client ID for a provider.
 * Prefers the user-supplied override (from ProviderConfig.clientId) over the
 * build-time environment variable. This allows self-hosters to bring their own
 * OAuth application without rebuilding the frontend.
 */
export function getEffectiveClientId(
  provider: 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud',
  override?: string,
): string {
  return (override && override.trim()) ? override.trim() : OAUTH_CONFIGS[provider].clientId;
}

/**
 * Validate that the OAuth client ID is configured for a given provider.
 * Accepts an optional user-supplied override that takes priority over the env var.
 * Throws at runtime if neither is configured.
 */
export function validateOAuthConfig(
  provider: 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud',
  override?: string,
): void {
  const clientId = getEffectiveClientId(provider, override);
  if (!clientId) {
    throw new Error(
      `OAuth client ID not configured for ${provider}. ` +
      `Set clientIds.${provider} in /config.json (deploy-vps.sh writes this ` +
      `file from the operator's .env), or supply a clientId in the provider configuration.`,
    );
  }
}