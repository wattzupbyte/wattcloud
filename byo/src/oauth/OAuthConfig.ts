/**
 * OAuth2 configuration for BYO storage providers.
 *
 * Client IDs are injected at build time via VITE_* environment variables.
 * No server-side secrets are needed — all flows use PKCE.
 *
 * The redirect URI points to a callback page in the BYO SPA that posts the
 * authorization code back to the opener via window.postMessage.
 */

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

// Base URL for redirect URIs. Defaults to localhost in dev.
const BASE_URL = import.meta.env.VITE_BYO_BASE_URL ||
  (import.meta.env.DEV ? 'http://localhost:5173' : '');

/**
 * OAuth2 configuration per provider.
 * Client IDs must be configured via environment variables at build time.
 */
export const OAUTH_CONFIGS: Record<'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud', OAuthProviderConfig> = {
  gdrive: {
    clientId: import.meta.env.VITE_BYO_GDRIVE_CLIENT_ID || '',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'https://www.googleapis.com/auth/drive.file',
    redirectUri: `${BASE_URL}/oauth/callback`,
    extraAuthParams: {
      access_type: 'offline',    // Request refresh token
      prompt: 'consent',          // Force consent to get new refresh token
    },
  },
  dropbox: {
    clientId: import.meta.env.VITE_BYO_DROPBOX_CLIENT_ID || '',
    authUrl: 'https://www.dropbox.com/oauth2/authorize',
    tokenUrl: 'https://api.dropboxapi.com/oauth2/token',
    scope: 'files.content.write files.content.read',
    redirectUri: `${BASE_URL}/oauth/callback`,
    extraAuthParams: {
      token_access_type: 'offline', // Required to receive a refresh token from Dropbox
    },
  },
  onedrive: {
    clientId: import.meta.env.VITE_BYO_ONEDRIVE_CLIENT_ID || '',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scope: 'Files.ReadWrite offline_access',
    redirectUri: `${BASE_URL}/oauth/callback`,
  },
  box: {
    clientId: import.meta.env.VITE_BYO_BOX_CLIENT_ID || '',
    authUrl: 'https://account.box.com/api/oauth2/authorize',
    tokenUrl: 'https://api.box.com/oauth2/token',
    scope: 'root_readwrite',
    redirectUri: `${BASE_URL}/oauth/callback`,
  },
  pcloud: {
    clientId: import.meta.env.VITE_BYO_PCLOUD_CLIENT_ID || '',
    // pCloud has separate US and EU auth endpoints. Default to US.
    // EU users must configure the region during setup; the EU endpoint is
    // https://eapi.pcloud.com/oauth2/authorize with token at https://eapi.pcloud.com/oauth2_token
    authUrl: 'https://my.pcloud.com/oauth2/authorize',
    tokenUrl: 'https://api.pcloud.com/oauth2_token',
    scope: '',  // pCloud uses no explicit scopes in PKCE flow
    redirectUri: `${BASE_URL}/oauth/callback`,
  },
};

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
      `Set the VITE_BYO_${provider.toUpperCase()}_CLIENT_ID environment variable ` +
      `or supply a clientId in the provider configuration.`,
    );
  }
}