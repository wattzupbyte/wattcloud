// OAuth / PKCE WASM bindings.
//
// PKCE generation delegates entirely to sdk-core (OsRng + SHA-256 + base64url).
// OAuth URL/form builders and token response parser are pure string/JSON operations.
// The actual HTTP fetch() and browser popup logic stay in byo/src/oauth/OAuthFlow.ts.

use sdk_core::byo::{
    build_auth_url as sdk_build_auth_url, build_refresh_form as sdk_build_refresh_form,
    build_token_exchange_form as sdk_build_token_exchange_form, generate_pkce,
    oauth::provider_oauth_config, parse_token_response as sdk_parse_token_response,
    PkcePair as CorePkcePair, ProviderType,
};
use wasm_bindgen::prelude::*;

use crate::util::js_set;

// ─── PKCE ─────────────────────────────────────────────────────────────────────

/// Generate a PKCE code verifier + SHA-256 challenge pair (RFC 7636).
///
/// Returns `{ codeVerifier: string, codeChallenge: string }` on success.
#[wasm_bindgen(js_name = generatePkce)]
pub fn generate_pkce_wasm() -> Result<JsValue, JsValue> {
    let CorePkcePair {
        code_verifier,
        code_challenge,
    } = generate_pkce().map_err(|e| JsValue::from_str(&e.to_string()))?;

    let obj = js_sys::Object::new();
    js_set(&obj, "codeVerifier", &JsValue::from_str(&code_verifier));
    js_set(&obj, "codeChallenge", &JsValue::from_str(&code_challenge));
    Ok(obj.into())
}

// ─── OAuth provider config ────────────────────────────────────────────────────

/// Return the static OAuth config for a provider type string.
///
/// `providerType` must be one of `"gdrive"`, `"dropbox"`, `"onedrive"`.
/// Returns `null` for non-OAuth providers (`"webdav"`, `"sftp"`).
/// Returns `null` for unknown strings (caller should validate before calling).
///
/// Result shape: `{ authUrl, tokenUrl, scope, extraAuthParams: [{ key, value }] }`
#[wasm_bindgen(js_name = providerOAuthConfig)]
pub fn provider_oauth_config_wasm(provider_type: &str) -> JsValue {
    let pt = match provider_type {
        "gdrive" => ProviderType::Gdrive,
        "dropbox" => ProviderType::Dropbox,
        "onedrive" => ProviderType::Onedrive,
        "webdav" => ProviderType::Webdav,
        "sftp" => ProviderType::Sftp,
        _ => return JsValue::NULL,
    };

    match provider_oauth_config(pt) {
        None => JsValue::NULL,
        Some(cfg) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "authUrl", &JsValue::from_str(cfg.auth_url));
            js_set(&obj, "tokenUrl", &JsValue::from_str(cfg.token_url));
            js_set(&obj, "scope", &JsValue::from_str(cfg.scope));

            let extras = js_sys::Array::new();
            for (k, v) in cfg.extra_auth_params {
                let pair = js_sys::Object::new();
                js_set(&pair, "key", &JsValue::from_str(k));
                js_set(&pair, "value", &JsValue::from_str(v));
                extras.push(&pair.into());
            }
            js_set(&obj, "extraAuthParams", &extras.into());
            obj.into()
        }
    }
}

// ─── URL / form builders ──────────────────────────────────────────────────────

/// Build an authorization URL for the PKCE flow.
///
/// `providerType`: `"gdrive"` | `"dropbox"` | `"onedrive"`
/// `state`: cryptographically random nonce for CSRF protection
/// `codeChallenge`: base64url(SHA-256(codeVerifier)) from generatePkce()
///
/// Throws if `providerType` has no OAuth config.
#[wasm_bindgen(js_name = buildAuthUrl)]
pub fn build_auth_url_wasm(
    provider_type: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, JsValue> {
    let pt = parse_provider_type(provider_type)?;
    let cfg = provider_oauth_config(pt)
        .ok_or_else(|| JsValue::from_str(&format!("{provider_type} does not use OAuth")))?;
    Ok(sdk_build_auth_url(
        cfg,
        client_id,
        redirect_uri,
        state,
        code_challenge,
    ))
}

/// Build the `application/x-www-form-urlencoded` body for the authorization_code grant.
#[wasm_bindgen(js_name = buildTokenExchangeForm)]
pub fn build_token_exchange_form_wasm(
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
) -> String {
    sdk_build_token_exchange_form(code, code_verifier, redirect_uri, client_id)
}

/// Build the `application/x-www-form-urlencoded` body for the refresh_token grant.
#[wasm_bindgen(js_name = buildRefreshForm)]
pub fn build_refresh_form_wasm(refresh_token: &str, client_id: &str) -> String {
    sdk_build_refresh_form(refresh_token, client_id)
}

// ─── Token response parser ────────────────────────────────────────────────────

/// Parse a JSON OAuth token response body (Uint8Array).
///
/// Returns `{ accessToken, refreshToken?, expiresIn? }` on success.
/// Throws a string on error (malformed JSON or provider error field).
#[wasm_bindgen(js_name = parseTokenResponse)]
pub fn parse_token_response_wasm(body: &[u8]) -> Result<JsValue, JsValue> {
    let r = sdk_parse_token_response(body).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let obj = js_sys::Object::new();
    js_set(&obj, "accessToken", &JsValue::from_str(&r.access_token));
    match r.refresh_token {
        Some(rt) => js_set(&obj, "refreshToken", &JsValue::from_str(&rt)),
        None => js_set(&obj, "refreshToken", &JsValue::UNDEFINED),
    }
    match r.expires_in {
        Some(exp) => js_set(&obj, "expiresIn", &JsValue::from_f64(exp as f64)),
        None => js_set(&obj, "expiresIn", &JsValue::UNDEFINED),
    }
    Ok(obj.into())
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn parse_provider_type(s: &str) -> Result<ProviderType, JsValue> {
    match s {
        "gdrive" => Ok(ProviderType::Gdrive),
        "dropbox" => Ok(ProviderType::Dropbox),
        "onedrive" => Ok(ProviderType::Onedrive),
        "webdav" => Ok(ProviderType::Webdav),
        "sftp" => Ok(ProviderType::Sftp),
        other => Err(JsValue::from_str(&format!(
            "unknown provider type: {other}"
        ))),
    }
}
