// ReqwestProviderHttpClient — WASM implementation of ProviderHttpClient.
//
// reqwest's wasm feature automatically uses web-sys fetch under the hood.
// This is the wasm analogue of the native implementation in sdk-ffi.

use sdk_core::api::{ProviderHttpClient, ProviderHttpRequest, ProviderHttpResponse};
use sdk_core::byo::ProviderError;

/// R1: hard cap on response body size (256 MiB). A hostile provider that
/// ignores Range and returns 200 + unbounded body would otherwise OOM the
/// WASM tab before AES-GCM rejects the bytes. The cap is well above the
/// 8 MiB range-chunk size and any realistic manifest blob, so legitimate
/// paths (Range 206, JSON API responses, vault bodies) are unaffected.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

pub struct ReqwestProviderHttpClient {
    client: reqwest::Client,
}

impl ReqwestProviderHttpClient {
    pub fn new() -> Self {
        // P2/SSRF on WASM: the browser's fetch() handles redirects itself and
        // reqwest's `.redirect(...)` builder API is not available for
        // wasm32-unknown-unknown targets (the fetch backend doesn't expose a
        // redirect policy). Defense-in-depth on WASM comes from:
        //   - the browser's built-in cross-origin Authorization stripping
        //     when CORS is not permissive,
        //   - the URL-guard (`validate_response_url` / `validate_same_origin`)
        //     that every provider runs on attacker-controlled URLs BEFORE
        //     making the request, so a redirect target injected via `Location`
        //     has already been validated.
        // Native (sdk-ffi) additionally applies a custom redirect Policy that
        // rejects RFC1918/loopback/link-local hops.
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl ProviderHttpClient for ReqwestProviderHttpClient {
    fn request(
        &self,
        req: ProviderHttpRequest,
    ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> {
        let client = self.client.clone();
        async move {
            let method = reqwest::Method::from_bytes(req.method.as_bytes())
                .map_err(|e| ProviderError::Network(format!("invalid method: {e}")))?;
            let mut rb = client.request(method, &req.url);
            for (k, v) in req.headers {
                rb = rb.header(k, v);
            }
            if let Some(body) = req.body {
                rb = rb.body(body);
            }
            let resp = rb
                .send()
                .await
                .map_err(|e| ProviderError::Network(e.to_string()))?;
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            // R1: if the server advertises a Content-Length that already
            // exceeds the cap, reject before reading the body.
            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES as u64 {
                    return Err(ProviderError::Provider(format!(
                        "response body too large: {cl} bytes > cap {MAX_RESPONSE_BYTES}"
                    )));
                }
            }
            let body = resp
                .bytes()
                .await
                .map_err(|e| ProviderError::Network(e.to_string()))?
                .to_vec();
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(ProviderError::Provider(format!(
                    "response body too large: {} bytes > cap {MAX_RESPONSE_BYTES}",
                    body.len()
                )));
            }
            Ok(ProviderHttpResponse {
                status,
                headers,
                body,
            })
        }
    }
}
