// HTTP client abstraction for BYO storage provider implementations.
//
// Unlike `HttpClient` (relative-path, managed-backend, sync), this trait:
//   - Takes absolute URLs
//   - Accepts arbitrary headers
//   - Is async (providers hit third-party REST APIs)
//   - Is NOT tied to a base URL or auth model
//
// Concrete implementations:
//   sdk-ffi: reqwest (native/Android)
//   sdk-wasm: reqwest wasm feature (browser fetch)
//
// sdk-core never provides a concrete implementation — the crate has no I/O.

use crate::byo::ProviderError;

// ─── Request / Response ───────────────────────────────────────────────────────

/// An HTTP request to a storage provider endpoint.
#[derive(Debug, Clone)]
pub struct ProviderHttpRequest {
    /// HTTP method: "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
    /// "PROPFIND", "MKCOL" (WebDAV).
    pub method: String,
    /// Absolute URL.
    pub url: String,
    /// Request headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

impl ProviderHttpRequest {
    /// Create a request with an arbitrary method. Used for WebDAV methods
    /// (PROPFIND, MKCOL) and HEAD.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: vec![],
            body: None,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new("GET", url)
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self::new("POST", url)
    }

    pub fn put(url: impl Into<String>) -> Self {
        Self::new("PUT", url)
    }

    pub fn patch(url: impl Into<String>) -> Self {
        Self::new("PATCH", url)
    }

    pub fn delete(url: impl Into<String>) -> Self {
        Self::new("DELETE", url)
    }

    /// Add a header tuple `(name, value)`, consuming self (builder pattern).
    pub fn header(mut self, h: (String, String)) -> Self {
        self.headers.push(h);
        self
    }

    /// Set the request body, consuming self (builder pattern).
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

/// An HTTP response from a storage provider endpoint.
#[derive(Debug, Clone)]
pub struct ProviderHttpResponse {
    pub status: u16,
    /// Response headers as (name, value) pairs (lowercase names).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ProviderHttpResponse {
    /// Find the first response header with the given name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// True iff status is 2xx.
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Async HTTP client for BYO storage provider implementations.
///
/// Implemented by sdk-ffi (reqwest + tokio) and sdk-wasm (reqwest wasm feature).
/// All four concrete providers (GDrive, Dropbox, OneDrive, WebDAV) are generic
/// over this trait so they compile for both targets without duplication.
///
/// Implementations must follow redirects (up to ~10), handle TLS, and forward
/// all request headers verbatim. Response bodies are always buffered.
///
/// Send-ness of the returned future is target-dependent. On native targets the
/// UniFFI macro (`#[uniffi::export(async_runtime = "tokio")]`) wraps exported
/// async fns in a type that requires `Send`, so every future that can be
/// `.await`-ed from an exported fn must be `Send`. Native `reqwest::Client`
/// produces `Send` futures, so we require `+ Send` there. On wasm, `reqwest`'s
/// futures are `!Send` (they wrap JS promises) and execution is single-threaded
/// through `wasm-bindgen-futures`, so `Send` is not required (and would be
/// impossible to satisfy).
#[cfg(not(target_arch = "wasm32"))]
pub trait ProviderHttpClient: Send + Sync {
    fn request(
        &self,
        req: ProviderHttpRequest,
    ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait ProviderHttpClient: Send + Sync {
    fn request(
        &self,
        req: ProviderHttpRequest,
    ) -> impl std::future::Future<Output = Result<ProviderHttpResponse, ProviderError>>;
}
