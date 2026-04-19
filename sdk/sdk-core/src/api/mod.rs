// BYO-only HTTP plumbing. The managed API client was removed with the managed feature.
//
// What remains: the ProviderHttpClient trait used by BYO storage providers
// (Google Drive, Dropbox, OneDrive, Box, pCloud, WebDAV, SFTP, S3, R2).

#[cfg(feature = "providers")]
pub mod provider_http;
#[cfg(feature = "providers")]
pub use provider_http::{ProviderHttpClient, ProviderHttpRequest, ProviderHttpResponse};
