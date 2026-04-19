use thiserror::Error;

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("blocked IP address: {0}")]
    BlockedIp(std::net::IpAddr),

    #[error("no DNS records found for hostname")]
    NoRecords(String),

    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("invalid hostname")]
    InvalidHostname,
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("missing or invalid relay_auth cookie")]
    Unauthenticated,

    #[error("token expired")]
    TokenExpired,

    #[error("channel is full (max 2 clients)")]
    ChannelFull,

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("SSRF protection: {0}")]
    Ssrf(#[from] SsrfError),

    #[error("invalid query parameter: {0}")]
    InvalidParam(String),
}

#[derive(Debug, Error)]
pub enum SftpRelayError {
    #[error("SSRF protection: {0}")]
    Ssrf(#[from] SsrfError),

    #[error("SSH connection failed: {0}")]
    SshConnect(String),

    #[error("SSH authentication failed")]
    SshAuth,

    #[error("SFTP subsystem failed: {0}")]
    SftpInit(String),

    #[error("SFTP operation failed: {0}")]
    SftpOp(String),

    #[error("unexpected message type")]
    UnexpectedMessage,

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("connection timed out")]
    Timeout,

    #[error("host key rejected by client (TOFU mismatch or first-connect refusal)")]
    HostKeyRejected,

    #[error("remote did not present an SSH banner; not an SSH server")]
    NotSshServer,
}
