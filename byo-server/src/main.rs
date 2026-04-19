use anyhow::Context;
use axum::{extract::State, http::StatusCode, middleware, response::IntoResponse, routing::get, routing::post, Router};
use byo_server::{
    channel::ChannelRegistry,
    config::Config,
    rate_limit::{AuthChallengeLimiter, ChannelJoinLimiter, SftpAuthFailureTracker, SftpConnectionTracker},
    relay_auth::{get_challenge, post_relay_auth, AppState, ChallengeStore, JtiConsumedSet},
    relay_ws::ws_handler,
    security_headers::{byo_security_headers, Domain},
    share_relay::{
        create_b1_share, get_b1_share, revoke_b1_share,
        upload_b2_share, get_b2_share, revoke_b2_share,
        ShareSweeper, ShareGetLimiter,
    },
    stats::{ingest_stats, StatsIngestLimiter, StatsStore},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    services::{ServeDir, ServeFile},
    timeout::TimeoutLayer,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (ring) — same as backend
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    // Initialize tracing: zero-logging means RUST_LOG=warn by default
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let config = Config::from_env();
    let bind_addr = config.bind_addr;
    let tls_cert = config.tls_cert.clone();
    let tls_key = config.tls_key.clone();
    let spa_dir = config.spa_dir.clone();
    let domain = config.domain.clone();
    let pow_difficulty = config.pow_difficulty_bits;
    let auth_challenge_per_min = config.auth_challenge_per_min;
    let stats_ingest_per_min = config.stats_ingest_per_min;

    // Open (or create) the stats database.
    let stats_store = Arc::new(
        StatsStore::open(&config.stats_db_path)
            .context("Failed to open stats database")?,
    );

    // Build shared application state
    let registry = Arc::new(ChannelRegistry::new());
    ChannelRegistry::start_sweeper(Arc::clone(&registry));

    let state = Arc::new(AppState {
        join_limiter: ChannelJoinLimiter::new(),
        sftp_tracker: SftpConnectionTracker::new(),
        sftp_auth_tracker: Arc::new(SftpAuthFailureTracker::new()),
        challenge_store: Arc::new(ChallengeStore::new()),
        jti_consumed: Arc::new(JtiConsumedSet::new()),
        auth_challenge_limiter: AuthChallengeLimiter::new(auth_challenge_per_min),
        channel_registry: registry,
        config,
        b1_shares: Arc::new(RwLock::new(HashMap::new())),
        b2_shares: Arc::new(RwLock::new(HashMap::new())),
        share_get_limiter: ShareGetLimiter::new(),
        stats_store,
        stats_ingest_limiter: StatsIngestLimiter::new(stats_ingest_per_min),
    });

    ShareSweeper::start(Arc::clone(&state));

    tracing::warn!(
        pow_difficulty,
        auth_challenge_per_min,
        sftp_allowlist_len = state.config.sftp_host_allowlist.len(),
        "byo-server starting on {bind_addr}",
    );

    // Static SPA: serve dist/ with index.html fallback for client-side routing
    let spa_service =
        ServeDir::new(&spa_dir).not_found_service(ServeFile::new(spa_dir.join("index.html")));

    // Build router — no CORS (same-origin), no CSRF (no server-side session state),
    // no request logger middleware (zero-logging, R5)
    let app = Router::new()
        // Liveness and readiness probes — no state leak, no auth required.
        // /ready probes stats_store so orchestrators drain before a wedged DB.
        .route("/health", get(|| async { "ok" }))
        .route("/ready",  get(ready_handler))
        .route("/relay/auth/challenge", get(get_challenge))
        .route("/relay/auth", post(post_relay_auth))
        .route("/relay/ws", get(ws_handler))
        .route("/relay/share/b1", post(create_b1_share))
        .route("/relay/share/b1/:share_id", get(get_b1_share).delete(revoke_b1_share))
        .route("/relay/share/b2", post(upload_b2_share))
        .route("/relay/share/b2/:share_id", get(get_b2_share).delete(revoke_b2_share))
        .route("/relay/stats", post(ingest_stats))
        .fallback_service(spa_service)
        .layer(middleware::from_fn(byo_security_headers))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(CookieManagerLayer::new())
        .layer(axum::Extension(Domain(domain)))
        .with_state(state);

    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .context("Failed to load TLS certificate/key")?;
            // axum-server Handle enables graceful shutdown on the TLS branch.
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            axum_server::bind_rustls(bind_addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("Server failed")?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(&bind_addr)
                .await
                .context("Failed to bind")?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("Server failed")?;
        }
    }
    Ok(())
}

async fn ready_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.stats_store.ping() {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    // signal() is infallible on Linux in practice; log and proceed on error.
    let ctrl_c = tokio::signal::ctrl_c();
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        Err(e) => {
            tracing::error!("Failed to register SIGTERM handler: {e}; falling back to ctrl-c only");
            let _ = ctrl_c.await;
        }
    }
    tracing::warn!("shutdown signal received");
}
