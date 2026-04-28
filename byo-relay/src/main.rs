use anyhow::Context;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use byo_relay::{
    channel::ChannelRegistry,
    config::Config,
    enrollment::{get_info as get_enrollment_info, EnrollmentInfoLimiter, EnrollmentStore},
    enrollment_admin::{
        bootstrap_if_needed, delete_device, delete_invite, get_claim_challenge, get_devices,
        get_invites, get_me, get_redeem_challenge, post_claim, post_invite, post_redeem,
        post_signout, require_device_cookie, require_owner_device, ClaimLimiter, InviteMintLimiter,
        RedeemLimiter, BOOTSTRAP_TOKEN_FILE_DEFAULT,
    },
    rate_limit::{
        AuthChallengeLimiter, ByteBudgetTracker, ChannelJoinLimiter, SftpAuthFailureTracker,
        SftpConnectionTracker, ShareBytesPerShareTracker, ShareConcurrencyTracker,
        ShareCreationRateLimiter, ShareStoragePerIpTracker,
    },
    relay_auth::{get_challenge, post_relay_auth, AppState, ChallengeStore, JtiConsumedSet},
    relay_ws::ws_handler,
    security_headers::{byo_security_headers, Domain},
    share_relay::{
        get_b2_share, get_share_blob, get_share_headroom, get_share_meta, init_bundle,
        revoke_b2_share, seal_bundle, upload_b2_share, upload_bundle_blob, ShareGetLimiter,
        ShareSweeper,
    },
    share_store::ShareStore,
    stats::{ingest_stats, StatsIngestLimiter, StatsStore},
};
use std::net::SocketAddr;
use std::sync::Arc;
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
    let enrollment_mode = config.enrollment_mode;
    let enrollment_info_per_min = config.enrollment_info_per_min;

    // Open (or create) the stats database.
    let stats_store =
        Arc::new(StatsStore::open(&config.stats_db_path).context("Failed to open stats database")?);

    // Open (or create) the persistent share store — replaces the former
    // in-memory HashMap. Blobs live on disk, metadata in SQLite.
    let share_store = ShareStore::open(&config.share_db_path, &config.share_storage_dir)
        .context("Failed to open share store")?;

    // Open (or create) the enrollment store — backs the restricted-mode
    // device allow-list, invite codes, and bootstrap token. Phase 1 only
    // reads `owner_count()` off it for the `/relay/info` `bootstrapped` flag;
    // phase 2 adds write paths.
    let enrollment_store = EnrollmentStore::open(&config.enrollment_db_path)
        .context("Failed to open enrollment store")?;

    let share_byte_budget = ByteBudgetTracker::new(config.share_daily_bytes_per_ip);

    // Abuse-protection trackers — every knob is env-overridable via config.
    // State is in-memory; the sweeper drops matching entries when shares
    // expire so long-running relays don't accumulate phantom totals.
    let share_create_limiter = ShareCreationRateLimiter::new(
        config.share_create_per_hour_per_ip,
        config.share_create_per_day_per_ip,
    );
    let share_storage_tracker =
        ShareStoragePerIpTracker::new(config.share_total_storage_per_ip_bytes);
    let share_download_bytes =
        ShareBytesPerShareTracker::new(config.share_download_bytes_per_hour_per_share);
    let share_concurrency = ShareConcurrencyTracker::new(config.share_max_concurrent_downloads);
    let sftp_tracker = SftpConnectionTracker::with_max(config.sftp_max_concurrent_per_ip);
    let sftp_auth_tracker = Arc::new(SftpAuthFailureTracker::with_config(
        config.sftp_failed_auth_per_5min as usize,
        std::time::Duration::from_secs(5 * 60),
    ));

    // Build shared application state
    let registry = Arc::new(ChannelRegistry::new());
    ChannelRegistry::start_sweeper(Arc::clone(&registry));

    let state = Arc::new(AppState {
        join_limiter: ChannelJoinLimiter::new(),
        sftp_tracker,
        sftp_auth_tracker,
        challenge_store: Arc::new(ChallengeStore::new()),
        jti_consumed: Arc::new(JtiConsumedSet::new()),
        auth_challenge_limiter: AuthChallengeLimiter::new(auth_challenge_per_min),
        channel_registry: registry,
        config,
        share_store,
        share_get_limiter: ShareGetLimiter::new(),
        share_byte_budget,
        share_create_limiter,
        share_storage_tracker,
        share_download_bytes,
        share_concurrency,
        stats_store,
        stats_ingest_limiter: StatsIngestLimiter::new(stats_ingest_per_min),
        enrollment_store,
        enrollment_info_limiter: EnrollmentInfoLimiter::new(enrollment_info_per_min),
        enrollment_claim_limiter: ClaimLimiter::new(),
        enrollment_redeem_limiter: RedeemLimiter::new(),
        enrollment_invite_limiter: InviteMintLimiter::new(),
    });

    // If the relay is in `restricted` mode and no owner has claimed yet,
    // mint a bootstrap token and drop its plaintext on disk for the
    // operator-side claim-token wrapper (prod: `sudo wattcloud
    // claim-token`; dev: `make claim-token`). No-op otherwise.
    let bootstrap_token_path = std::path::PathBuf::from(
        std::env::var("BOOTSTRAP_TOKEN_PATH")
            .unwrap_or_else(|_| BOOTSTRAP_TOKEN_FILE_DEFAULT.to_string()),
    );
    match bootstrap_if_needed(&state, &bootstrap_token_path) {
        Ok(Some(_)) => tracing::warn!(
            path = %bootstrap_token_path.display(),
            "bootstrap token minted — read with `sudo wattcloud claim-token` (prod) or `make claim-token` (dev)"
        ),
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "bootstrap token generation failed"),
    }

    ShareSweeper::start(Arc::clone(&state));

    tracing::warn!(
        pow_difficulty,
        auth_challenge_per_min,
        sftp_allowlist_len = state.config.sftp_host_allowlist.len(),
        enrollment_mode = enrollment_mode.as_str(),
        "byo-relay starting on {bind_addr}",
    );

    // Static SPA: serve dist/ with index.html fallback for client-side routing
    let spa_service =
        ServeDir::new(&spa_dir).not_found_service(ServeFile::new(spa_dir.join("index.html")));

    // Axum's DefaultBodyLimit applies a blanket 2 MB cap to any route that
    // doesn't override it. The streaming upload routes below disable it
    // entirely (they enforce their own byte caps chunk-by-chunk). The
    // small-JSON routes — /relay/auth and /relay/share/bundle/init —
    // tighten it to a config-driven limit so a misbehaving client can't
    // tie up a parse task with a 2 MB JSON body (realistic payloads are
    // ~1 KB and ~100 B respectively). Crossing the cap returns 413.
    let auth_body_cap = state.config.auth_max_body_bytes;
    let bundle_init_body_cap = state.config.bundle_init_max_body_bytes;

    // ── Router composition ─────────────────────────────────────────────────
    //
    // The relay splits its surface into four groups so the restricted-
    // enrollment gate can be applied to exactly the write paths:
    //
    //   - `public`         — health/readiness/info/share-recipient + WS.
    //                        Recipients holding a share URL never need a
    //                        device; SPA static assets are always served.
    //   - `gated`          — operational writes + the /relay/auth funnel.
    //                        `require_device_cookie` middleware is a no-op
    //                        in Open mode, enforces device-cookie validity
    //                        in Restricted mode.
    //   - `admin_public`   — /relay/admin/claim + /redeem. These mint their
    //                        own device cookies, so they must NOT require a
    //                        prior cookie; rate limiters live inside the
    //                        handlers.
    //   - `admin_owner`    — invite + device CRUD. `require_owner_device`
    //                        middleware enforces cookie validity AND
    //                        is_owner=1.
    //
    // Layer order matters: axum applies layers inside-out, so the cookie
    // layer must be present where handlers need to inspect them. We
    // install `CookieManagerLayer` at the top-level router so every group
    // inherits it.

    let gated = Router::new()
        .route("/relay/auth/challenge", get(get_challenge))
        .route(
            "/relay/auth",
            post(post_relay_auth).layer(DefaultBodyLimit::max(auth_body_cap)),
        )
        .route(
            "/relay/share/b2",
            post(upload_b2_share).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/relay/share/bundle/init",
            post(init_bundle).layer(DefaultBodyLimit::max(bundle_init_body_cap)),
        )
        .route(
            "/relay/share/bundle/{share_id}/blob/{blob_id}",
            post(upload_bundle_blob).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/relay/share/bundle/{share_id}/seal",
            post(seal_bundle).layer(DefaultBodyLimit::disable()),
        )
        .route("/relay/stats", post(ingest_stats))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_device_cookie,
        ));

    let admin_public = Router::new()
        // PoW challenge issuance for claim + redeem. Lives under admin_public
        // because `/relay/auth/challenge` (the generic challenge endpoint)
        // sits behind `require_device_cookie` — by design, to prevent
        // unauthenticated SFTP/stats cookie acquisition in restricted mode.
        // These two admin-scoped challenges need to be reachable BEFORE a
        // device cookie exists.
        .route("/relay/admin/claim/challenge", get(get_claim_challenge))
        .route("/relay/admin/redeem/challenge", get(get_redeem_challenge))
        .route(
            "/relay/admin/claim",
            post(post_claim).layer(DefaultBodyLimit::max(auth_body_cap)),
        )
        .route(
            "/relay/admin/redeem",
            post(post_redeem).layer(DefaultBodyLimit::max(auth_body_cap)),
        )
        // Identity probe: always 200. Lets the SPA pick the right first-run
        // screen in one round-trip without side effects.
        .route("/relay/admin/me", get(get_me))
        // Sign out: revoke the cookie's device + clear the cookie. Public
        // route by design — the handler's first step is cookie validation
        // (so only the cookie's owner can target themselves). No separate
        // rate limiter: the action requires a valid cookie in the first
        // place, so brute force isn't a concern; genuine mis-fires are
        // bounded by the cookie supply.
        .route("/relay/admin/signout", post(post_signout));

    let admin_owner = Router::new()
        .route(
            "/relay/admin/invite",
            post(post_invite).layer(DefaultBodyLimit::max(auth_body_cap)),
        )
        .route("/relay/admin/invites", get(get_invites))
        .route("/relay/admin/invites/{id}", delete(delete_invite))
        .route("/relay/admin/devices", get(get_devices))
        .route("/relay/admin/devices/{id}", delete(delete_device))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_owner_device,
        ));

    let public = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ready", get(ready_handler))
        // Public: tells the SPA whether this relay is in restricted mode
        // and whether a bootstrap owner exists. Rate-limited in-handler.
        .route("/relay/info", get(get_enrollment_info))
        // WebSocket upgrade — validates its own `relay_auth_*` cookie
        // (which in restricted mode is transitively gated because
        // `/relay/auth` sits behind the device cookie).
        .route("/relay/ws", get(ws_handler))
        // Share recipient read surface: public by design (recipients with
        // a share URL have no device account).
        .route(
            "/relay/share/b2/{share_id}",
            get(get_b2_share).delete(revoke_b2_share),
        )
        .route("/relay/share/{share_id}/meta", get(get_share_meta))
        .route(
            "/relay/share/{share_id}/blob/{blob_id}",
            get(get_share_blob),
        )
        .route("/relay/share/headroom", get(get_share_headroom));

    let app = public
        .merge(gated)
        .merge(admin_public)
        .merge(admin_owner)
        .fallback_service(spa_service)
        .layer(middleware::from_fn(sw_download_headers))
        .layer(middleware::from_fn(byo_security_headers))
        // 4-hour request ceiling covers genuine bulk transfers over slow
        // links (a multi-GB share on a 1 Mbit uplink needs hours). Non-bulk
        // handlers return in milliseconds so the wider budget doesn't
        // relax the DoS posture — stalled connections are still rate- and
        // byte-budget gated.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(4 * 3600),
        ))
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

/// Rewrite `Content-Type` on `/dl/sw-download.js` to include `charset=utf-8`
/// and add `Service-Worker-Allowed: /dl/`. ServeDir infers `text/javascript`
/// from the extension and emits no charset, which makes Firefox log the
/// "character encoding not declared" warning on every fetch. The
/// Service-Worker-Allowed header is strictly redundant (default max scope
/// equals the script's directory) but keeps dev and prod symmetric.
async fn sw_download_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let is_sw = request.uri().path() == "/dl/sw-download.js";
    let mut response = next.run(request).await;
    if is_sw {
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        );
        headers.insert(
            header::HeaderName::from_static("service-worker-allowed"),
            HeaderValue::from_static("/dl/"),
        );
    }
    response
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
