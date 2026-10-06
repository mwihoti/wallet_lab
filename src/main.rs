use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use wallet_lab::{app::build_router, config::AppConfig, security::spawn_pruner, state::AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "wallet_lab=debug,info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();
    let port   = config.port;
    tracing::info!(
        trust_proxy = config.trust_proxy,
        allowed_origins = ?config.allowed_origins,
        rate_limit_rps = config.rate_limit_rps,
        tx_rate_limit_per_min = config.tx_rate_limit_per_min,
        "config loaded"
    );
    let state  = Arc::new(AppState::new(config));
    spawn_pruner(state.clone());

    let app = build_router(state, "src/static");

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    tracing::info!("Wallet Lab running on http://0.0.0.0:{}", port);
    // Connect info gives the rate limiter the peer address.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/// Finish in-flight requests on Ctrl-C or SIGTERM (what hosts send on redeploy).
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok(); };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutting down");
}
