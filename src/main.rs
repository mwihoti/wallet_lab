mod config;
mod error;
mod state;
mod wallet;
mod script;
mod api;
mod blockstream;

use std::sync::Arc;
use axum::{Router, routing::{get, post}};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::AppConfig;
use state::AppState;
use api::{
    wallet_handlers::create_wallet,
    utxo_handlers::get_utxos,
    tx_handlers::build_and_send,
    status_handlers::get_tx_status,
    malleability_handlers::malleability_demo,
    lab_handler::get_lab_info,
};

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
    let state  = Arc::new(AppState::new(config));

    let api_router = Router::new()
        .route("/wallet/create", post(create_wallet))
        .route("/utxo/{address}", get(get_utxos))
        .route("/tx/build-and-send", post(build_and_send))
        .route("/tx/{txid}/status", get(get_tx_status))
        .route("/demo/malleability", post(malleability_demo))
        .route("/lab/info", get(get_lab_info))
        .with_state(state);

    let app = Router::new()
        .nest("/api", api_router)
        .fallback_service(ServeDir::new("src/static"))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    tracing::info!("Wallet Lab running on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.unwrap();
}
