//! HTTP router: API routes, static files, and the protections around them.

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue, Method},
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{
    api::{
        lab_handler::get_lab_info,
        malleability_handlers::malleability_demo,
        network_handlers::{get_fee_rates, validate_address},
        status_handlers::get_tx_status,
        tx_handlers::build_and_send,
        utxo_handlers::get_utxos,
        wallet_handlers::create_wallet,
    },
    security::{api_rate_limit, tx_rate_limit},
    state::AppState,
};

/// Largest JSON body the API accepts. A multi-input send request is a few KB.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Scripts: our own, the QR library, and Cloudflare Web Analytics.
/// Images: `data:` for the QR code PNG.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
    script-src 'self' https://cdnjs.cloudflare.com https://static.cloudflareinsights.com; \
    style-src 'self'; \
    img-src 'self' data:; \
    connect-src 'self' https://cloudflareinsights.com; \
    object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn build_router(state: Arc<AppState>, static_dir: &str) -> Router {
    // Expensive or abusable endpoints get a second, stricter limit.
    let strict = Router::new()
        .route("/wallet/create", post(create_wallet))
        .route("/tx/build-and-send", post(build_and_send))
        .route_layer(middleware::from_fn_with_state(state.clone(), tx_rate_limit));

    let api = Router::new()
        .route("/utxo/{address}", get(get_utxos))
        .route("/tx/{txid}/status", get(get_tx_status))
        .route("/demo/malleability", post(malleability_demo))
        .route("/lab/info", get(get_lab_info))
        .route("/fees", get(get_fee_rates))
        .route("/address/{address}/validate", get(validate_address))
        .merge(strict)
        .route_layer(middleware::from_fn_with_state(state.clone(), api_rate_limit))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        // Responses can contain a private key: never cache them.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let mut app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api)
        .fallback_service(ServeDir::new(static_dir))
        .with_state(state.clone());

    if let Some(cors) = cors_layer(&state.config.allowed_origins) {
        app = app.layer(cors);
    }

    with_security_headers(app).layer(TraceLayer::new_for_http())
}

/// Same-origin by default (the frontend is served by this app). Cross-site
/// access only for origins listed in `ALLOWED_ORIGINS`.
fn cors_layer(origins: &[String]) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE]),
    )
}

fn with_security_headers(app: Router) -> Router {
    let h = |name: HeaderName, value: &'static str| {
        SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
    };
    app.layer(h(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY))
        .layer(h(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(h(header::X_FRAME_OPTIONS, "DENY"))
        .layer(h(header::REFERRER_POLICY, "strict-origin-when-cross-origin"))
        // Browsers ignore this over plain HTTP, so it is safe to always send.
        .layer(h(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000"))
        .layer(h(
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=()",
        ))
}
