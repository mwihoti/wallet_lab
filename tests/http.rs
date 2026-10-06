//! Drives the real router in-process to check the public-hosting protections.

use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use tower::ServiceExt;
use wallet_lab::{app::build_router, config::AppConfig, state::AppState};

fn config() -> AppConfig {
    AppConfig {
        port: 0,
        // Nothing in these tests should reach the upstream API.
        blockstream_base_url: "http://127.0.0.1:9".to_string(),
        lab_wallet_address: String::new(),
        trust_proxy: false,
        allowed_origins: vec![],
        rate_limit_rps: 0.01,
        rate_limit_burst: 100,
        tx_rate_limit_per_min: 0.5,
        tx_rate_limit_burst: 100,
    }
}

fn app(cfg: AppConfig) -> Router {
    build_router(Arc::new(AppState::new(cfg)), "src/static")
}

async fn send(app: &Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn health_and_static_pages_carry_security_headers() {
    let app = app(config());
    for uri in ["/healthz", "/", "/app.js"] {
        let res = send(&app, get(uri)).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        let h = res.headers();
        assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("frame-ancestors 'none'"));
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert!(h.contains_key(header::STRICT_TRANSPORT_SECURITY));
    }
}

#[tokio::test]
async fn api_responses_are_not_cached() {
    let res = send(&app(config()), get("/api/lab/info")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn api_is_rate_limited_per_client() {
    let mut cfg = config();
    cfg.rate_limit_burst = 3;
    let app = app(cfg);
    for _ in 0..3 {
        assert_eq!(send(&app, get("/api/lab/info")).await.status(), StatusCode::OK);
    }
    let res = send(&app, get("/api/lab/info")).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(header::RETRY_AFTER));
    let body = to_bytes(res.into_body(), 4096).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Too many requests"));

    // The health check is never limited, so the host can always probe it.
    assert_eq!(send(&app, get("/healthz")).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn wallet_creation_has_its_own_stricter_limit() {
    let mut cfg = config();
    cfg.tx_rate_limit_burst = 2;
    let app = app(cfg);
    let create = || Request::post("/api/wallet/create").body(Body::from("{}")).unwrap();
    assert_eq!(send(&app, create()).await.status(), StatusCode::OK);
    assert_eq!(send(&app, create()).await.status(), StatusCode::OK);
    assert_eq!(send(&app, create()).await.status(), StatusCode::TOO_MANY_REQUESTS);
    // Ordinary API calls still work
    assert_eq!(send(&app, get("/api/lab/info")).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn forwarded_clients_get_separate_buckets_only_behind_a_trusted_proxy() {
    let req = |ip: &str| {
        Request::get("/api/lab/info").header("x-forwarded-for", ip).body(Body::empty()).unwrap()
    };

    let mut cfg = config();
    cfg.rate_limit_burst = 1;
    cfg.trust_proxy = true;
    let trusted = app(cfg);
    assert_eq!(send(&trusted, req("1.1.1.1")).await.status(), StatusCode::OK);
    assert_eq!(send(&trusted, req("2.2.2.2")).await.status(), StatusCode::OK);
    assert_eq!(send(&trusted, req("1.1.1.1")).await.status(), StatusCode::TOO_MANY_REQUESTS);

    // Untrusted: a client can't dodge the limit by forging the header
    let mut cfg = config();
    cfg.rate_limit_burst = 1;
    let untrusted = app(cfg);
    assert_eq!(send(&untrusted, req("1.1.1.1")).await.status(), StatusCode::OK);
    assert_eq!(send(&untrusted, req("2.2.2.2")).await.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn cross_origin_access_is_off_unless_configured() {
    let preflight = |origin: &str| {
        Request::builder()
            .method("OPTIONS")
            .uri("/api/fees")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .unwrap()
    };

    let res = send(&app(config()), preflight("https://evil.example")).await;
    assert!(!res.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));

    let mut cfg = config();
    cfg.allowed_origins = vec!["https://friend.example".to_string()];
    let app = app(cfg);
    let res = send(&app, preflight("https://friend.example")).await;
    assert_eq!(res.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://friend.example");
    let res = send(&app, preflight("https://evil.example")).await;
    assert!(!res.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn path_params_cannot_steer_upstream_requests() {
    let app = app(config());
    // %2F decodes to "/" — would otherwise turn into a different upstream path
    let res = send(&app, get("/api/utxo/..%2F..%2Fblocks")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = send(&app, get("/api/tx/not-a-txid/status")).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let big = format!("{{\"raw_tx_hex\":\"{}\"}}", "00".repeat(100_000));
    let req = Request::post("/api/demo/malleability")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(big))
        .unwrap();
    assert_eq!(send(&app(config()), req).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
