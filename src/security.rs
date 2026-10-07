//! Protections for running the lab on the public internet:
//! per-IP rate limiting, client-IP detection behind a proxy, and
//! validation of path parameters that are forwarded to the upstream API.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{error::AppError, state::AppState};

// ── Token bucket rate limiter ─────────────────────────────────────────────────

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-client token bucket: `capacity` requests in a burst, refilled at
/// `refill_per_sec`. Kept in memory — fine for a single instance.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity.max(1) as f64,
            refill_per_sec: refill_per_sec.max(0.001),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `ip`. On refusal returns how many seconds until a
    /// token is available, for the `Retry-After` header.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(bucket_key(ip))
            .or_insert(Bucket { tokens: self.capacity, last: now });

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - bucket.tokens) / self.refill_per_sec).ceil() as u64)
        }
    }

    /// Forget clients whose bucket has refilled completely; they are
    /// indistinguishable from new clients. Keeps memory bounded.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&self, now: Instant) {
        let (cap, rate) = (self.capacity, self.refill_per_sec);
        self.buckets.lock().unwrap().retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens + elapsed * rate < cap
        });
    }

    pub fn tracked_clients(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// IPv6 users usually control a whole /64, so limit per /64 rather than per
/// address; otherwise one client could rotate addresses to dodge the limit.
fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// Periodically drop idle buckets from both limiters.
pub fn spawn_pruner(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            state.api_limiter.prune();
            state.tx_limiter.prune();
        }
    });
}

// ── Client IP ─────────────────────────────────────────────────────────────────

/// The address to rate-limit by.
///
/// Behind a reverse proxy (Render, Fly, Caddy…) every request arrives from the
/// proxy, so the real client is taken from `X-Forwarded-For`. The proxy
/// appends the address it saw to the end of that header, so the right-most
/// entry is the one we can trust; anything to its left is client-supplied.
/// Only consulted when `trust_proxy` is on — otherwise anyone could spoof it.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

fn request_ip(state: &AppState, req: &Request) -> IpAddr {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    client_ip(req.headers(), peer, state.config.trust_proxy)
}

fn too_many_requests(retry_after: u64) -> Response {
    let mut res = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": format!("Too many requests — please wait {retry_after}s and try again.")
        })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
        res.headers_mut().insert(header::RETRY_AFTER, v);
    }
    res
}

/// Middleware: general limit for every API call.
pub async fn api_rate_limit(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let ip = request_ip(&state, &req);
    match state.api_limiter.check(ip) {
        Ok(()) => next.run(req).await,
        Err(retry) => {
            tracing::warn!(%ip, "API rate limit hit");
            too_many_requests(retry)
        }
    }
}

/// Middleware: stricter limit for wallet creation and broadcasting.
pub async fn tx_rate_limit(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let ip = request_ip(&state, &req);
    match state.tx_limiter.check(ip) {
        Ok(()) => next.run(req).await,
        Err(retry) => {
            tracing::warn!(%ip, "wallet/broadcast rate limit hit");
            too_many_requests(retry)
        }
    }
}

// ── Path parameter validation ─────────────────────────────────────────────────
// These values are pasted into upstream URLs. Axum percent-decodes path
// segments, so without a check "%2F.." could steer the request to another
// upstream endpoint.

/// Addresses are base58 or bech32: ASCII letters and digits only.
pub fn validate_address_param(address: &str) -> Result<(), AppError> {
    if address.is_empty() || address.len() > 90 || !address.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(AppError::InvalidAddress("Address must be letters and digits only".to_string()));
    }
    Ok(())
}

/// A txid is exactly 64 hex characters.
pub fn validate_txid_param(txid: &str) -> Result<(), AppError> {
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::ParseError("Transaction id must be 64 hex characters".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bucket_allows_burst_then_refills() {
        let rl = RateLimiter::new(3, 1.0);
        let t0 = Instant::now();
        let a = ip("1.2.3.4");
        for _ in 0..3 {
            assert!(rl.check_at(a, t0).is_ok());
        }
        assert_eq!(rl.check_at(a, t0), Err(1));
        // Another client is unaffected
        assert!(rl.check_at(ip("5.6.7.8"), t0).is_ok());
        // One second later one token is back
        assert!(rl.check_at(a, t0 + Duration::from_secs(1)).is_ok());
        assert!(rl.check_at(a, t0 + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn retry_after_reflects_refill_rate() {
        let rl = RateLimiter::new(1, 0.1); // one request per 10 s
        let t0 = Instant::now();
        let a = ip("1.2.3.4");
        assert!(rl.check_at(a, t0).is_ok());
        assert_eq!(rl.check_at(a, t0), Err(10));
    }

    #[test]
    fn ipv6_is_limited_per_slash_64() {
        let rl = RateLimiter::new(1, 0.01);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("2001:db8:1:2::1"), t0).is_ok());
        assert!(rl.check_at(ip("2001:db8:1:2::ffff"), t0).is_err(), "same /64");
        assert!(rl.check_at(ip("2001:db8:1:3::1"), t0).is_ok(), "different /64");
    }

    #[test]
    fn prune_drops_only_refilled_buckets() {
        let rl = RateLimiter::new(2, 1.0);
        let t0 = Instant::now();
        rl.check_at(ip("1.1.1.1"), t0).unwrap();
        rl.check_at(ip("2.2.2.2"), t0 + Duration::from_secs(5)).unwrap();
        rl.prune_at(t0 + Duration::from_millis(5_500));
        assert_eq!(rl.tracked_clients(), 1);
    }

    #[test]
    fn forwarded_for_is_used_only_when_trusted() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 10.0.0.9"));
        let peer = Some(ip("127.0.0.1"));
        assert_eq!(client_ip(&h, peer, false), ip("127.0.0.1"));
        // Right-most entry is the one appended by our proxy
        assert_eq!(client_ip(&h, peer, true), ip("10.0.0.9"));
        // Garbage falls back to the socket peer
        h.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(&h, peer, true), ip("127.0.0.1"));
    }

    #[test]
    fn path_params_are_validated() {
        assert!(validate_address_param("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").is_ok());
        assert!(validate_address_param("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn").is_ok());
        assert!(validate_address_param("../../blocks").is_err());
        assert!(validate_address_param("abc/txs").is_err());
        assert!(validate_address_param("").is_err());
        assert!(validate_txid_param(&"ab".repeat(32)).is_ok());
        assert!(validate_txid_param(&"zz".repeat(32)).is_err());
        assert!(validate_txid_param("abc").is_err());
    }
}
