use std::future::Future;
use std::time::{Duration, Instant};

use crate::blockstream::client::FeeRates;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::security::RateLimiter;

/// Caches one upstream value for a short time. The lock is held while
/// fetching, so concurrent requests on a cold cache trigger a single fetch.
pub struct TtlCache<T> {
    ttl: Duration,
    slot: tokio::sync::Mutex<Option<(Instant, T)>>,
}

impl<T: Clone> TtlCache<T> {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, slot: tokio::sync::Mutex::new(None) }
    }

    pub async fn get_or_fetch<F, Fut>(&self, fetch: F) -> Result<T, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, AppError>>,
    {
        let mut slot = self.slot.lock().await;
        if let Some((at, value)) = slot.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(value.clone());
            }
        }
        let value = fetch().await?;
        *slot = Some((Instant::now(), value.clone()));
        Ok(value)
    }
}

pub struct AppState {
    pub config: AppConfig,
    pub http: reqwest::Client,
    pub api_limiter: RateLimiter,
    pub tx_limiter: RateLimiter,
    pub fee_cache: TtlCache<FeeRates>,
    pub tip_cache: TtlCache<u32>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to build HTTP client"),
            api_limiter: RateLimiter::new(config.rate_limit_burst, config.rate_limit_rps),
            tx_limiter: RateLimiter::new(config.tx_rate_limit_burst, config.tx_rate_limit_per_min / 60.0),
            fee_cache: TtlCache::new(Duration::from_secs(30)),
            tip_cache: TtlCache::new(Duration::from_secs(15)),
            config,
        }
    }
}
