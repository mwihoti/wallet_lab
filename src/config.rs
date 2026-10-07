pub struct AppConfig {
    pub port: u16,
    pub blockstream_base_url: String,
    pub lab_wallet_address: String,

    /// Read the client IP from `X-Forwarded-For` (set when behind a reverse proxy).
    pub trust_proxy: bool,
    /// Origins allowed to call the API cross-site. Empty = same-origin only.
    pub allowed_origins: Vec<String>,

    /// General API limit per client: sustained requests per second and burst size.
    pub rate_limit_rps: f64,
    pub rate_limit_burst: u32,
    /// Wallet creation + broadcast limit per client: per minute and burst size.
    pub tx_rate_limit_per_min: f64,
    pub tx_rate_limit_burst: u32,
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn env_flag(key: &str) -> Option<bool> {
    std::env::var(key).ok().map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
}

impl AppConfig {
    /// Used by plain `cargo run` — reads from environment variables and lab_wallet/wallet.json.
    pub fn from_env() -> Self {
        let lab_wallet_address = std::env::var("LAB_WALLET_ADDRESS").unwrap_or_else(|_| {
            std::fs::read_to_string("lab_wallet/wallet.json")
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v["address"].as_str().map(String::from))
                .unwrap_or_default()
        });

        // Render and Fly always sit behind their own proxy; trust it there by
        // default so every visitor doesn't share the proxy's rate-limit bucket.
        let behind_known_proxy =
            std::env::var("RENDER").is_ok() || std::env::var("FLY_APP_NAME").is_ok();

        Self {
            port: env_parse("PORT", 8080),
            blockstream_base_url: std::env::var("BLOCKSTREAM_URL")
                .unwrap_or_else(|_| "https://mempool.space/testnet4/api".to_string()),
            lab_wallet_address,
            trust_proxy: env_flag("TRUST_PROXY").unwrap_or(behind_known_proxy),
            allowed_origins: std::env::var("ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            rate_limit_rps: env_parse("RATE_LIMIT_RPS", 5.0),
            rate_limit_burst: env_parse("RATE_LIMIT_BURST", 120),
            tx_rate_limit_per_min: env_parse("RATE_LIMIT_TX_PER_MIN", 12.0),
            tx_rate_limit_burst: env_parse("RATE_LIMIT_TX_BURST", 30),
        }
    }
}
