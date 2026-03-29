pub struct AppConfig {
    pub port: u16,
    pub blockstream_base_url: String,
    pub lab_wallet_address: String,
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

        Self {
            port: std::env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            blockstream_base_url: std::env::var("BLOCKSTREAM_URL")
                .unwrap_or_else(|_| "https://mempool.space/testnet4/api".to_string()),
            lab_wallet_address,
        }
    }
}
