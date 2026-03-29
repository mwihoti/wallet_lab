use crate::config::AppConfig;

pub struct AppState {
    pub config: AppConfig,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("Failed to build HTTP client"),
            config,
        }
    }

    pub fn blockstream_url(&self, path: &str) -> String {
        format!("{}{}", self.config.blockstream_base_url, path)
    }
}
