use serde::{Deserialize, Serialize};
use crate::error::AppError;

// --- Response types from Blockstream API ---

#[derive(Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxInfo {
    pub txid: String,
    pub status: TxStatus,
}

// --- API calls ---

/// GET /address/{address}/utxo
pub async fn fetch_utxos(
    client: &reqwest::Client,
    base_url: &str,
    address: &str,
) -> Result<Vec<Utxo>, AppError> {
    let url = format!("{}/address/{}/utxo", base_url, address);
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::BlockstreamError(e.to_string()))?;

    if !res.status().is_success() {
        return Err(AppError::BlockstreamError(format!(
            "HTTP {}: {}",
            res.status(),
            url
        )));
    }

    res.json::<Vec<Utxo>>()
        .await
        .map_err(|e| AppError::BlockstreamError(e.to_string()))
}

/// POST /tx  (body = raw hex string)
pub async fn broadcast_tx(
    client: &reqwest::Client,
    base_url: &str,
    raw_hex: &str,
) -> Result<String, AppError> {
    let url = format!("{}/tx", base_url);
    let res = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(raw_hex.to_string())
        .send()
        .await
        .map_err(|e| AppError::BroadcastFailed(e.to_string()))?;

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(AppError::BroadcastFailed(body));
    }

    res.text()
        .await
        .map_err(|e| AppError::BroadcastFailed(e.to_string()))
}

/// GET /tx/{txid}
pub async fn fetch_tx_status(
    client: &reqwest::Client,
    base_url: &str,
    txid: &str,
) -> Result<TxInfo, AppError> {
    let url = format!("{}/tx/{}", base_url, txid);
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::BlockstreamError(e.to_string()))?;

    if !res.status().is_success() {
        return Err(AppError::BlockstreamError(format!(
            "HTTP {}: {}",
            res.status(),
            url
        )));
    }

    res.json::<TxInfo>()
        .await
        .map_err(|e| AppError::BlockstreamError(e.to_string()))
}
