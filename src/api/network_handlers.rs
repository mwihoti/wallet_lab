use axum::{extract::{Path, State}, Json};
use serde_json::json;
use std::sync::Arc;
use crate::{
    blockstream::client::{fetch_fee_rates, FeeRates},
    error::AppError,
    state::AppState,
    wallet::signing::classify_address,
};

/// GET /api/fees — recommended fee rates (sat/vB) from the mempool.
pub async fn get_fee_rates(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FeeRates>, AppError> {
    let rates = state
        .fee_cache
        .get_or_fetch(|| fetch_fee_rates(&state.http, &state.config.blockstream_base_url))
        .await?;
    Ok(Json(rates))
}

/// GET /api/address/{address}/validate — decode an address without touching the network.
/// Always 200: `valid: false` carries the reason so the form can show it inline.
pub async fn validate_address(Path(address): Path<String>) -> Json<serde_json::Value> {
    match classify_address(address.trim()) {
        Ok(info) => Json(json!({
            "valid": info.network == "testnet",
            "kind": info.kind,
            "network": info.network,
            "dust_limit": info.kind.dust_limit(),
            "output_size": info.kind.output_size(),
            "error": if info.network == "testnet" { None } else {
                Some("Mainnet address — this lab runs on testnet4")
            },
        })),
        Err(e) => Json(json!({ "valid": false, "error": e.to_string() })),
    }
}
