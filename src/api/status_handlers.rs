use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use crate::{
    blockstream::client::{fetch_tip_height, fetch_tx_status},
    error::AppError,
    state::AppState,
};

/// Transaction status plus the current tip height and confirmation count.
pub async fn get_tx_status(
    State(state): State<Arc<AppState>>,
    Path(txid): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let base = &state.config.blockstream_base_url;
    let (info, tip) = tokio::join!(
        fetch_tx_status(&state.http, base, &txid),
        fetch_tip_height(&state.http, base),
    );
    let info = info?;
    // The tip is a nice-to-have: report the status even if it fails.
    let tip = tip.ok();
    let confirmations = match (info.status.block_height, tip) {
        (Some(h), Some(t)) if info.status.confirmed && t >= h => t - h + 1,
        _ => 0,
    };

    let mut value = serde_json::to_value(info).unwrap();
    value["tip_height"] = serde_json::json!(tip);
    value["confirmations"] = serde_json::json!(confirmations);
    Ok(Json(value))
}
