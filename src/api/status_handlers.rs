use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use crate::{blockstream::client::fetch_tx_status, error::AppError, state::AppState};

pub async fn get_tx_status(
    State(state): State<Arc<AppState>>,
    Path(txid): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let info = fetch_tx_status(&state.http, &state.config.blockstream_base_url, &txid).await?;
    Ok(Json(serde_json::to_value(info).unwrap()))
}
