use axum::{extract::{Path, State}, Json};
use std::sync::Arc;
use crate::{blockstream::client::fetch_utxos, error::AppError, state::AppState};

pub async fn get_utxos(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let utxos = fetch_utxos(&state.http, &state.config.blockstream_base_url, &address).await?;
    Ok(Json(serde_json::to_value(utxos).unwrap()))
}
