use axum::{extract::State, Json};
use std::sync::Arc;
use serde_json::json;
use crate::{error::AppError, state::AppState};

pub async fn get_lab_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(json!({
        "address": state.config.lab_wallet_address,
    })))
}
