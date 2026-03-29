use axum::{extract::State, Json};
use std::sync::Arc;
use crate::{error::AppError, state::AppState, wallet::keygen::generate_wallet};

pub async fn create_wallet(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet = generate_wallet();
    Ok(Json(serde_json::to_value(wallet).map_err(|e| AppError::Internal(e.to_string()))?))
}
