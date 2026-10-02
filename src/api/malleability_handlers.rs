use axum::{extract::State, Json};
use serde::Deserialize;
use std::sync::Arc;
use crate::{error::AppError, state::AppState, wallet::malleability::{malleate, MalleabilityResult}};

#[derive(Debug, Deserialize)]
pub struct MalleabilityRequest {
    pub raw_tx_hex: String,
}

pub async fn malleability_demo(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<MalleabilityRequest>,
) -> Result<Json<MalleabilityResult>, AppError> {
    let raw = hex::decode(body.raw_tx_hex.trim())
        .map_err(|_| AppError::ParseError("Invalid raw tx hex".to_string()))?;
    Ok(Json(malleate(&raw)?))
}
