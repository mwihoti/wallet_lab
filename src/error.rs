use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Blockstream API error: {0}")]
    BlockstreamError(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid WIF: {0}")]
    InvalidWif(String),

    #[error("Insufficient funds: available {available} sat, required {required} sat")]
    InsufficientFunds { available: u64, required: u64 },

    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BlockstreamError(_) => StatusCode::BAD_GATEWAY,
            AppError::BroadcastFailed(_) => StatusCode::BAD_GATEWAY,
            AppError::InvalidAddress(_) => StatusCode::BAD_REQUEST,
            AppError::InvalidWif(_) => StatusCode::BAD_REQUEST,
            AppError::InsufficientFunds { .. } => StatusCode::BAD_REQUEST,
            AppError::ParseError(_) => StatusCode::BAD_REQUEST,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}
