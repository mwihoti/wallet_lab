use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use crate::{
    blockstream::client::broadcast_tx,
    error::AppError,
    script::p2pkh::build_p2pkh_scriptpubkey,
    state::AppState,
    wallet::signing::{
        build_tx, decode_p2pkh_address,
        sign_and_assemble, sign_and_assemble_segwit,
    },
};

#[derive(Debug, Deserialize)]
pub struct BuildAndSendRequest {
    pub wif: String,
    pub utxo_txid: String,
    pub utxo_vout: u32,
    pub utxo_value: u64,
    pub recipient_address: String,
    pub send_amount: u64,
    pub fee: u64,
    pub sender_address: String,
    /// "p2pkh" (default) | "p2sh_p2wpkh" | "p2wpkh"
    pub wallet_type: Option<String>,
}

pub async fn build_and_send(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BuildAndSendRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let wallet_type = body.wallet_type.as_deref().unwrap_or("p2pkh");

    let tx = build_tx(
        &body.utxo_txid,
        body.utxo_vout,
        body.utxo_value,
        &body.recipient_address,
        body.send_amount,
        body.fee,
        &body.sender_address,
    )?;

    let (signed_bytes, display_txid) = match wallet_type {
        "p2wpkh" | "p2sh_p2wpkh" => {
            sign_and_assemble_segwit(tx, &body.wif, 0, body.utxo_value, wallet_type)?
        }
        _ => {
            // Legacy P2PKH: derive UTXO's scriptPubKey from sender address
            let sender_hash       = decode_p2pkh_address(&body.sender_address)?;
            let utxo_script_pubkey = build_p2pkh_scriptpubkey(&sender_hash);
            sign_and_assemble(tx, &body.wif, 0, &utxo_script_pubkey)?
        }
    };

    let raw_hex = hex::encode(&signed_bytes);

    let _broadcast_txid = broadcast_tx(
        &state.http,
        &state.config.blockstream_base_url,
        &raw_hex,
    )
    .await?;

    Ok(Json(json!({
        "txid": display_txid,
        "raw_tx_hex": raw_hex,
        "wallet_type": wallet_type,
        "signed": true
    })))
}
