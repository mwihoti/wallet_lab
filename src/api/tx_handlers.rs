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
        build_tx, decode_p2pkh_address, InputSpec,
        sign_and_assemble, sign_and_assemble_segwit,
    },
};

#[derive(Debug, Deserialize)]
pub struct BuildAndSendRequest {
    pub wif: String,
    /// UTXOs to spend. All must belong to `sender_address`.
    #[serde(default)]
    pub inputs: Vec<InputSpec>,
    // Single-UTXO form, kept for older clients.
    pub utxo_txid: Option<String>,
    pub utxo_vout: Option<u32>,
    pub utxo_value: Option<u64>,
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

    let mut inputs = body.inputs;
    if inputs.is_empty() {
        if let (Some(txid), Some(vout), Some(value)) = (body.utxo_txid, body.utxo_vout, body.utxo_value) {
            inputs.push(InputSpec { txid, vout, value });
        }
    }

    let built = build_tx(
        &inputs,
        &body.recipient_address,
        body.send_amount,
        body.fee,
        &body.sender_address,
    )?;

    let signed = match wallet_type {
        "p2wpkh" | "p2sh_p2wpkh" => {
            let values: Vec<u64> = inputs.iter().map(|i| i.value).collect();
            sign_and_assemble_segwit(built.tx, &body.wif, &values, wallet_type)?
        }
        _ => {
            // Legacy P2PKH: derive the UTXOs' scriptPubKey from the sender address
            let sender_hash        = decode_p2pkh_address(&body.sender_address)?;
            let utxo_script_pubkey = build_p2pkh_scriptpubkey(&sender_hash);
            sign_and_assemble(built.tx, &body.wif, &utxo_script_pubkey)?
        }
    };

    let raw_hex = hex::encode(&signed.raw);

    broadcast_tx(
        &state.http,
        &state.config.blockstream_base_url,
        &raw_hex,
    )
    .await?;

    Ok(Json(json!({
        "txid": signed.txid,
        "wtxid": signed.wtxid,
        "raw_tx_hex": raw_hex,
        "wallet_type": wallet_type,
        "signed": true,
        "input_count": inputs.len(),
        "input_total": built.input_total,
        "send_amount": body.send_amount,
        "fee": built.fee,
        "change": built.change,
        "dust_change_added_to_fee": built.dust_change_added_to_fee,
        "vsize": signed.vsize,
        "weight": signed.weight,
        "fee_rate": built.fee as f64 / signed.vsize as f64,
    })))
}
