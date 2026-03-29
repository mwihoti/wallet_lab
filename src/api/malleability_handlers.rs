use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use bitcoin_dojo::ecc::constants::SECP256K1_N;
use bitcoin_dojo::ecc::ecdsa::Signature;
use bitcoin_dojo::ecc::scalar::Scalar;
use bitcoin_dojo::transaction::tx::Tx;
use bitcoin_dojo::utils::hash256::hash256;
use num_bigint::BigUint;
use crate::{
    error::AppError,
    script::p2pkh::build_p2pkh_scriptsig,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct MalleabilityRequest {
    pub raw_tx_hex: String,
}

pub async fn malleability_demo(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<MalleabilityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Decode hex → bytes → parse transaction
    let raw_bytes = hex::decode(&body.raw_tx_hex)
        .map_err(|_| AppError::ParseError("Invalid raw tx hex".to_string()))?;

    let tx = Tx::parse(Cursor::new(&raw_bytes))
        .map_err(|e| AppError::ParseError(e.to_string()))?;

    if tx.tx_ins.is_empty() {
        return Err(AppError::ParseError("Transaction has no inputs".to_string()));
    }

    let script_sig = &tx.tx_ins[0].script_sig;

    // ── Extract DER signature from P2PKH scriptSig ────────────────────────────
    // Layout: <sig_len> <der_sig + 0x01 hashtype> <pubkey_len> <pubkey_bytes>
    if script_sig.is_empty() {
        return Err(AppError::ParseError("Input has empty scriptSig".to_string()));
    }
    let sig_push_len = script_sig[0] as usize;
    if script_sig.len() < 1 + sig_push_len {
        return Err(AppError::ParseError("scriptSig too short for signature".to_string()));
    }

    // DER sig + 0x01 hashtype
    let der_with_hashtype = &script_sig[1..1 + sig_push_len];
    // Strip the final 0x01 SIGHASH_ALL byte before passing to from_der
    let der_only = &der_with_hashtype[..der_with_hashtype.len() - 1];

    let original_sig = Signature::from_der(der_only)
        .ok_or_else(|| AppError::ParseError("Failed to parse DER signature".to_string()))?;

    // ── Extract pubkey bytes ──────────────────────────────────────────────────
    let pubkey_offset = 1 + sig_push_len;
    if script_sig.len() <= pubkey_offset {
        return Err(AppError::ParseError("scriptSig too short for pubkey".to_string()));
    }
    let pubkey_len = script_sig[pubkey_offset] as usize;
    let pubkey_bytes = &script_sig[pubkey_offset + 1..pubkey_offset + 1 + pubkey_len];

    // ── Flip s → N - s ───────────────────────────────────────────────────────
    let n: &BigUint = &*SECP256K1_N;
    let malleable_s = Scalar::new(n - original_sig.s.value());
    let malleable_sig = Signature { r: original_sig.r.clone(), s: malleable_s };

    // ── Re-encode DER + hashtype ──────────────────────────────────────────────
    let _orig_der_with_hashtype = der_with_hashtype.to_vec();

    let mut mall_der_with_hashtype = malleable_sig.to_der();
    mall_der_with_hashtype.push(0x01); // SIGHASH_ALL

    // ── Rebuild scriptSig with malleable sig ──────────────────────────────────
    let malleable_script_sig = build_p2pkh_scriptsig(&mall_der_with_hashtype, pubkey_bytes);

    // ── Reconstruct malleable transaction ────────────────────────────────────
    let mut mall_tx = tx.clone();
    mall_tx.tx_ins[0].script_sig = malleable_script_sig;
    let mall_raw = mall_tx.serialize();

    // ── Compute both display txids (reversed Hash256) ─────────────────────────
    let orig_txid = display_txid(&raw_bytes);
    let mall_txid = display_txid(&mall_raw);

    Ok(Json(json!({
        "original_txid":         orig_txid,
        "malleable_txid":        mall_txid,
        "original_sig_der_hex":  hex::encode(der_only),
        "malleable_sig_der_hex": hex::encode(&mall_der_with_hashtype[..mall_der_with_hashtype.len()-1]),
        "original_s_hex":        hex::encode(original_sig.s.as_bytes()),
        "malleable_s_hex":       hex::encode(malleable_sig.s.as_bytes()),
        "both_valid":            true,
        "explanation": "Flipping s → N-s produces a different valid ECDSA signature. \
                        The DER encoding changes, so the serialized transaction bytes change, \
                        so Hash256(tx) changes → different TXID. Same coins moved. \
                        This is why SegWit moves signatures outside the data hashed for the TXID."
    })))
}

/// Compute the standard Bitcoin display txid: reverse(Hash256(raw_tx_bytes)) as hex.
fn display_txid(raw_bytes: &[u8]) -> String {
    let hash = hash256(raw_bytes);
    hex::encode(hash.iter().rev().copied().collect::<Vec<u8>>())
}
