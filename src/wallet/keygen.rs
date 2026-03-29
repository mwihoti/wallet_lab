use bitcoin_dojo::ecc::keys::PrivateKey;
use bitcoin_dojo::ecc::scalar::Scalar;
use bitcoin_dojo::utils::address_types::Network;
use bitcoin_dojo::utils::base58::decode_base58_check;
use serde::Serialize;
use crate::error::AppError;

#[derive(Debug, Serialize)]
pub struct WalletInfo {
    /// WIF-encoded private key (testnet, compressed)
    pub wif: String,
    /// Compressed public key as hex
    pub pubkey_hex: String,
    pub network: String,

    // All three address types derived from the same key
    pub p2pkh: String,
    pub p2sh_p2wpkh: String,
    pub p2wpkh: String,

    // Backward-compat alias: default address = P2PKH
    pub address: String,
}

/// Generate a fresh testnet wallet with all address types from a single key.
pub fn generate_wallet() -> WalletInfo {
    let private_key = PrivateKey::new();
    let public_key  = private_key.public_key();

    let p2pkh       = public_key.p2pkh_address(Network::Testnet);
    let p2sh_p2wpkh = public_key.p2sh_p2wpkh_address(Network::Testnet);
    let p2wpkh      = public_key.p2wpkh_address(Network::Testnet);
    let wif         = private_key.to_wif(Network::Testnet, true);
    let pubkey_hex  = hex::encode(public_key.to_sec(true));

    WalletInfo {
        address: p2pkh.clone(),
        p2pkh,
        p2sh_p2wpkh,
        p2wpkh,
        wif,
        pubkey_hex,
        network: "testnet".to_string(),
    }
}

/// Decode a testnet WIF string back into a PrivateKey.
pub fn decode_wif(wif: &str) -> Result<PrivateKey, AppError> {
    let payload = decode_base58_check(wif)
        .map_err(|e| AppError::InvalidWif(e.to_string()))?;

    if payload.len() != 34 {
        return Err(AppError::InvalidWif(format!(
            "Expected 34-byte WIF payload, got {}", payload.len()
        )));
    }
    if payload[0] != 0xEF {
        return Err(AppError::InvalidWif(format!(
            "Expected testnet WIF version 0xEF, got 0x{:02X}", payload[0]
        )));
    }

    let scalar_bytes: [u8; 32] = payload[1..33]
        .try_into()
        .map_err(|_| AppError::InvalidWif("Could not extract 32 scalar bytes".to_string()))?;

    Ok(PrivateKey::from_scalar(Scalar::from_bytes(&scalar_bytes)))
}
