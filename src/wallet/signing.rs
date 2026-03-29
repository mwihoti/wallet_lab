use bitcoin_dojo::ecc::ecdsa::sign;
use bitcoin_dojo::transaction::tx::Tx;
use bitcoin_dojo::transaction::tx_input::TxInput;
use bitcoin_dojo::transaction::tx_output::TxOutput;
use bitcoin_dojo::utils::address_types::Network;
use bitcoin_dojo::utils::base58::decode_base58_check;
use bitcoin_dojo::utils::hash160::hash160;
use bitcoin_dojo::utils::hash256::hash256;
use bitcoin_dojo::utils::varint::encode_varint;
use crate::error::AppError;
use crate::script::p2pkh::{build_p2pkh_scriptpubkey, build_p2pkh_scriptsig};
use crate::script::p2sh::build_p2sh_scriptpubkey;
use crate::script::p2wpkh::build_p2wpkh_scriptpubkey;
use crate::wallet::keygen::decode_wif;

// ── Address decoding ──────────────────────────────────────────────────────────

/// Decode a testnet P2PKH address to its 20-byte pubkey hash.
pub fn decode_p2pkh_address(address: &str) -> Result<[u8; 20], AppError> {
    let payload = decode_base58_check(address)
        .map_err(|e| AppError::InvalidAddress(e.to_string()))?;
    if payload.len() != 21 {
        return Err(AppError::InvalidAddress(format!(
            "Expected 21-byte P2PKH payload, got {}", payload.len()
        )));
    }
    if payload[0] != Network::Testnet.p2pkh_version() && payload[0] != Network::Mainnet.p2pkh_version() {
        return Err(AppError::InvalidAddress(format!(
            "Unexpected version byte 0x{:02X}", payload[0]
        )));
    }
    Ok(payload[1..21].try_into().unwrap())
}

/// Decode a testnet P2SH address to its 20-byte script hash.
pub fn decode_p2sh_address(address: &str) -> Result<[u8; 20], AppError> {
    let payload = decode_base58_check(address)
        .map_err(|e| AppError::InvalidAddress(e.to_string()))?;
    if payload.len() != 21 {
        return Err(AppError::InvalidAddress(format!(
            "Expected 21-byte P2SH payload, got {}", payload.len()
        )));
    }
    if payload[0] != Network::Testnet.p2sh_version() && payload[0] != Network::Mainnet.p2sh_version() {
        return Err(AppError::InvalidAddress(format!(
            "Unexpected P2SH version byte 0x{:02X}", payload[0]
        )));
    }
    Ok(payload[1..21].try_into().unwrap())
}

/// Decode a bech32 P2WPKH address to its 20-byte pubkey hash.
pub fn decode_p2wpkh_address(address: &str) -> Result<[u8; 20], AppError> {
    let hrp = if address.starts_with("bc1") { "bc" } else { "tb" };
    let (version, program) = bitcoin_dojo::utils::bech32::decode(hrp, address)
        .ok_or_else(|| AppError::InvalidAddress(format!("Invalid bech32 address: {}", address)))?;
    if version != 0 {
        return Err(AppError::InvalidAddress(format!("Unsupported witness version: {}", version)));
    }
    if program.len() != 20 {
        return Err(AppError::InvalidAddress(format!(
            "Expected 20-byte P2WPKH program, got {}", program.len()
        )));
    }
    Ok(program.try_into().unwrap())
}

/// Detect address type and build the corresponding output scriptPubKey.
pub fn address_to_scriptpubkey(address: &str) -> Result<Vec<u8>, AppError> {
    if address.starts_with("tb1") || address.starts_with("bc1") {
        let hash = decode_p2wpkh_address(address)?;
        Ok(build_p2wpkh_scriptpubkey(&hash))
    } else if address.starts_with('2') || address.starts_with('3') {
        let hash = decode_p2sh_address(address)?;
        Ok(build_p2sh_scriptpubkey(&hash))
    } else {
        // m, n, 1 — P2PKH
        let hash = decode_p2pkh_address(address)?;
        Ok(build_p2pkh_scriptpubkey(&hash))
    }
}

// ── Transaction builder ───────────────────────────────────────────────────────

/// Build an unsigned transaction with generic output scripts.
///
/// Works for any wallet type — output scriptPubKeys are derived from the
/// recipient and sender addresses automatically.
pub fn build_tx(
    utxo_txid: &str,
    utxo_vout: u32,
    utxo_value: u64,
    recipient_address: &str,
    send_amount: u64,
    fee: u64,
    sender_address: &str,
) -> Result<Tx, AppError> {
    let total_out = send_amount + fee;
    if total_out > utxo_value {
        return Err(AppError::InsufficientFunds {
            available: utxo_value,
            required: total_out,
        });
    }

    // Decode txid: display format (big-endian hex) → internal byte order (reversed)
    let txid_bytes = hex::decode(utxo_txid)
        .map_err(|_| AppError::ParseError("Invalid UTXO txid hex".to_string()))?;
    if txid_bytes.len() != 32 {
        return Err(AppError::ParseError("UTXO txid must be 32 bytes".to_string()));
    }
    let mut prev_tx_id = [0u8; 32];
    prev_tx_id.copy_from_slice(&txid_bytes);
    prev_tx_id.reverse();

    let input = TxInput {
        prev_tx_id,
        prev_index: utxo_vout,
        script_sig: vec![],
        sequence: 0xFFFFFFFF,
    };

    let recipient_script = address_to_scriptpubkey(recipient_address)?;
    let mut outputs = vec![TxOutput { amount: send_amount, script_pubkey: recipient_script }];

    let change = utxo_value - total_out;
    if change > 0 {
        let change_script = address_to_scriptpubkey(sender_address)?;
        outputs.push(TxOutput { amount: change, script_pubkey: change_script });
    }

    Ok(Tx::new(1, vec![input], outputs, 0))
}

/// Build an unsigned P2PKH transaction (kept for backward compat).
pub fn build_p2pkh_tx(
    utxo_txid: &str,
    utxo_vout: u32,
    utxo_value: u64,
    recipient_address: &str,
    send_amount: u64,
    fee: u64,
    sender_address: &str,
) -> Result<Tx, AppError> {
    build_tx(utxo_txid, utxo_vout, utxo_value, recipient_address, send_amount, fee, sender_address)
}

// ── Legacy P2PKH signing ──────────────────────────────────────────────────────

/// Compute the legacy P2PKH sighash for a single input (SIGHASH_ALL).
pub fn compute_sighash(
    tx: &Tx,
    input_index: usize,
    utxo_script_pubkey: &[u8],
) -> Result<[u8; 32], AppError> {
    if input_index >= tx.tx_ins.len() {
        return Err(AppError::ParseError("input_index out of range".to_string()));
    }

    let mut preimage: Vec<u8> = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());

    preimage.extend(encode_varint(tx.tx_ins.len() as u64));
    for (i, inp) in tx.tx_ins.iter().enumerate() {
        preimage.extend_from_slice(&inp.prev_tx_id);
        preimage.extend_from_slice(&inp.prev_index.to_le_bytes());
        if i == input_index {
            preimage.extend(encode_varint(utxo_script_pubkey.len() as u64));
            preimage.extend_from_slice(utxo_script_pubkey);
        } else {
            preimage.push(0x00);
        }
        preimage.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    preimage.extend(encode_varint(tx.tx_outs.len() as u64));
    for out in &tx.tx_outs {
        preimage.extend_from_slice(&out.amount.to_le_bytes());
        preimage.extend(encode_varint(out.script_pubkey.len() as u64));
        preimage.extend_from_slice(&out.script_pubkey);
    }

    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&1u32.to_le_bytes()); // SIGHASH_ALL

    Ok(hash256(&preimage))
}

/// Sign a P2PKH transaction and return (raw_bytes, display_txid).
pub fn sign_and_assemble(
    mut tx: Tx,
    wif: &str,
    input_index: usize,
    utxo_script_pubkey: &[u8],
) -> Result<(Vec<u8>, String), AppError> {
    let private_key      = decode_wif(wif)?;
    let public_key       = private_key.public_key();
    let compressed_pubkey = public_key.to_sec(true);

    let sighash = compute_sighash(&tx, input_index, utxo_script_pubkey)?;
    let sig     = sign(&private_key, &sighash);

    let mut der_with_hashtype = sig.to_der();
    der_with_hashtype.push(0x01);

    tx.tx_ins[input_index].script_sig =
        build_p2pkh_scriptsig(&der_with_hashtype, &compressed_pubkey);

    let raw_bytes    = tx.serialize();
    let display_txid = txid_from_bytes(&raw_bytes);
    Ok((raw_bytes, display_txid))
}

// ── SegWit BIP143 signing ─────────────────────────────────────────────────────

/// Compute the BIP143 sighash for a P2WPKH or P2SH-P2WPKH input (SIGHASH_ALL).
///
/// `pubkey_hash` is hash160(compressed_pubkey) of the key that controls the UTXO.
/// `utxo_value` is the satoshi value of the input being signed.
pub fn compute_bip143_sighash(
    tx: &Tx,
    input_index: usize,
    pubkey_hash: &[u8; 20],
    utxo_value: u64,
) -> Result<[u8; 32], AppError> {
    if input_index >= tx.tx_ins.len() {
        return Err(AppError::ParseError("input_index out of range".to_string()));
    }

    // hashPrevouts
    let mut prevouts = Vec::new();
    for inp in &tx.tx_ins {
        prevouts.extend_from_slice(&inp.prev_tx_id);
        prevouts.extend_from_slice(&inp.prev_index.to_le_bytes());
    }
    let hash_prevouts = hash256(&prevouts);

    // hashSequence
    let mut seqs = Vec::new();
    for inp in &tx.tx_ins { seqs.extend_from_slice(&inp.sequence.to_le_bytes()); }
    let hash_sequence = hash256(&seqs);

    // hashOutputs
    let mut outs = Vec::new();
    for out in &tx.tx_outs {
        outs.extend_from_slice(&out.amount.to_le_bytes());
        outs.extend(encode_varint(out.script_pubkey.len() as u64));
        outs.extend_from_slice(&out.script_pubkey);
    }
    let hash_outputs = hash256(&outs);

    // scriptCode for P2WPKH = OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    let script_code = build_p2pkh_scriptpubkey(pubkey_hash);

    let inp = &tx.tx_ins[input_index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());    // nVersion
    preimage.extend_from_slice(&hash_prevouts);                // hashPrevouts
    preimage.extend_from_slice(&hash_sequence);                // hashSequence
    preimage.extend_from_slice(&inp.prev_tx_id);               // outpoint txid
    preimage.extend_from_slice(&inp.prev_index.to_le_bytes()); // outpoint vout
    preimage.extend(encode_varint(script_code.len() as u64));  // scriptCode length
    preimage.extend_from_slice(&script_code);                  // scriptCode
    preimage.extend_from_slice(&utxo_value.to_le_bytes());     // value
    preimage.extend_from_slice(&inp.sequence.to_le_bytes());   // nSequence
    preimage.extend_from_slice(&hash_outputs);                 // hashOutputs
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());    // nLocktime
    preimage.extend_from_slice(&1u32.to_le_bytes());           // SIGHASH_ALL

    Ok(hash256(&preimage))
}

/// Serialize a transaction with SegWit witness data (BIP 141 format).
///
/// The TXID is still computed from `tx.serialize()` (non-witness, no marker/flag).
fn serialize_witness_tx(tx: &Tx, witness: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = Vec::new();

    raw.extend_from_slice(&tx.version.to_le_bytes());
    raw.push(0x00); // segwit marker
    raw.push(0x01); // segwit flag

    raw.extend(encode_varint(tx.tx_ins.len() as u64));
    for inp in &tx.tx_ins {
        raw.extend_from_slice(&inp.prev_tx_id);
        raw.extend_from_slice(&inp.prev_index.to_le_bytes());
        raw.extend(encode_varint(inp.script_sig.len() as u64));
        raw.extend_from_slice(&inp.script_sig);
        raw.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    raw.extend(encode_varint(tx.tx_outs.len() as u64));
    for out in &tx.tx_outs {
        raw.extend_from_slice(&out.amount.to_le_bytes());
        raw.extend(encode_varint(out.script_pubkey.len() as u64));
        raw.extend_from_slice(&out.script_pubkey);
    }

    // One witness stack per input. Only our single input has [sig, pubkey].
    for (i, _) in tx.tx_ins.iter().enumerate() {
        if i == 0 && !witness.is_empty() {
            raw.extend(encode_varint(witness.len() as u64));
            for item in witness {
                raw.extend(encode_varint(item.len() as u64));
                raw.extend_from_slice(item);
            }
        } else {
            raw.push(0x00); // empty witness for this input
        }
    }

    raw.extend_from_slice(&tx.locktime.to_le_bytes());
    raw
}

/// Sign a SegWit input (P2WPKH or P2SH-P2WPKH) and return (raw_bytes, display_txid).
///
/// `wallet_type`: `"p2wpkh"` or `"p2sh_p2wpkh"`
pub fn sign_and_assemble_segwit(
    mut tx: Tx,
    wif: &str,
    input_index: usize,
    utxo_value: u64,
    wallet_type: &str,
) -> Result<(Vec<u8>, String), AppError> {
    let private_key       = decode_wif(wif)?;
    let public_key        = private_key.public_key();
    let compressed_pubkey = public_key.to_sec(true);

    let pubkey_hash = hash160(&compressed_pubkey);

    // BIP143 sighash
    let sighash = compute_bip143_sighash(&tx, input_index, &pubkey_hash, utxo_value)?;
    let sig     = sign(&private_key, &sighash);

    let mut der_with_hashtype = sig.to_der();
    der_with_hashtype.push(0x01);

    // P2SH-P2WPKH: scriptSig = push(redeem_script)
    // P2WPKH: scriptSig stays empty
    if wallet_type == "p2sh_p2wpkh" {
        let mut redeem_script = vec![0x00, 0x14]; // OP_0 PUSH_20
        redeem_script.extend_from_slice(&pubkey_hash);
        let mut script_sig = Vec::new();
        script_sig.push(redeem_script.len() as u8); // single push opcode
        script_sig.extend_from_slice(&redeem_script);
        tx.tx_ins[input_index].script_sig = script_sig;
    }

    // Witness: [signature, pubkey]
    let witness = vec![der_with_hashtype, compressed_pubkey];

    let raw_bytes    = serialize_witness_tx(&tx, &witness);
    // TXID uses non-witness serialisation (legacy format of tx after scriptSig is set)
    let display_txid = txid_from_bytes(&tx.serialize());

    Ok((raw_bytes, display_txid))
}

// ── Shared helper ─────────────────────────────────────────────────────────────

fn txid_from_bytes(raw: &[u8]) -> String {
    let hash = hash256(raw);
    hex::encode(hash.iter().rev().copied().collect::<Vec<u8>>())
}
