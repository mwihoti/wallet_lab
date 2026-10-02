use bitcoin_dojo::ecc::ecdsa::sign;
use bitcoin_dojo::transaction::tx::Tx;
use bitcoin_dojo::transaction::tx_input::TxInput;
use bitcoin_dojo::transaction::tx_output::TxOutput;
use bitcoin_dojo::utils::address_types::Network;
use bitcoin_dojo::utils::base58::decode_base58_check;
use bitcoin_dojo::utils::hash160::hash160;
use bitcoin_dojo::utils::hash256::hash256;
use bitcoin_dojo::utils::varint::encode_varint;
use serde::{Deserialize, Serialize};
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

// ── Address classification ────────────────────────────────────────────────────

/// Which kind of output script an address locks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    P2pkh,
    P2sh,
    P2wpkh,
}

impl AddressKind {
    /// Serialized size of an output paying to this script type, in bytes:
    /// 8 (amount) + 1 (script length) + script.
    pub fn output_size(self) -> u64 {
        match self {
            AddressKind::P2pkh  => 8 + 1 + 25,
            AddressKind::P2sh   => 8 + 1 + 23,
            AddressKind::P2wpkh => 8 + 1 + 22,
        }
    }

    /// Bitcoin Core's default dust threshold for this output type at the
    /// 3 sat/vB dust relay fee: an output is dust if spending it would cost
    /// more than a third of its value.
    pub fn dust_limit(self) -> u64 {
        match self {
            AddressKind::P2pkh  => 546,
            AddressKind::P2sh   => 540,
            AddressKind::P2wpkh => 294,
        }
    }
}

/// A decoded address: its type, network and the scriptPubKey it locks to.
#[derive(Debug, Clone, Serialize)]
pub struct AddressInfo {
    pub kind: AddressKind,
    pub network: &'static str,
    #[serde(serialize_with = "serialize_hex")]
    pub script_pubkey: Vec<u8>,
}

fn serialize_hex<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

/// Decode any supported address into its type, network and scriptPubKey.
pub fn classify_address(address: &str) -> Result<AddressInfo, AppError> {
    let lower = address.to_lowercase();
    if lower.starts_with("tb1") || lower.starts_with("bc1") {
        let network = if lower.starts_with("tb1") { "testnet" } else { "mainnet" };
        let hash = decode_p2wpkh_address(address)?;
        return Ok(AddressInfo {
            kind: AddressKind::P2wpkh,
            network,
            script_pubkey: build_p2wpkh_scriptpubkey(&hash),
        });
    }

    let payload = decode_base58_check(address)
        .map_err(|e| AppError::InvalidAddress(e.to_string()))?;
    if payload.len() != 21 {
        return Err(AppError::InvalidAddress(format!(
            "Expected 21-byte payload, got {}", payload.len()
        )));
    }
    let hash: [u8; 20] = payload[1..21].try_into().unwrap();
    let version = payload[0];
    let (kind, network, script_pubkey) = if version == Network::Testnet.p2pkh_version() {
        (AddressKind::P2pkh, "testnet", build_p2pkh_scriptpubkey(&hash))
    } else if version == Network::Mainnet.p2pkh_version() {
        (AddressKind::P2pkh, "mainnet", build_p2pkh_scriptpubkey(&hash))
    } else if version == Network::Testnet.p2sh_version() {
        (AddressKind::P2sh, "testnet", build_p2sh_scriptpubkey(&hash))
    } else if version == Network::Mainnet.p2sh_version() {
        (AddressKind::P2sh, "mainnet", build_p2sh_scriptpubkey(&hash))
    } else {
        return Err(AppError::InvalidAddress(format!(
            "Unexpected version byte 0x{:02X}", version
        )));
    };
    Ok(AddressInfo { kind, network, script_pubkey })
}

// ── Transaction builder ───────────────────────────────────────────────────────

/// One UTXO to spend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputSpec {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

/// An unsigned transaction plus the accounting the UI shows the learner.
#[derive(Debug, Clone)]
pub struct BuiltTx {
    pub tx: Tx,
    pub input_total: u64,
    /// Final fee, including any change folded in because it was dust.
    pub fee: u64,
    /// Change paid back to the sender (0 if there is no change output).
    pub change: u64,
    /// Change that was below the dust limit and was added to the fee instead.
    pub dust_change_added_to_fee: u64,
}

/// Build an unsigned transaction spending `inputs` to one recipient, with
/// change back to `sender_address`.
///
/// Change below the dust limit is not created as an output (nodes would reject
/// the transaction as non-standard); it is added to the fee instead.
pub fn build_tx(
    inputs: &[InputSpec],
    recipient_address: &str,
    send_amount: u64,
    fee: u64,
    sender_address: &str,
) -> Result<BuiltTx, AppError> {
    if inputs.is_empty() {
        return Err(AppError::ParseError("Select at least one UTXO to spend".to_string()));
    }

    let recipient = classify_address(recipient_address)?;
    if recipient.network != "testnet" {
        return Err(AppError::InvalidAddress(
            "This is a mainnet address — the lab runs on testnet4, use a testnet address".to_string(),
        ));
    }
    if send_amount < recipient.kind.dust_limit() {
        return Err(AppError::ParseError(format!(
            "Amount {} sat is below the {} sat dust limit for this address type",
            send_amount, recipient.kind.dust_limit()
        )));
    }

    let mut input_total: u64 = 0;
    let mut tx_ins = Vec::with_capacity(inputs.len());
    for spec in inputs {
        // Decode txid: display format (big-endian hex) → internal byte order (reversed)
        let txid_bytes = hex::decode(&spec.txid)
            .map_err(|_| AppError::ParseError("Invalid UTXO txid hex".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err(AppError::ParseError("UTXO txid must be 32 bytes".to_string()));
        }
        let mut prev_tx_id = [0u8; 32];
        prev_tx_id.copy_from_slice(&txid_bytes);
        prev_tx_id.reverse();

        if tx_ins.iter().any(|i: &TxInput| i.prev_tx_id == prev_tx_id && i.prev_index == spec.vout) {
            return Err(AppError::ParseError(format!(
                "UTXO {}:{} is selected twice", spec.txid, spec.vout
            )));
        }

        input_total = input_total.checked_add(spec.value)
            .ok_or_else(|| AppError::ParseError("Input total overflows".to_string()))?;

        tx_ins.push(TxInput {
            prev_tx_id,
            prev_index: spec.vout,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
    }

    let total_out = send_amount.checked_add(fee)
        .ok_or_else(|| AppError::ParseError("Amount plus fee overflows".to_string()))?;
    if total_out > input_total {
        return Err(AppError::InsufficientFunds {
            available: input_total,
            required: total_out,
        });
    }

    let mut outputs = vec![TxOutput { amount: send_amount, script_pubkey: recipient.script_pubkey }];

    let mut change = input_total - total_out;
    let mut dust_change_added_to_fee = 0;
    if change > 0 {
        let sender = classify_address(sender_address)?;
        if change < sender.kind.dust_limit() {
            dust_change_added_to_fee = change;
            change = 0;
        } else {
            outputs.push(TxOutput { amount: change, script_pubkey: sender.script_pubkey });
        }
    }

    Ok(BuiltTx {
        tx: Tx::new(1, tx_ins, outputs, 0),
        input_total,
        fee: fee + dust_change_added_to_fee,
        change,
        dust_change_added_to_fee,
    })
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

/// A signed transaction ready to broadcast.
#[derive(Debug, Clone)]
pub struct SignedTx {
    pub raw: Vec<u8>,
    /// reverse(hash256(non-witness serialization))
    pub txid: String,
    /// reverse(hash256(full serialization)); equals txid for legacy transactions
    pub wtxid: String,
    /// Virtual size in vBytes: ceil(weight / 4)
    pub vsize: u64,
    pub weight: u64,
}

/// Sign every input of a P2PKH transaction. All inputs must be locked to
/// `utxo_script_pubkey` (the sender's own P2PKH address).
pub fn sign_and_assemble(
    mut tx: Tx,
    wif: &str,
    utxo_script_pubkey: &[u8],
) -> Result<SignedTx, AppError> {
    let private_key      = decode_wif(wif)?;
    let public_key       = private_key.public_key();
    let compressed_pubkey = public_key.to_sec(true);

    // Every sighash commits to the unsigned tx (other scriptSigs are blanked),
    // so compute them all before filling any scriptSig in.
    let mut script_sigs = Vec::with_capacity(tx.tx_ins.len());
    for i in 0..tx.tx_ins.len() {
        let sighash = compute_sighash(&tx, i, utxo_script_pubkey)?;
        let sig     = sign(&private_key, &sighash);
        let mut der_with_hashtype = sig.to_der();
        der_with_hashtype.push(0x01);
        script_sigs.push(build_p2pkh_scriptsig(&der_with_hashtype, &compressed_pubkey));
    }
    for (inp, script_sig) in tx.tx_ins.iter_mut().zip(script_sigs) {
        inp.script_sig = script_sig;
    }

    let raw  = tx.serialize();
    let txid = txid_from_bytes(&raw);
    let weight = raw.len() as u64 * 4;
    Ok(SignedTx { txid: txid.clone(), wtxid: txid, vsize: weight.div_ceil(4), weight, raw })
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
/// `witnesses` holds one stack per input (an empty stack for a non-witness input).
/// The TXID is still computed from `tx.serialize()` (non-witness, no marker/flag).
pub fn serialize_witness_tx(tx: &Tx, witnesses: &[Vec<Vec<u8>>]) -> Vec<u8> {
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

    for i in 0..tx.tx_ins.len() {
        let stack = witnesses.get(i).map(Vec::as_slice).unwrap_or(&[]);
        raw.extend(encode_varint(stack.len() as u64));
        for item in stack {
            raw.extend(encode_varint(item.len() as u64));
            raw.extend_from_slice(item);
        }
    }

    raw.extend_from_slice(&tx.locktime.to_le_bytes());
    raw
}

/// Sign every input of a SegWit transaction (P2WPKH or P2SH-P2WPKH).
///
/// `input_values[i]` is the satoshi value of input `i` — BIP143 commits to it.
/// `wallet_type`: `"p2wpkh"` or `"p2sh_p2wpkh"`
pub fn sign_and_assemble_segwit(
    mut tx: Tx,
    wif: &str,
    input_values: &[u64],
    wallet_type: &str,
) -> Result<SignedTx, AppError> {
    if input_values.len() != tx.tx_ins.len() {
        return Err(AppError::ParseError("One value is required per input".to_string()));
    }

    let private_key       = decode_wif(wif)?;
    let public_key        = private_key.public_key();
    let compressed_pubkey = public_key.to_sec(true);

    let pubkey_hash = hash160(&compressed_pubkey);

    // P2SH-P2WPKH: scriptSig = push(redeem_script)
    // P2WPKH: scriptSig stays empty.
    // BIP143 sighashes do not commit to scriptSigs, so it is fine to set them first.
    if wallet_type == "p2sh_p2wpkh" {
        let mut redeem_script = vec![0x00, 0x14]; // OP_0 PUSH_20
        redeem_script.extend_from_slice(&pubkey_hash);
        let mut script_sig = Vec::new();
        script_sig.push(redeem_script.len() as u8); // single push opcode
        script_sig.extend_from_slice(&redeem_script);
        for inp in tx.tx_ins.iter_mut() {
            inp.script_sig = script_sig.clone();
        }
    }

    // Witness per input: [signature, pubkey]
    let mut witnesses = Vec::with_capacity(tx.tx_ins.len());
    for (i, value) in input_values.iter().enumerate() {
        let sighash = compute_bip143_sighash(&tx, i, &pubkey_hash, *value)?;
        let sig     = sign(&private_key, &sighash);
        let mut der_with_hashtype = sig.to_der();
        der_with_hashtype.push(0x01);
        witnesses.push(vec![der_with_hashtype, compressed_pubkey.clone()]);
    }

    let raw       = serialize_witness_tx(&tx, &witnesses);
    let stripped  = tx.serialize();
    // TXID uses the non-witness serialisation; WTXID hashes everything.
    let txid      = txid_from_bytes(&stripped);
    let wtxid     = txid_from_bytes(&raw);
    // BIP141 weight: base size × 3 + total size
    let weight    = stripped.len() as u64 * 3 + raw.len() as u64;

    Ok(SignedTx { raw, txid, wtxid, vsize: weight.div_ceil(4), weight })
}

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Standard display id: reverse(hash256(bytes)) as hex.
pub fn txid_from_bytes(raw: &[u8]) -> String {
    let hash = hash256(raw);
    hex::encode(hash.iter().rev().copied().collect::<Vec<u8>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use bitcoin_dojo::ecc::ecdsa::{verify, Signature};
    use bitcoin_dojo::ecc::keys::PublicKey;
    use crate::wallet::keygen::generate_wallet;

    const TXID_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TXID_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn input(txid: &str, vout: u32, value: u64) -> InputSpec {
        InputSpec { txid: txid.to_string(), vout, value }
    }

    #[test]
    fn classify_address_detects_all_wallet_types() {
        let w = generate_wallet();
        assert_eq!(classify_address(&w.p2pkh).unwrap().kind, AddressKind::P2pkh);
        assert_eq!(classify_address(&w.p2sh_p2wpkh).unwrap().kind, AddressKind::P2sh);
        assert_eq!(classify_address(&w.p2wpkh).unwrap().kind, AddressKind::P2wpkh);
        for a in [&w.p2pkh, &w.p2sh_p2wpkh, &w.p2wpkh] {
            assert_eq!(classify_address(a).unwrap().network, "testnet");
        }
    }

    #[test]
    fn classify_address_rejects_bad_checksum_and_flags_mainnet() {
        let w = generate_wallet();
        let mut broken = w.p2wpkh.clone();
        let last = broken.pop().unwrap();
        broken.push(if last == 'q' { 'p' } else { 'q' });
        assert!(classify_address(&broken).is_err());

        // Satoshi's genesis coinbase address
        let info = classify_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(info.network, "mainnet");
        assert_eq!(info.kind, AddressKind::P2pkh);
    }

    #[test]
    fn build_tx_spends_multiple_inputs_with_change() {
        let w = generate_wallet();
        let built = build_tx(
            &[input(TXID_A, 0, 6_000), input(TXID_B, 1, 5_000)],
            &w.p2wpkh, 9_000, 500, &w.p2pkh,
        ).unwrap();
        assert_eq!(built.tx.tx_ins.len(), 2);
        assert_eq!(built.input_total, 11_000);
        assert_eq!(built.change, 1_500);
        assert_eq!(built.fee, 500);
        assert_eq!(built.tx.tx_outs.len(), 2);
        assert_eq!(built.tx.tx_outs[1].amount, 1_500);
        // txid is stored in internal (reversed) byte order
        assert_eq!(built.tx.tx_ins[1].prev_index, 1);
        assert_eq!(built.tx.tx_ins[1].prev_tx_id, [0x22; 32]);
    }

    #[test]
    fn build_tx_folds_dust_change_into_fee() {
        let w = generate_wallet();
        // 10_000 - 9_000 - 600 = 400 sat change < 546 P2PKH dust limit
        let built = build_tx(&[input(TXID_A, 0, 10_000)], &w.p2wpkh, 9_000, 600, &w.p2pkh).unwrap();
        assert_eq!(built.tx.tx_outs.len(), 1);
        assert_eq!(built.change, 0);
        assert_eq!(built.dust_change_added_to_fee, 400);
        assert_eq!(built.fee, 1_000);

        // Same 400 sat is above the 294 sat P2WPKH dust limit, so it is kept
        let built = build_tx(&[input(TXID_A, 0, 10_000)], &w.p2pkh, 9_000, 600, &w.p2wpkh).unwrap();
        assert_eq!(built.tx.tx_outs.len(), 2);
        assert_eq!(built.change, 400);
    }

    #[test]
    fn build_tx_rejects_invalid_requests() {
        let w = generate_wallet();
        let one = [input(TXID_A, 0, 10_000)];
        assert!(matches!(
            build_tx(&one, &w.p2wpkh, 9_900, 200, &w.p2pkh),
            Err(AppError::InsufficientFunds { available: 10_000, required: 10_100 })
        ));
        assert!(build_tx(&[], &w.p2wpkh, 1_000, 200, &w.p2pkh).is_err());
        assert!(build_tx(&one, &w.p2wpkh, 100, 200, &w.p2pkh).is_err(), "dust amount");
        assert!(build_tx(&one, &w.p2wpkh, u64::MAX, 1, &w.p2pkh).is_err(), "overflow");
        assert!(build_tx(&one, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1_000, 200, &w.p2pkh).is_err(), "mainnet");
        assert!(build_tx(
            &[input(TXID_A, 0, 10_000), input(TXID_A, 0, 10_000)],
            &w.p2wpkh, 1_000, 200, &w.p2pkh,
        ).is_err(), "duplicate input");
    }

    /// BIP143 "Native P2WPKH" test vector, input 1.
    #[test]
    fn bip143_sighash_matches_spec_vector() {
        let unsigned = hex::decode(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000\
             00eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
             00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac90\
             93510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
        ).unwrap();
        let tx = Tx::parse(Cursor::new(&unsigned)).unwrap();
        let pubkey_hash: [u8; 20] = hex::decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
            .unwrap().try_into().unwrap();
        let sighash = compute_bip143_sighash(&tx, 1, &pubkey_hash, 600_000_000).unwrap();
        assert_eq!(
            hex::encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    #[test]
    fn legacy_signing_signs_every_input() {
        let w = generate_wallet();
        let built = build_tx(
            &[input(TXID_A, 0, 6_000), input(TXID_B, 3, 5_000)],
            &w.p2wpkh, 9_000, 500, &w.p2pkh,
        ).unwrap();
        let unsigned = built.tx.clone();
        let spk = build_p2pkh_scriptpubkey(&decode_p2pkh_address(&w.p2pkh).unwrap());
        let signed = sign_and_assemble(built.tx, &w.wif, &spk).unwrap();

        assert_eq!(signed.txid, signed.wtxid);
        assert_eq!(signed.vsize, signed.raw.len() as u64);

        let parsed = Tx::parse(Cursor::new(&signed.raw)).unwrap();
        let pubkey = PublicKey::parse(&hex::decode(&w.pubkey_hex).unwrap()).unwrap();
        for i in 0..2 {
            let script_sig = &parsed.tx_ins[i].script_sig;
            let sig_len = script_sig[0] as usize;
            let sig = Signature::from_der(&script_sig[1..sig_len]).unwrap();
            let sighash = compute_sighash(&unsigned, i, &spk).unwrap();
            assert!(verify(&pubkey, &sighash, &sig), "input {i} signature must verify");
        }
    }

    #[test]
    fn segwit_signing_signs_every_input_and_reports_vsize() {
        let w = generate_wallet();
        for (addr, kind) in [(&w.p2wpkh, "p2wpkh"), (&w.p2sh_p2wpkh, "p2sh_p2wpkh")] {
            let built = build_tx(
                &[input(TXID_A, 0, 6_000), input(TXID_B, 1, 5_000)],
                &w.p2pkh, 9_000, 500, addr,
            ).unwrap();
            let signed = sign_and_assemble_segwit(built.tx, &w.wif, &[6_000, 5_000], kind).unwrap();

            assert_ne!(signed.txid, signed.wtxid);
            assert_eq!(&signed.raw[4..6], &[0x00, 0x01], "segwit marker + flag");

            let (tx, witnesses) = crate::wallet::malleability::parse_tx(&signed.raw).unwrap();
            let witnesses = witnesses.unwrap();
            assert_eq!(witnesses.len(), 2);
            assert_eq!(txid_from_bytes(&tx.serialize()), signed.txid);

            let pubkey = PublicKey::parse(&witnesses[0][1]).unwrap();
            let pkh = hash160(&witnesses[0][1]);
            for (i, value) in [6_000u64, 5_000].iter().enumerate() {
                let der = &witnesses[i][0];
                let sig = Signature::from_der(&der[..der.len() - 1]).unwrap();
                let sighash = compute_bip143_sighash(&tx, i, &pkh, *value).unwrap();
                assert!(verify(&pubkey, &sighash, &sig), "{kind} input {i} must verify");
            }

            // Weight = 3 × stripped size + total size
            let expected_weight = tx.serialize().len() as u64 * 3 + signed.raw.len() as u64;
            assert_eq!(signed.weight, expected_weight);
            assert!(signed.vsize < signed.raw.len() as u64, "witness discount");
        }
    }
}
