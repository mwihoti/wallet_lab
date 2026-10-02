//! Signature malleability: flip ECDSA `s → n − s` and show what happens to the IDs.
//!
//! Legacy: the signature lives in the scriptSig, which is hashed into the TXID,
//! so the TXID changes. SegWit: the signature lives in the witness, which is
//! only hashed into the WTXID, so the TXID stays the same.

use std::io::{Cursor, Read};
use bitcoin_dojo::ecc::constants::SECP256K1_N;
use bitcoin_dojo::ecc::ecdsa::Signature;
use bitcoin_dojo::ecc::scalar::Scalar;
use bitcoin_dojo::transaction::tx::Tx;
use bitcoin_dojo::utils::varint::decode_varint;
use num_bigint::BigUint;
use serde::Serialize;
use crate::error::AppError;
use crate::script::p2pkh::build_p2pkh_scriptsig;
use crate::wallet::signing::{serialize_witness_tx, txid_from_bytes};

#[derive(Debug, Serialize)]
pub struct MalleabilityResult {
    pub segwit: bool,
    pub original_txid: String,
    pub malleable_txid: String,
    pub original_wtxid: String,
    pub malleable_wtxid: String,
    pub txid_changed: bool,
    pub original_sig_der_hex: String,
    pub malleable_sig_der_hex: String,
    pub original_s_hex: String,
    pub malleable_s_hex: String,
    pub both_valid: bool,
    pub explanation: &'static str,
}

/// One witness stack (list of pushed items) per input.
pub type Witnesses = Vec<Vec<Vec<u8>>>;

/// Parse a transaction in either legacy or BIP141 (marker + flag + witness) format.
/// Returns the transaction and, for SegWit, one witness stack per input.
pub fn parse_tx(raw: &[u8]) -> Result<(Tx, Option<Witnesses>), AppError> {
    let bad = |e: String| AppError::ParseError(e);
    let is_segwit = raw.len() > 6 && raw[4] == 0x00 && raw[5] == 0x01;
    if !is_segwit {
        let tx = Tx::parse(Cursor::new(raw)).map_err(|e| bad(e.to_string()))?;
        return Ok((tx, None));
    }

    // Strip marker/flag and witnesses to get the legacy serialization, which
    // `Tx::parse` understands. Walk the body to find where the witnesses start.
    let mut cur = Cursor::new(&raw[6..]);
    let n_in = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
    for _ in 0..n_in {
        skip(&mut cur, 36)?;
        let len = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
        skip(&mut cur, len + 4)?;
    }
    let n_out = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
    for _ in 0..n_out {
        skip(&mut cur, 8)?;
        let len = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
        skip(&mut cur, len)?;
    }
    let body_end = 6 + cur.position() as usize;

    let mut witnesses = Vec::with_capacity(n_in as usize);
    for _ in 0..n_in {
        let items = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
        let mut stack = Vec::new();
        for _ in 0..items {
            let len = decode_varint(&mut cur).map_err(|e| bad(e.to_string()))?;
            let mut item = vec![0u8; len as usize];
            cur.read_exact(&mut item).map_err(|e| bad(e.to_string()))?;
            stack.push(item);
        }
        witnesses.push(stack);
    }
    let lock_start = 6 + cur.position() as usize;
    if raw.len() != lock_start + 4 {
        return Err(bad("Unexpected trailing bytes in SegWit transaction".to_string()));
    }

    let mut stripped = raw[..4].to_vec();
    stripped.extend_from_slice(&raw[6..body_end]);
    stripped.extend_from_slice(&raw[lock_start..]);
    let tx = Tx::parse(Cursor::new(&stripped)).map_err(|e| bad(e.to_string()))?;
    Ok((tx, Some(witnesses)))
}

fn skip(cur: &mut Cursor<&[u8]>, n: u64) -> Result<(), AppError> {
    let pos = cur.position() + n;
    if pos > cur.get_ref().len() as u64 {
        return Err(AppError::ParseError("Transaction truncated".to_string()));
    }
    cur.set_position(pos);
    Ok(())
}

/// Split `<der || hashtype>` and parse the DER part.
fn split_sig(sig_with_hashtype: &[u8]) -> Result<(Signature, u8), AppError> {
    let (hashtype, der) = sig_with_hashtype
        .split_last()
        .ok_or_else(|| AppError::ParseError("Empty signature".to_string()))?;
    let sig = Signature::from_der(der)
        .ok_or_else(|| AppError::ParseError("Failed to parse DER signature".to_string()))?;
    Ok((sig, *hashtype))
}

fn flip_s(sig: &Signature) -> Signature {
    let n: &BigUint = &SECP256K1_N;
    Signature { r: sig.r.clone(), s: Scalar::new(n - sig.s.value()) }
}

/// Flip the signature on input 0 and return both versions' IDs.
pub fn malleate(raw: &[u8]) -> Result<MalleabilityResult, AppError> {
    let (tx, witnesses) = parse_tx(raw)?;
    if tx.tx_ins.is_empty() {
        return Err(AppError::ParseError("Transaction has no inputs".to_string()));
    }

    match witnesses {
        None => {
            // Legacy P2PKH scriptSig: <sig_len> <der + hashtype> <pubkey_len> <pubkey>
            let script_sig = &tx.tx_ins[0].script_sig;
            let sig_len = *script_sig.first()
                .ok_or_else(|| AppError::ParseError("Input has empty scriptSig".to_string()))? as usize;
            let pk_off = 1 + sig_len;
            if script_sig.len() <= pk_off {
                return Err(AppError::ParseError("scriptSig is not a P2PKH spend".to_string()));
            }
            let pk_len = script_sig[pk_off] as usize;
            if script_sig.len() < pk_off + 1 + pk_len {
                return Err(AppError::ParseError("scriptSig too short for pubkey".to_string()));
            }
            let pubkey = &script_sig[pk_off + 1..pk_off + 1 + pk_len];

            let (orig, hashtype) = split_sig(&script_sig[1..pk_off])?;
            let mall = flip_s(&orig);
            let mut mall_bytes = mall.to_der();
            mall_bytes.push(hashtype);

            let mut mall_tx = tx.clone();
            mall_tx.tx_ins[0].script_sig = build_p2pkh_scriptsig(&mall_bytes, pubkey);

            let orig_txid = txid_from_bytes(raw);
            let mall_txid = txid_from_bytes(&mall_tx.serialize());
            Ok(result(false, &orig, &mall, orig_txid.clone(), mall_txid.clone(), orig_txid, mall_txid))
        }
        Some(mut witnesses) => {
            let stack = &witnesses[0];
            if stack.len() != 2 {
                return Err(AppError::ParseError("Input 0 is not a P2WPKH-style [sig, pubkey] witness".to_string()));
            }
            let (orig, hashtype) = split_sig(&stack[0])?;
            let mall = flip_s(&orig);
            let mut mall_bytes = mall.to_der();
            mall_bytes.push(hashtype);
            witnesses[0][0] = mall_bytes;

            let mall_raw  = serialize_witness_tx(&tx, &witnesses);
            let txid      = txid_from_bytes(&tx.serialize());
            Ok(result(true, &orig, &mall, txid.clone(), txid,
                      txid_from_bytes(raw), txid_from_bytes(&mall_raw)))
        }
    }
}

fn result(
    segwit: bool,
    orig: &Signature,
    mall: &Signature,
    original_txid: String,
    malleable_txid: String,
    original_wtxid: String,
    malleable_wtxid: String,
) -> MalleabilityResult {
    MalleabilityResult {
        segwit,
        txid_changed: original_txid != malleable_txid,
        original_txid,
        malleable_txid,
        original_wtxid,
        malleable_wtxid,
        original_sig_der_hex: hex::encode(orig.to_der()),
        malleable_sig_der_hex: hex::encode(mall.to_der()),
        original_s_hex: hex::encode(orig.s.as_bytes()),
        malleable_s_hex: hex::encode(mall.s.as_bytes()),
        both_valid: true,
        explanation: if segwit {
            "Flipping s → N−s still yields a valid signature and changes the witness, \
             so the WTXID changes. But the TXID is computed without witness data, \
             so it stays the same — SegWit fixed third-party malleability."
        } else {
            "Flipping s → N−s produces a different valid ECDSA signature. \
             The scriptSig bytes change, so Hash256(tx) changes → different TXID. \
             Same coins moved. This is why SegWit moved signatures outside the TXID."
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::p2pkh::build_p2pkh_scriptpubkey;
    use crate::wallet::keygen::generate_wallet;
    use crate::wallet::signing::{
        build_tx, decode_p2pkh_address, sign_and_assemble, sign_and_assemble_segwit, InputSpec,
    };

    fn inputs() -> Vec<InputSpec> {
        vec![InputSpec { txid: "ab".repeat(32), vout: 0, value: 20_000 }]
    }

    #[test]
    fn legacy_flip_changes_txid() {
        let w = generate_wallet();
        let built = build_tx(&inputs(), &w.p2wpkh, 10_000, 500, &w.p2pkh).unwrap();
        let spk = build_p2pkh_scriptpubkey(&decode_p2pkh_address(&w.p2pkh).unwrap());
        let signed = sign_and_assemble(built.tx, &w.wif, &spk).unwrap();

        let r = malleate(&signed.raw).unwrap();
        assert!(!r.segwit);
        assert_eq!(r.original_txid, signed.txid);
        assert!(r.txid_changed);
        assert_ne!(r.original_s_hex, r.malleable_s_hex);
    }

    #[test]
    fn segwit_flip_keeps_txid_but_changes_wtxid() {
        let w = generate_wallet();
        for (addr, kind) in [(&w.p2wpkh, "p2wpkh"), (&w.p2sh_p2wpkh, "p2sh_p2wpkh")] {
            let built = build_tx(&inputs(), &w.p2pkh, 10_000, 500, addr).unwrap();
            let signed = sign_and_assemble_segwit(built.tx, &w.wif, &[20_000], kind).unwrap();

            let r = malleate(&signed.raw).unwrap();
            assert!(r.segwit);
            assert!(!r.txid_changed, "{kind}: txid must not change");
            assert_eq!(r.original_txid, signed.txid);
            assert_eq!(r.original_wtxid, signed.wtxid);
            assert_ne!(r.original_wtxid, r.malleable_wtxid);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(malleate(&[0u8; 3]).is_err());
        assert!(malleate(&[1, 0, 0, 0, 0, 1, 1]).is_err());
    }
}
