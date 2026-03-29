/// Build a P2PKH scriptPubKey (locking script) from a 20-byte hash160.
///
/// Layout (25 bytes):
///   OP_DUP  OP_HASH160  PUSH_20  <hash160_20_bytes>  OP_EQUALVERIFY  OP_CHECKSIG
///   0x76    0xa9        0x14     <...20 bytes...>     0x88            0xac
pub fn build_p2pkh_scriptpubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push next 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Build a P2PKH scriptSig (unlocking script).
///
/// `der_sig_with_hashtype` must already include the SIGHASH_ALL byte (0x01) at the end.
///
/// Layout:
///   <sig_len>  <der_sig + 0x01>   <pubkey_len>  <compressed_pubkey_33_bytes>
///   Typical total: 107 bytes
pub fn build_p2pkh_scriptsig(der_sig_with_hashtype: &[u8], compressed_pubkey: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + der_sig_with_hashtype.len() + compressed_pubkey.len());
    // push-data for sig (data <= 75 bytes → single length byte)
    script.push(der_sig_with_hashtype.len() as u8);
    script.extend_from_slice(der_sig_with_hashtype);
    // push-data for pubkey
    script.push(compressed_pubkey.len() as u8);
    script.extend_from_slice(compressed_pubkey);
    script
}
