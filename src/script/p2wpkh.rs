/// Build a P2WPKH scriptPubKey (native SegWit output locking script).
///
/// Layout (22 bytes):
///   OP_0  PUSH_20  <20-byte pubkey hash>
///   0x00  0x14     <...20 bytes...>
pub fn build_p2wpkh_scriptpubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0 (witness version)
    script.push(0x14); // push next 20 bytes
    script.extend_from_slice(pubkey_hash);
    script
}
