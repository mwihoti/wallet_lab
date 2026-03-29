/// Build a P2SH scriptPubKey.
///
/// Layout (23 bytes):
///   OP_HASH160  PUSH_20  <20-byte script hash>  OP_EQUAL
///   0xa9        0x14     <...20 bytes...>        0x87
pub fn build_p2sh_scriptpubkey(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push next 20 bytes
    script.extend_from_slice(script_hash);
    script.push(0x87); // OP_EQUAL
    script
}
