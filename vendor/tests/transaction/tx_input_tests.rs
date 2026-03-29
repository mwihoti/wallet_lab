#[cfg(test)]
use std::io::Cursor;
use bitcoin_dojo::transaction::tx_input::TxInput;

#[test]
fn test_txinput_parse() {
    // Complete transaction input hex string including txid, prev_index, script_sig and sequence
    let test_vector = "10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5010000008b483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089effffffff";
    
    let bytes = hex::decode(test_vector).expect("Invalid hex");
    
    let mut cursor = Cursor::new(&bytes);
    let tx_input = TxInput::parse(&mut cursor).expect("Failed to parse TxInput");
    
    // Verify the parsed values
    let expected_prev_tx_id = hex::decode("10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5").unwrap();
    let mut expected_prev_tx_id_array = [0u8; 32];
    expected_prev_tx_id_array.copy_from_slice(&expected_prev_tx_id);
    
    assert_eq!(tx_input.prev_tx_id, expected_prev_tx_id_array);
    assert_eq!(tx_input.prev_index, 0x00000001); // 01000000 in little-endian = 1
    assert_eq!(tx_input.script_sig.len(), 139); // 0x8b = 139 bytes for script_sig
    // The actual script signature from the test vector should be preserved
    assert_eq!(tx_input.script_sig[0], 0x48); // Script sig starts with length byte 0x48
    assert_eq!(tx_input.script_sig[1], 0x30); // DER signature starts with 0x30
    assert_eq!(tx_input.sequence, 0xffffffff);
}
