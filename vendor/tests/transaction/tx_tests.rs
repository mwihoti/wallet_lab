use bitcoin_dojo::transaction::{tx::Tx, tx_input::TxInput, tx_output::TxOutput};
use hex::decode;
use std::io::Cursor;

#[test]
fn test_parse_legacy_tx() {
    // Raw legacy transaction (hex string)
    let raw_tx_hex = "010000000110ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5010000008b483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089effffffff0200e9c829010000001976a9146f34d3811aded1df870359f311c2a11a015e945388ac00e40b54020000001976a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac00000000";

    let raw_tx = decode(raw_tx_hex).expect("Invalid hex in raw_tx");
    let mut cursor = Cursor::new(raw_tx);

    let tx = Tx::parse(&mut cursor).expect("Failed to parse transaction");

    // Check the transaction version
    assert_eq!(tx.version, 1);

    // Check the transaction input
    assert_eq!(tx.tx_ins.len(), 1);
    let tx_in = &tx.tx_ins[0];

    let prev_tx_id_hex = "10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5";
    let expected_prev_tx_id = decode(prev_tx_id_hex).expect("Invalid hex for prev_tx_id");
    // expected_prev_tx_id.reverse();

    assert_eq!(tx_in.prev_tx_id, expected_prev_tx_id.as_slice());

    assert_eq!(tx_in.prev_index, 1);

    let script_sig_hex = "483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089e";
    let script_sig = decode(script_sig_hex).expect("Invalid hex for script_sig");
    assert_eq!(tx_in.script_sig, script_sig);

    assert_eq!(tx_in.sequence, 0xffffffff);

    // Check the transaction outputs
    assert_eq!(tx.tx_outs.len(), 2);

    // First output
    let out0 = &tx.tx_outs[0];
    assert_eq!(out0.amount, 4996000000);
    let script_pubkey0_hex = "76a9146f34d3811aded1df870359f311c2a11a015e945388ac";
    let expected_script_pubkey0 =
        decode(script_pubkey0_hex).expect("Invalid hex for script_pubkey0");
    assert_eq!(out0.script_pubkey, expected_script_pubkey0);

    // Second output
    let out1 = &tx.tx_outs[1];
    assert_eq!(out1.amount, 10000000000);
    let script_pubkey1_hex = "76a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac";
    let expected_script_pubkey1 =
        decode(script_pubkey1_hex).expect("Invalid hex for script_pubkey1");
    assert_eq!(out1.script_pubkey, expected_script_pubkey1);

    // Check the locktime
    assert_eq!(tx.locktime, 0);
}

#[test]
fn test_serialize_tx_output() {
    let script_pubkey_hex = "76a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac";
    let script_pubkey = decode(script_pubkey_hex).expect("Invalid hex for script_pubkey");

    let tx_output = TxOutput {
        amount: 10000000000,
        script_pubkey,
    };

    let serialized_tx_output = tx_output.serialize();
    let expected_hex = "00e40b54020000001976a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac";
    assert_eq!(hex::encode(serialized_tx_output), expected_hex);
}

#[test]
fn test_serialize_tx_input() {
    let prev_tx_id_hex = "10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5"; // little endian
    let prev_tx_id_vec = decode(prev_tx_id_hex).expect("Invalid hex for prev_tx_id");
    let prev_tx_id: [u8; 32] = prev_tx_id_vec.try_into().unwrap();

    let script_sig_hex = "483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089e";
    let script_sig = decode(script_sig_hex).expect("Invalid hex for script_sig");

    let tx_input = TxInput {
        prev_tx_id,
        prev_index: 1,
        script_sig,
        sequence: 0xffffffff,
    };

    let serialized_tx_input = tx_input.serialize();
    let expected_hex = "10ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5010000008b483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089effffffff";
    assert_eq!(hex::encode(serialized_tx_input), expected_hex);
}

#[test]
fn test_tx_parse_serialize() {
    // Create test inputs
    let tx_input1 = TxInput {
        prev_tx_id: [1u8; 32],
        prev_index: 0,
        script_sig: vec![0x76, 0xa9, 0x14],
        sequence: 0xffffffff,
    };

    let tx_input2 = TxInput {
        prev_tx_id: [2u8; 32],
        prev_index: 1,
        script_sig: vec![0x76, 0xa9, 0x14, 0x89],
        sequence: 0xfffffffe,
    };

    // Create test outputs
    let tx_output1 = TxOutput {
        amount: 5000000000,
        script_pubkey: vec![0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef],
    };

    let tx_output2 = TxOutput {
        amount: 1000000000,
        script_pubkey: vec![0x76, 0xa9, 0x14],
    };

    // Create a test transaction
    let original_tx = Tx {
        version: 1,
        tx_ins: vec![tx_input1, tx_input2],
        tx_outs: vec![tx_output1, tx_output2],
        locktime: 0,
    };

    // Serialize
    let serialized = original_tx.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx = Tx::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx.version, parsed_tx.version);
    assert_eq!(original_tx.tx_ins.len(), parsed_tx.tx_ins.len());
    assert_eq!(original_tx.tx_outs.len(), parsed_tx.tx_outs.len());
    assert_eq!(original_tx.locktime, parsed_tx.locktime);

    // Verify inputs
    for (orig, parsed) in original_tx.tx_ins.iter().zip(parsed_tx.tx_ins.iter()) {
        assert_eq!(orig.prev_tx_id, parsed.prev_tx_id);
        assert_eq!(orig.prev_index, parsed.prev_index);
        assert_eq!(orig.script_sig, parsed.script_sig);
        assert_eq!(orig.sequence, parsed.sequence);
    }

    // Verify outputs
    for (orig, parsed) in original_tx.tx_outs.iter().zip(parsed_tx.tx_outs.iter()) {
        assert_eq!(orig.amount, parsed.amount);
        assert_eq!(orig.script_pubkey, parsed.script_pubkey);
    }
}

#[test]
fn test_tx_id_le() {
    // Raw legacy transaction (hex string)
    let raw_tx_hex = "010000000110ddd830599b17cc690535f7df28a84466eaca3c22f0d55b79023b6570f4fbc5010000008b483045022100e6186d6f344ce4df46b2e15d87093d34edbf5b50462b6b45f9bd499a6a62fbc4022055f56a1c4a24ea6be61564593c4196b47478a25cf596c1baf59f5a9a229b637c014104a41e997b6656bc4f5dd1f9b9df3b4884cbec254d3b71d928587695b0df0a80417432f4ca6276bc620b1f04308e82e70015a40f597d8260912f801e4b62ab089effffffff0200e9c829010000001976a9146f34d3811aded1df870359f311c2a11a015e945388ac00e40b54020000001976a91470d6734de69c1ac8913892f2df9be0e738d26c2d88ac00000000";

    let raw_tx = decode(raw_tx_hex).expect("Invalid hex in raw_tx");
    let mut cursor = Cursor::new(raw_tx);

    let tx = Tx::parse(&mut cursor).expect("Failed to parse transaction");

    let txid = tx.id();
    let expected_id =
        String::from("cb4c3ba8fb88e101106a68cc6f41fdc466a84b33bf775b17d5d3d0ffba901425"); // little endian
    assert_eq!(txid, expected_id);
}

/*
#[test]
fn test_tx_input_parse_serialize() {
    // Create a test TxInput
    let original_tx_input = TxInput {
        prev_tx_id: [1u8; 32],
        prev_index: 0,
        script_sig: vec![0x76, 0xa9, 0x14], // Simple script
        sequence: 0xffffffff,
    };

    // Serialize
    let serialized = original_tx_input.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx_input = TxInput::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx_input.prev_tx_id, parsed_tx_input.prev_tx_id);
    assert_eq!(original_tx_input.prev_index, parsed_tx_input.prev_index);
    assert_eq!(original_tx_input.script_sig, parsed_tx_input.script_sig);
    assert_eq!(original_tx_input.sequence, parsed_tx_input.sequence);
}

#[test]
fn test_tx_output_parse_serialize() {
    // Create a test TxOutput
    let original_tx_output = TxOutput {
        amount: 5000000000, // 50 BTC in satoshis
        script_pubkey: vec![0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef], // Simple script
    };

    // Serialize
    let serialized = original_tx_output.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx_output = TxOutput::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx_output.amount, parsed_tx_output.amount);
    assert_eq!(original_tx_output.script_pubkey, parsed_tx_output.script_pubkey);
}


#[test]
fn test_empty_tx_parse_serialize() {
    // Create an empty transaction
    let original_tx = Tx {
        version: 2,
        tx_ins: vec![],
        tx_outs: vec![],
        locktime: 500000,
        testnet: false,
        segwit: false,
    };

    // Serialize
    let serialized = original_tx.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx = Tx::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx.version, parsed_tx.version);
    assert_eq!(original_tx.tx_ins.len(), parsed_tx.tx_ins.len());
    assert_eq!(original_tx.tx_outs.len(), parsed_tx.tx_outs.len());
    assert_eq!(original_tx.locktime, parsed_tx.locktime);
}

#[test]
fn test_tx_input_empty_script() {
    // Create a TxInput with empty script
    let original_tx_input = TxInput {
        prev_tx_id: [0u8; 32],
        prev_index: 0,
        script_sig: vec![],
        sequence: 0,
    };

    // Serialize
    let serialized = original_tx_input.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx_input = TxInput::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx_input.prev_tx_id, parsed_tx_input.prev_tx_id);
    assert_eq!(original_tx_input.prev_index, parsed_tx_input.prev_index);
    assert_eq!(original_tx_input.script_sig, parsed_tx_input.script_sig);
    assert_eq!(original_tx_input.sequence, parsed_tx_input.sequence);
}

#[test]
fn test_tx_output_empty_script() {
    // Create a TxOutput with empty script
    let original_tx_output = TxOutput {
        amount: 0,
        script_pubkey: vec![],
    };

    // Serialize
    let serialized = original_tx_output.serialize();

    // Parse back
    let cursor = Cursor::new(&serialized);
    let parsed_tx_output = TxOutput::parse(cursor).unwrap();

    // Verify
    assert_eq!(original_tx_output.amount, parsed_tx_output.amount);
    assert_eq!(original_tx_output.script_pubkey, parsed_tx_output.script_pubkey);
}
*/
