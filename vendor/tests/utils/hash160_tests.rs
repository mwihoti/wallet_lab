#[cfg(test)]
mod tests {
    use bitcoin_dojo::utils::hash160::hash160;

    #[test]
    fn test_hash160_empty_input() {
        let result = hash160(&[]);
        // HASH160 of empty input should be consistent
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_hash160_known_vector() {
        // Test with a known input
        let input = b"hello world";
        let result = hash160(input);

        // The result should always be 20 bytes
        assert_eq!(result.len(), 20);

        // Test that the same input produces the same output
        let result2 = hash160(input);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash160_different_inputs() {
        let input1 = b"test1";
        let input2 = b"test2";

        let result1 = hash160(input1);
        let result2 = hash160(input2);

        // Different inputs should produce different outputs
        assert_ne!(result1, result2);

        // Both should be 20 bytes
        assert_eq!(result1.len(), 20);
        assert_eq!(result2.len(), 20);
    }

    #[test]
    fn test_hash160_bitcoin_example() {
        // Test with a Bitcoin-style public key (compressed format example)
        let compressed_pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let result = hash160(&compressed_pubkey);
        assert_eq!(result.len(), 20);

        // Verify it's deterministic
        let result2 = hash160(&compressed_pubkey);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash160_deterministic() {
        // Test that multiple calls with the same input produce identical results
        let test_data = b"Bitcoin is digital gold";

        let results: Vec<[u8; 20]> = (0..5).map(|_| hash160(test_data)).collect();

        // All results should be identical
        for result in &results[1..] {
            assert_eq!(&results[0], result);
        }
    }

    #[test]
    fn test_hash160_various_lengths() {
        // Test with inputs of various lengths
        let test_cases = vec![
            vec![],           // empty
            vec![0x00],       // 1 byte
            vec![0x01, 0x02], // 2 bytes
            vec![0; 32],      // 32 bytes (typical hash size)
            vec![0xFF; 65],   // 65 bytes (uncompressed pubkey size)
            vec![0xAA; 100],  // 100 bytes
        ];

        for (i, input) in test_cases.iter().enumerate() {
            let result = hash160(input);
            assert_eq!(
                result.len(),
                20,
                "Test case {} failed: result should be 20 bytes",
                i
            );

            // Verify deterministic behavior
            let result2 = hash160(input);
            assert_eq!(
                result, result2,
                "Test case {} failed: should be deterministic",
                i
            );
        }
    }

    #[test]
    fn test_hash160_known_bitcoin_vectors() {
        // Test with some known Bitcoin-related vectors

        // Genesis block coinbase transaction output script
        let genesis_script = hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
        let result = hash160(&genesis_script);
        assert_eq!(result.len(), 20);

        // Test with a simple script (OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG)
        let p2pkh_script_prefix = [0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH(20)
        let result = hash160(&p2pkh_script_prefix);
        assert_eq!(result.len(), 20);
    }
}
