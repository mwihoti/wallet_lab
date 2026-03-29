#[cfg(test)]
mod tests {
    use bitcoin_dojo::ecc::util::sha256;
    use bitcoin_dojo::utils::hash256::hash256;

    #[test]
    fn test_hash256_empty_input() {
        let input = b"";
        let result = hash256(input);

        // hash256 of empty string should be sha256(sha256(""))
        // First: sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // Second: sha256 of above
        let expected = [
            0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
            0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
            0x5d, 0x4c, 0x94, 0x56,
        ];

        assert_eq!(result, expected);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash256_known_values() {
        // Test with a known input
        let input = b"hello";
        let result = hash256(input);

        // Should be deterministic
        let result2 = hash256(input);
        assert_eq!(result, result2);

        // Should be 32 bytes
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash256_different_inputs() {
        let input1 = b"Bitcoin";
        let input2 = b"bitcoin"; // Different case

        let hash1 = hash256(input1);
        let hash2 = hash256(input2);

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash256_avalanche_effect() {
        // Small change in input should cause large change in output
        let input1 = b"test message";
        let input2 = b"test messag3"; // Changed last character

        let hash1 = hash256(input1);
        let hash2 = hash256(input2);

        assert_ne!(hash1, hash2);

        // Count different bits (avalanche effect test)
        let mut different_bits = 0;
        for i in 0..32 {
            different_bits += (hash1[i] ^ hash2[i]).count_ones();
        }

        // Good hash function should change about half the bits
        // We expect roughly 128 bits different out of 256 total
        assert!(
            different_bits > 64,
            "Avalanche effect too weak: only {} bits different",
            different_bits
        );
    }

    #[test]
    fn test_hash256_consistency() {
        // Test that multiple calls with the same input produce identical results
        let test_data = b"Bitcoin is digital gold";

        let results: Vec<[u8; 32]> = (0..5).map(|_| hash256(test_data)).collect();

        // All results should be identical
        for result in &results[1..] {
            assert_eq!(&results[0], result);
        }
    }

    #[test]
    fn test_hash256_various_lengths() {
        // Test with inputs of various lengths
        let test_cases = vec![
            vec![],           // empty
            vec![0x00],       // 1 byte
            vec![0x01, 0x02], // 2 bytes
            vec![0; 32],      // 32 bytes (typical hash size)
            vec![0xFF; 65],   // 65 bytes (uncompressed pubkey size)
            vec![0xAA; 1000], // large input
        ];

        for (i, test_case) in test_cases.iter().enumerate() {
            let result = hash256(test_case);
            assert_eq!(result.len(), 32, "Test case {} failed", i);

            // Verify consistency
            let result2 = hash256(test_case);
            assert_eq!(
                result, result2,
                "Consistency check failed for test case {}",
                i
            );
        }
    }

    #[test]
    fn test_hash256_is_double_sha256() {
        // Verify that hash256 is indeed sha256(sha256(data))
        let input = b"test data";

        let hash256_result = hash256(input);

        // Manual double hash
        let first_hash = sha256(input);
        let manual_double_hash = sha256(&first_hash);

        assert_eq!(hash256_result, manual_double_hash);
    }

    #[test]
    fn test_hash256_bitcoin_genesis_block() {
        // Test with Bitcoin genesis block data (simplified)
        let genesis_data = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        let result = hash256(genesis_data);

        // Should be deterministic and 32 bytes
        assert_eq!(result.len(), 32);

        // Should be consistent
        let result2 = hash256(genesis_data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hash256_zero_bytes() {
        // Test with various patterns of zero bytes
        let test_cases = vec![vec![0x00], vec![0x00, 0x00], vec![0x00; 32], vec![0x00; 64]];

        for test_case in test_cases {
            let result = hash256(&test_case);
            assert_eq!(result.len(), 32);

            // Each should produce a different hash
            let different_case = vec![0x00; test_case.len() + 1];
            let different_result = hash256(&different_case);
            assert_ne!(result, different_result);
        }
    }

    #[test]
    fn test_hash256_max_bytes() {
        // Test with bytes containing maximum values
        let max_byte_cases = vec![
            vec![0xFF],
            vec![0xFF, 0xFF],
            vec![0xFF; 32],
            vec![0xFF; 100],
        ];

        for test_case in max_byte_cases {
            let result = hash256(&test_case);
            assert_eq!(result.len(), 32);

            // Should be consistent
            let result2 = hash256(&test_case);
            assert_eq!(result, result2);
        }
    }

    #[test]
    fn test_hash256_incremental_pattern() {
        // Test with incremental byte patterns
        let incremental: Vec<u8> = (0..=255).collect();
        let result = hash256(&incremental);

        assert_eq!(result.len(), 32);

        // Slight modification should produce different result
        let mut modified = incremental.clone();
        modified[0] = 1; // Change first byte from 0 to 1
        let modified_result = hash256(&modified);

        assert_ne!(result, modified_result);
    }
}
