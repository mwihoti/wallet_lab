use bitcoin_dojo::utils::base58::{
    decode_base58, decode_base58_check, encode_base58, encode_base58_check,
};

#[cfg(test)]
mod tests {
    use super::*;

    // Encoding tests
    #[test]
    fn test_encode_base58_empty_input() {
        let result = encode_base58(&[]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_encode_base58_single_zero() {
        let result = encode_base58(&[0]);
        assert_eq!(result, "1");
    }

    #[test]
    fn test_encode_base58_multiple_leading_zeros() {
        let result = encode_base58(&[0, 0, 0]);
        assert_eq!(result, "111");

        let result = encode_base58(&[0, 0, 0, 0, 0]);
        assert_eq!(result, "11111");
    }

    #[test]
    fn test_encode_base58_leading_zeros_with_data() {
        let result = encode_base58(&[0, 1]);
        assert_eq!(result, "12");

        let result = encode_base58(&[0, 0, 1]);
        assert_eq!(result, "112");

        let result = encode_base58(&[0, 0, 0, 1]);
        assert_eq!(result, "1112");
    }

    #[test]
    fn test_encode_base58_single_bytes() {
        // Test individual byte values
        assert_eq!(encode_base58(&[1]), "2");
        assert_eq!(encode_base58(&[57]), "z");
        assert_eq!(encode_base58(&[58]), "21"); // 58 = 1*58 + 0, so "21"
        assert_eq!(encode_base58(&[255]), "5Q"); // Maximum single byte value
    }

    #[test]
    fn test_encode_base58_known_values() {
        // Test some known Base58 encodings
        let hello_world = b"hello world";
        let result = encode_base58(hello_world);

        // Verify it doesn't contain confusing characters
        assert!(!result.contains('0'));
        assert!(!result.contains('O'));
        assert!(!result.contains('I'));
        assert!(!result.contains('l'));

        // Should be deterministic
        assert_eq!(result, encode_base58(hello_world));
    }

    #[test]
    fn test_encode_base58_bitcoin_like_data() {
        // Test with data similar to Bitcoin hashes (32 bytes)
        let hash_like = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let result = encode_base58(&hash_like);

        // Should start with '1' due to leading zero
        assert!(result.starts_with('1'));

        // Should be a reasonable length for 32 bytes of data
        assert!(result.len() > 30);
        assert!(result.len() < 50);

        // Should only contain valid Base58 characters
        for c in result.chars() {
            assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
        }
    }

    #[test]
    fn test_encode_base58_deterministic() {
        let test_data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];

        let result1 = encode_base58(test_data);
        let result2 = encode_base58(test_data);
        let result3 = encode_base58(test_data);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_encode_base58_different_inputs_different_outputs() {
        let input1 = &[0x01, 0x02, 0x03];
        let input2 = &[0x01, 0x02, 0x04];
        let input3 = &[0x02, 0x02, 0x03];

        let result1 = encode_base58(input1);
        let result2 = encode_base58(input2);
        let result3 = encode_base58(input3);

        assert_ne!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result2, result3);
    }

    #[test]
    fn test_encode_base58_large_numbers() {
        // Test with larger byte arrays
        let large_data = vec![0xff; 64]; // 64 bytes of 0xff
        let result = encode_base58(&large_data);

        // Should be non-empty and contain only valid characters
        assert!(!result.is_empty());
        for c in result.chars() {
            assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
        }
    }

    #[test]
    fn test_encode_base58_mixed_leading_zeros() {
        // Test various patterns of leading zeros
        let test_cases = vec![
            (vec![0x00], "1"),
            (vec![0x00, 0x00], "11"),
            (vec![0x00, 0x01], "12"),
            (vec![0x00, 0x00, 0x01], "112"),
            (vec![0x00, 0x00, 0x00, 0x01], "1112"),
            (vec![0x00, 0x39], "1z"), // 0x39 = 57, which encodes to 'z'
        ];

        for (input, expected) in test_cases {
            let result = encode_base58(&input);
            assert_eq!(result, expected, "Failed for input: {:?}", input);
        }
    }

    #[test]
    fn test_encode_base58_alphabet_coverage() {
        // Test that our encoding can produce various characters from the alphabet
        let mut found_chars = std::collections::HashSet::new();

        // Test a range of inputs to see what characters we get
        for i in 0u8..=255u8 {
            let result = encode_base58(&[i]);
            for c in result.chars() {
                found_chars.insert(c);
            }
        }

        // Should have found several different characters
        assert!(
            found_chars.len() > 10,
            "Should produce diverse character set"
        );

        // Should not contain forbidden characters
        assert!(!found_chars.contains(&'0'));
        assert!(!found_chars.contains(&'O'));
        assert!(!found_chars.contains(&'I'));
        assert!(!found_chars.contains(&'l'));
    }

    #[test]
    fn test_encode_base58_incremental_values() {
        // Test that incrementing input produces different outputs
        let base = vec![0x01, 0x02, 0x03, 0x04];
        let mut results = std::collections::HashSet::new();

        for i in 0u8..10u8 {
            let mut input = base.clone();
            input.push(i);
            let result = encode_base58(&input);

            // Each result should be unique
            assert!(
                results.insert(result.clone()),
                "Duplicate result for input ending with {}: {}",
                i,
                result
            );
        }
    }

    #[test]
    fn test_encode_base58_edge_case_values() {
        // Test specific edge case values
        let test_cases = vec![
            vec![0x01],             // Minimum non-zero
            vec![0xff],             // Maximum single byte
            vec![0x01, 0x00],       // 256
            vec![0xff, 0xff],       // 65535
            vec![0x01, 0x00, 0x00], // 65536
        ];

        for input in test_cases {
            let result = encode_base58(&input);

            // Should produce valid output
            assert!(!result.is_empty(), "Empty result for input: {:?}", input);

            // Should be deterministic
            assert_eq!(result, encode_base58(&input));

            // Should contain only valid characters
            for c in result.chars() {
                assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
            }
        }
    }

    #[test]
    fn test_encode_base58_bitcoin_address_like() {
        // Test with data that looks like a Bitcoin address payload
        // Typical Bitcoin address: version byte + 20-byte hash + 4-byte checksum
        let version = 0x00; // P2PKH version
        let hash160 = [
            0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
            0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
        ]; // 20 bytes
        let checksum = [0x12, 0x34, 0x56, 0x78]; // 4 bytes

        let mut address_payload = vec![version];
        address_payload.extend_from_slice(&hash160);
        address_payload.extend_from_slice(&checksum);

        let result = encode_base58(&address_payload);

        // Bitcoin addresses typically start with '1' for P2PKH (version 0x00)
        assert!(result.starts_with('1'));

        // Should be reasonable length for a Bitcoin address
        assert!(result.len() >= 25);
        assert!(result.len() <= 35);
    }

    // Decoding tests
    #[test]
    fn test_decode_base58_empty_input() {
        let result = decode_base58("").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_decode_base58_single_one() {
        let result = decode_base58("1").unwrap();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn test_decode_base58_multiple_ones() {
        let result = decode_base58("111").unwrap();
        assert_eq!(result, vec![0, 0, 0]);

        let result = decode_base58("11111").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_decode_base58_leading_ones_with_data() {
        let result = decode_base58("12").unwrap();
        assert_eq!(result, vec![0, 1]);

        let result = decode_base58("112").unwrap();
        assert_eq!(result, vec![0, 0, 1]);

        let result = decode_base58("1112").unwrap();
        assert_eq!(result, vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_decode_base58_single_characters() {
        // Test individual character decoding
        assert_eq!(decode_base58("2").unwrap(), vec![1]);
        assert_eq!(decode_base58("z").unwrap(), vec![57]);
        assert_eq!(decode_base58("21").unwrap(), vec![58]);
        assert_eq!(decode_base58("5Q").unwrap(), vec![255]);
    }

    #[test]
    fn test_decode_base58_invalid_characters() {
        // Test characters not in Base58 alphabet
        assert!(decode_base58("0").is_err()); // Contains '0'
        assert!(decode_base58("O").is_err()); // Contains 'O'
        assert!(decode_base58("I").is_err()); // Contains 'I'
        assert!(decode_base58("l").is_err()); // Contains 'l'
        assert!(decode_base58("@").is_err()); // Contains '@'
        assert!(decode_base58("#").is_err()); // Contains '#'
        assert!(decode_base58("$").is_err()); // Contains '$'
        assert!(decode_base58("%").is_err()); // Contains '%'
    }

    #[test]
    fn test_decode_base58_mixed_invalid_characters() {
        // Test valid strings with invalid characters mixed in
        assert!(decode_base58("12O34").is_err()); // Contains 'O'
        assert!(decode_base58("1I234").is_err()); // Contains 'I'
        assert!(decode_base58("123l4").is_err()); // Contains 'l'
        assert!(decode_base58("1230").is_err()); // Contains '0'
    }

    #[test]
    fn test_decode_base58_non_ascii() {
        // Test non-ASCII characters
        assert!(decode_base58("ñ").is_err()); // Spanish ñ
        assert!(decode_base58("café").is_err()); // Contains é
        assert!(decode_base58("1ñ23").is_err()); // Mixed ASCII and non-ASCII
        assert!(decode_base58("🚀").is_err()); // Emoji
    }

    #[test]
    fn test_decode_base58_all_valid_characters() {
        // Test that all valid Base58 characters can be decoded individually
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        for c in alphabet.chars() {
            let s = c.to_string();
            let result = decode_base58(&s);
            assert!(result.is_ok(), "Failed to decode valid character: {}", c);
            assert!(
                !result.unwrap().is_empty(),
                "Decoded character should not be empty: {}",
                c
            );
        }
    }

    #[test]
    fn test_decode_base58_deterministic() {
        let test_input = "StV1DL6CwTryKyV";

        let result1 = decode_base58(test_input).unwrap();
        let result2 = decode_base58(test_input).unwrap();
        let result3 = decode_base58(test_input).unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_decode_base58_different_inputs_different_outputs() {
        let input1 = "StV1DL6CwTryKyV";
        let input2 = "StV1DL6CwTryKyW";
        let input3 = "TtV1DL6CwTryKyV";

        let result1 = decode_base58(input1).unwrap();
        let result2 = decode_base58(input2).unwrap();
        let result3 = decode_base58(input3).unwrap();

        assert_ne!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result2, result3);
    }

    #[test]
    fn test_decode_base58_case_sensitivity() {
        // Base58 is case sensitive
        let lower = "abc";
        let upper = "ABC";
        let mixed = "AbC";

        let result_lower = decode_base58(lower).unwrap();
        let result_upper = decode_base58(upper).unwrap();
        let result_mixed = decode_base58(mixed).unwrap();

        assert_ne!(result_lower, result_upper);
        assert_ne!(result_lower, result_mixed);
        assert_ne!(result_upper, result_mixed);
    }

    #[test]
    fn test_decode_base58_large_strings() {
        // Test with longer Base58 strings
        let long_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let result = decode_base58(long_string);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_base58_bitcoin_address_like() {
        // Test decoding strings that look like Bitcoin addresses
        let address_like = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Similar to first Bitcoin address
        let result = decode_base58(address_like);
        assert!(result.is_ok());

        let decoded = result.unwrap();
        // Should start with 0x00 (version byte for P2PKH)
        assert_eq!(decoded[0], 0x00);
        // Should be 25 bytes total (1 version + 20 hash + 4 checksum)
        assert_eq!(decoded.len(), 25);
    }

    // Base58Check encoding tests
    #[test]
    fn test_encode_base58_check_empty_input() {
        let result = encode_base58_check(&[]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_encode_base58_check_single_byte() {
        let result = encode_base58_check(&[0x01]);

        // Should be longer than regular Base58 due to 4-byte checksum
        let regular_result = encode_base58(&[0x01]);
        assert!(result.len() > regular_result.len());

        // Should not contain forbidden characters
        assert!(!result.contains('0'));
        assert!(!result.contains('O'));
        assert!(!result.contains('I'));
        assert!(!result.contains('l'));
    }

    #[test]
    fn test_encode_base58_check_multiple_bytes() {
        let input = &[0x01, 0x02, 0x03, 0x04, 0x05];
        let result = encode_base58_check(input);

        // Should be significantly longer due to checksum
        let regular_result = encode_base58(input);
        assert!(result.len() > regular_result.len());

        // Should only contain valid Base58 characters
        for c in result.chars() {
            assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
        }
    }

    #[test]
    fn test_encode_base58_check_deterministic() {
        let input = &[0x12, 0x34, 0x56, 0x78];
        let result1 = encode_base58_check(input);
        let result2 = encode_base58_check(input);
        let result3 = encode_base58_check(input);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_encode_base58_check_different_inputs() {
        let input1 = &[0x01, 0x02, 0x03];
        let input2 = &[0x01, 0x02, 0x04];
        let input3 = &[0x02, 0x02, 0x03];

        let result1 = encode_base58_check(input1);
        let result2 = encode_base58_check(input2);
        let result3 = encode_base58_check(input3);

        assert_ne!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result2, result3);
    }

    #[test]
    fn test_encode_base58_check_with_leading_zeros() {
        let test_cases = vec![
            vec![0x00],
            vec![0x00, 0x00],
            vec![0x00, 0x01],
            vec![0x00, 0x00, 0x01],
            vec![0x00, 0x12, 0x34, 0x56],
        ];

        for input in test_cases {
            let result = encode_base58_check(&input);

            // Should handle leading zeros correctly
            if input[0] == 0x00 {
                assert!(
                    result.starts_with('1'),
                    "Should start with '1' for leading zero in input: {:?}",
                    input
                );
            }

            // Should be deterministic
            assert_eq!(result, encode_base58_check(&input));
        }
    }

    #[test]
    fn test_encode_base58_check_bitcoin_address_format() {
        // Test with Bitcoin P2PKH address format (version + hash160)
        let version = 0x00; // P2PKH version byte
        let hash160 = [
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]; // 20-byte hash

        let mut payload = vec![version];
        payload.extend_from_slice(&hash160);

        let result = encode_base58_check(&payload);

        // Should start with '1' for P2PKH addresses
        assert!(result.starts_with('1'));

        // Should be typical Bitcoin address length
        assert!(result.len() >= 26);
        assert!(result.len() <= 35);

        // Should only contain valid Base58 characters
        for c in result.chars() {
            assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
        }
    }

    #[test]
    fn test_encode_base58_check_bitcoin_p2sh_format() {
        // Test with Bitcoin P2SH address format
        let version = 0x05; // P2SH version byte
        let hash160 = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        ]; // 20-byte hash

        let mut payload = vec![version];
        payload.extend_from_slice(&hash160);

        let result = encode_base58_check(&payload);

        // P2SH addresses typically start with '3'
        assert!(result.starts_with('3'));

        // Should be typical Bitcoin address length
        assert!(result.len() >= 26);
        assert!(result.len() <= 35);
    }

    #[test]
    fn test_encode_base58_check_private_key_format() {
        // Test with Bitcoin private key format (WIF)
        let version = 0x80; // Mainnet private key version
        let private_key = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ]; // 32-byte private key

        let mut payload = vec![version];
        payload.extend_from_slice(&private_key);

        let result = encode_base58_check(&payload);

        // WIF private keys typically start with '5', 'K', or 'L'
        let first_char = result.chars().next().unwrap();
        assert!(first_char == '5' || first_char == 'K' || first_char == 'L');

        // Should be typical WIF length
        assert!(result.len() >= 51);
        assert!(result.len() <= 52);
    }

    #[test]
    fn test_encode_base58_check_large_data() {
        // Test with larger data sets
        let large_data = (0..100).collect::<Vec<u8>>();
        let result = encode_base58_check(&large_data);

        // Should be significantly longer than input due to checksum
        assert!(result.len() > 100);

        // Should only contain valid characters
        for c in result.chars() {
            assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
        }

        // Should be deterministic
        assert_eq!(result, encode_base58_check(&large_data));
    }

    #[test]
    fn test_encode_base58_check_edge_cases() {
        let edge_cases = vec![
            vec![0x01],                   // Single byte
            vec![0xff],                   // Maximum single byte
            vec![0x00, 0x01],             // Leading zero
            vec![0xff, 0xff, 0xff, 0xff], // All high bits
            vec![0x00, 0x00, 0x00, 0x01], // Multiple leading zeros
        ];

        for input in edge_cases {
            let result = encode_base58_check(&input);

            // Should produce valid output
            assert!(!result.is_empty(), "Empty result for input: {:?}", input);

            // Should be deterministic
            assert_eq!(result, encode_base58_check(&input));

            // Should only contain valid characters
            for c in result.chars() {
                assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
            }
        }
    }

    #[test]
    fn test_encode_base58_check_checksum_sensitivity() {
        // Test that small changes in input produce different checksums
        let base_input = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let base_result = encode_base58_check(&base_input);

        // Change each byte and verify result is different
        for i in 0..base_input.len() {
            let mut modified_input = base_input.clone();
            modified_input[i] = modified_input[i].wrapping_add(1);

            let modified_result = encode_base58_check(&modified_input);
            assert_ne!(
                base_result, modified_result,
                "Results should differ when byte {} changes from {:02x} to {:02x}",
                i, base_input[i], modified_input[i]
            );
        }
    }

    #[test]
    fn test_encode_base58_check_vs_regular_base58() {
        let test_cases = vec![
            vec![0x01],
            vec![0x12, 0x34],
            vec![0x00, 0x01, 0x02],
            vec![0xff, 0xfe, 0xfd, 0xfc],
        ];

        for input in test_cases {
            let regular_result = encode_base58(&input);
            let check_result = encode_base58_check(&input);

            // Base58Check should be longer due to checksum
            assert!(
                check_result.len() > regular_result.len(),
                "Base58Check should be longer for input: {:?}",
                input
            );

            // Both should contain only valid characters
            for c in regular_result.chars() {
                assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
            }
            for c in check_result.chars() {
                assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c));
            }
        }
    }

    #[test]
    fn test_encode_base58_check_incremental_data() {
        // Test with incrementally different data
        let mut results = std::collections::HashSet::new();

        for i in 0u8..20u8 {
            let input = vec![0x01, 0x02, 0x03, i];
            let result = encode_base58_check(&input);

            // Each result should be unique
            assert!(
                results.insert(result.clone()),
                "Duplicate result for input ending with {}: {}",
                i,
                result
            );
        }
    }

    #[test]
    fn test_encode_base58_check_bitcoin_testnet_formats() {
        // Test Bitcoin testnet address formats
        let testnet_p2pkh_version = 0x6f; // Testnet P2PKH
        let testnet_p2sh_version = 0xc4; // Testnet P2SH

        let hash160 = [
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]; // 20-byte hash

        // Test testnet P2PKH
        let mut testnet_p2pkh = vec![testnet_p2pkh_version];
        testnet_p2pkh.extend_from_slice(&hash160);
        let testnet_p2pkh_result = encode_base58_check(&testnet_p2pkh);

        // Testnet P2PKH addresses typically start with 'm' or 'n'
        let first_char = testnet_p2pkh_result.chars().next().unwrap();
        assert!(first_char == 'm' || first_char == 'n');

        // Test testnet P2SH
        let mut testnet_p2sh = vec![testnet_p2sh_version];
        testnet_p2sh.extend_from_slice(&hash160);
        let testnet_p2sh_result = encode_base58_check(&testnet_p2sh);

        // Testnet P2SH addresses typically start with '2'
        assert!(testnet_p2sh_result.starts_with('2'));

        // Both should be different from each other and from mainnet
        assert_ne!(testnet_p2pkh_result, testnet_p2sh_result);
    }

    #[test]
    fn test_encode_base58_check_performance_large_input() {
        // Test with reasonably large input to ensure performance is acceptable
        let large_input = vec![0x42; 1000]; // 1KB of data
        let result = encode_base58_check(&large_input);

        // Should successfully encode large input
        assert!(!result.is_empty());
        assert!(result.len() > 1000); // Should be longer due to encoding overhead

        // Should be deterministic even for large inputs
        assert_eq!(result, encode_base58_check(&large_input));
    }

    // Round-trip tests (encode then decode)
    #[test]
    fn test_encode_decode_roundtrip_basic() {
        let test_cases = vec![
            vec![],
            vec![0],
            vec![0, 0, 0],
            vec![1],
            vec![255],
            vec![0, 1],
            vec![0, 0, 1],
            vec![1, 2, 3, 4, 5],
            vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        ];

        for original in test_cases {
            let encoded = encode_base58(&original);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(original, decoded, "Round-trip failed for: {:?}", original);
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_leading_zeros() {
        let test_cases = vec![
            vec![0x00],
            vec![0x00, 0x00],
            vec![0x00, 0x00, 0x00],
            vec![0x00, 0x01],
            vec![0x00, 0x00, 0x01],
            vec![0x00, 0x00, 0x00, 0x01],
            vec![0x00, 0x39], // 0x39 = 57
            vec![0x00, 0x00, 0xff, 0xff],
        ];

        for original in test_cases {
            let encoded = encode_base58(&original);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(
                original, decoded,
                "Leading zero round-trip failed for: {:?}",
                original
            );
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_large_data() {
        // Test with larger data sets
        let test_cases = vec![
            vec![0xff; 32],                           // 32 bytes of 0xff
            vec![0x00; 10],                           // 10 bytes of zeros
            (0..=255).collect(),                      // Sequential bytes 0-255
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05], // Mixed with leading zero
            (0..100).collect::<Vec<u8>>(),            // 0-99
        ];

        for original in test_cases {
            let encoded = encode_base58(&original);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(
                original,
                decoded,
                "Large data round-trip failed for length: {}",
                original.len()
            );
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_random_patterns() {
        // Test with various bit patterns
        let test_patterns = vec![
            vec![0b10101010; 16],                                 // Alternating bits
            vec![0b11110000; 16],                                 // High nibble set
            vec![0b00001111; 16],                                 // Low nibble set
            vec![0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01], // Powers of 2
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], // Hex sequence
        ];

        for pattern in test_patterns {
            let encoded = encode_base58(&pattern);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(
                pattern, decoded,
                "Pattern round-trip failed for: {:02x?}",
                pattern
            );
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_edge_cases() {
        // Test edge cases
        let edge_cases = vec![
            vec![0x01],                   // Minimum non-zero
            vec![0xff],                   // Maximum single byte
            vec![0x01, 0x00],             // 256
            vec![0xff, 0xff],             // 65535
            vec![0x01, 0x00, 0x00],       // 65536
            vec![0x00, 0xff, 0xff],       // Leading zero with max values
            vec![0xff, 0xff, 0xff, 0xff], // 32-bit max
        ];

        for edge_case in edge_cases {
            let encoded = encode_base58(&edge_case);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(
                edge_case, decoded,
                "Edge case round-trip failed for: {:02x?}",
                edge_case
            );
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_bitcoin_like_data() {
        // Test with Bitcoin-like data structures
        let bitcoin_like_cases = vec![
            // P2PKH address payload (version + hash160 + checksum)
            {
                let mut payload = vec![0x00]; // P2PKH version
                payload.extend_from_slice(&[
                    0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
                    0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
                ]); // 20-byte hash
                payload.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // 4-byte checksum
                payload
            },
            // P2SH address payload
            {
                let mut payload = vec![0x05]; // P2SH version
                payload.extend_from_slice(&[
                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
                ]); // 20-byte hash
                payload.extend_from_slice(&[0xab, 0xcd, 0xef, 0x01]); // 4-byte checksum
                payload
            },
            // 32-byte hash (like transaction ID)
            vec![
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
        ];

        for bitcoin_data in bitcoin_like_cases {
            let encoded = encode_base58(&bitcoin_data);
            let decoded = decode_base58(&encoded).unwrap();
            assert_eq!(bitcoin_data, decoded, "Bitcoin-like data round-trip failed");
        }
    }

    #[test]
    fn test_decode_base58_preserves_leading_zeros() {
        // Specifically test that leading zeros are preserved correctly
        let test_cases = vec![
            ("1", vec![0x00]),
            ("11", vec![0x00, 0x00]),
            ("111", vec![0x00, 0x00, 0x00]),
            ("1111", vec![0x00, 0x00, 0x00, 0x00]),
            ("12", vec![0x00, 0x01]),
            ("112", vec![0x00, 0x00, 0x01]),
            ("1112", vec![0x00, 0x00, 0x00, 0x01]),
        ];

        for (input, expected) in test_cases {
            let result = decode_base58(input).unwrap();
            assert_eq!(
                result, expected,
                "Leading zero preservation failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_decode_base58_error_messages() {
        // Test that error messages are appropriate
        let invalid_cases = vec![
            ("0", "Invalid character: not in Base58 alphabet"),
            ("O", "Invalid character: not in Base58 alphabet"),
            ("I", "Invalid character: not in Base58 alphabet"),
            ("l", "Invalid character: not in Base58 alphabet"),
        ];

        for (input, expected_error) in invalid_cases {
            let result = decode_base58(input);
            assert!(result.is_err(), "Should have failed for input: {}", input);
            assert_eq!(
                result.unwrap_err(),
                expected_error,
                "Wrong error message for input: {}",
                input
            );
        }
    }

    #[test]
    fn test_decode_base58_comprehensive_alphabet() {
        // Test decoding every character in the Base58 alphabet
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        for (i, c) in alphabet.chars().enumerate() {
            let s = c.to_string();
            let result = decode_base58(&s).unwrap();

            // Single character should decode to single byte with value equal to index
            assert_eq!(
                result.len(),
                1,
                "Character '{}' should decode to single byte",
                c
            );
            assert_eq!(
                result[0] as usize, i,
                "Character '{}' should decode to value {}",
                c, i
            );
        }
    }

    #[test]
    fn test_decode_base58_empty_vs_zero() {
        // Test distinction between empty input and zero input
        let empty_result = decode_base58("").unwrap();
        let zero_result = decode_base58("1").unwrap();

        assert_eq!(empty_result, Vec::<u8>::new());
        assert_eq!(zero_result, vec![0x00]);
        assert_ne!(empty_result, zero_result);
    }

    #[test]
    fn test_decode_base58_performance_large_input() {
        // Test with a reasonably large input to ensure performance is acceptable
        let large_input = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".repeat(10);
        let result = decode_base58(&large_input);

        assert!(result.is_ok(), "Should successfully decode large input");
        assert!(
            !result.unwrap().is_empty(),
            "Large input should produce non-empty output"
        );
    }

    #[test]
    fn test_base58_check_avalanche_effect() {
        // Test that small changes in input produce large changes in output (avalanche effect)
        let base_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let base_encoded = encode_base58_check(&base_data);

        // Change each byte by 1 and verify the output changes significantly
        for i in 0..base_data.len() {
            let mut modified_data = base_data.clone();
            modified_data[i] = modified_data[i].wrapping_add(1);

            let modified_encoded = encode_base58_check(&modified_data);

            // Should be different
            assert_ne!(
                base_encoded, modified_encoded,
                "Output should change when byte {} changes",
                i
            );

            // Count different characters (should be significant)
            let base_chars: Vec<char> = base_encoded.chars().collect();
            let modified_chars: Vec<char> = modified_encoded.chars().collect();

            let min_len = base_chars.len().min(modified_chars.len());
            let different_chars = base_chars
                .iter()
                .zip(modified_chars.iter())
                .take(min_len)
                .filter(|(a, b)| a != b)
                .count();

            // Should have multiple character differences due to checksum change
            assert!(
                different_chars > 0,
                "Should have character differences when byte {} changes",
                i
            );
        }
    }

    // Base58Check decoding tests
    #[test]
    fn test_decode_base58_check_empty_input() {
        let result = decode_base58_check("").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_decode_base58_check_too_short() {
        // Test with data shorter than 4 bytes (minimum for checksum)
        let short_data = encode_base58(&[0x01, 0x02]); // Only 2 bytes
        let result = decode_base58_check(&short_data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Base58Check data too short: must be at least 4 bytes"
        );
    }

    #[test]
    fn test_decode_base58_check_invalid_checksum() {
        // Create valid Base58Check data, then corrupt it
        let original = &[0x01, 0x02, 0x03, 0x04, 0x05];
        let valid_encoded = encode_base58_check(original);

        // Corrupt the last character (part of checksum)
        let mut corrupted = valid_encoded.chars().collect::<Vec<_>>();
        let last_char = corrupted.last_mut().unwrap();
        *last_char = if *last_char == '2' { '3' } else { '2' };
        let corrupted_string: String = corrupted.into_iter().collect();

        let result = decode_base58_check(&corrupted_string);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Base58Check checksum verification failed"
        );
    }

    #[test]
    fn test_decode_base58_check_invalid_base58() {
        // Test with invalid Base58 characters
        let invalid_inputs = vec![
            "123456789O", // Contains 'O'
            "123456789I", // Contains 'I'
            "123456789l", // Contains 'l'
            "1234567890", // Contains '0'
        ];

        for invalid_input in invalid_inputs {
            let result = decode_base58_check(invalid_input);
            assert!(
                result.is_err(),
                "Should fail for invalid input: {}",
                invalid_input
            );
        }
    }

    #[test]
    fn test_decode_base58_check_valid_data() {
        // Test decoding valid Base58Check data
        let test_cases = vec![
            vec![0x01],
            vec![0x00, 0x01],
            vec![0x12, 0x34, 0x56],
            vec![0xff, 0xfe, 0xfd, 0xfc, 0xfb],
            vec![0x00, 0x00, 0x01, 0x02, 0x03],
        ];

        for original in test_cases {
            let encoded = encode_base58_check(&original);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(original, decoded, "Decode failed for: {:?}", original);
        }
    }

    #[test]
    fn test_decode_base58_check_bitcoin_addresses() {
        // Test decoding Bitcoin-like addresses
        let address_cases = vec![
            // P2PKH mainnet
            {
                let mut addr = vec![0x00]; // P2PKH version
                addr.extend_from_slice(&[
                    0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
                    0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                ]); // 20-byte hash
                addr
            },
            // P2SH mainnet
            {
                let mut addr = vec![0x05]; // P2SH version
                addr.extend_from_slice(&[
                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
                ]); // 20-byte hash
                addr
            },
        ];

        for bitcoin_addr in address_cases {
            let encoded = encode_base58_check(&bitcoin_addr);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(bitcoin_addr, decoded, "Bitcoin address decode failed");

            // Verify structure
            assert_eq!(decoded.len(), 21); // 1 version + 20 hash
            assert!(decoded[0] == 0x00 || decoded[0] == 0x05); // Valid version bytes
        }
    }

    #[test]
    fn test_decode_base58_check_private_keys() {
        // Test decoding Bitcoin private key formats (WIF)
        let private_key_cases = vec![
            // Mainnet uncompressed private key
            {
                let mut wif = vec![0x80]; // Mainnet private key version
                wif.extend_from_slice(&[
                    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
                    0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
                    0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                ]); // 32-byte private key
                wif
            },
            // Mainnet compressed private key
            {
                let mut wif = vec![0x80]; // Mainnet private key version
                wif.extend_from_slice(&[
                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                ]); // 32-byte private key
                wif.push(0x01); // Compressed flag
                wif
            },
        ];

        for private_key in private_key_cases {
            let encoded = encode_base58_check(&private_key);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(private_key, decoded, "Private key decode failed");

            // Verify structure
            assert_eq!(decoded[0], 0x80); // Mainnet private key version
            assert!(decoded.len() == 33 || decoded.len() == 34); // 33 uncompressed, 34 compressed
        }
    }

    #[test]
    fn test_decode_base58_check_corruption_detection() {
        // Test that various types of corruption are detected
        let original_data = vec![
            0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
            0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
        ];
        let valid_encoded = encode_base58_check(&original_data);

        // Test single character corruption at different positions
        for pos in 0..valid_encoded.len() {
            let mut corrupted_chars: Vec<char> = valid_encoded.chars().collect();
            let original_char = corrupted_chars[pos];

            // Find a different valid Base58 character
            let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            let replacement_char = alphabet.chars().find(|&c| c != original_char).unwrap();

            corrupted_chars[pos] = replacement_char;
            let corrupted_string: String = corrupted_chars.into_iter().collect();

            let result = decode_base58_check(&corrupted_string);
            assert!(
                result.is_err(),
                "Should detect corruption at position {} (changed '{}' to '{}')",
                pos,
                original_char,
                replacement_char
            );
        }
    }

    #[test]
    fn test_decode_base58_check_multiple_corruptions() {
        // Test detection of multiple character corruptions
        let original_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let valid_encoded = encode_base58_check(&original_data);

        if valid_encoded.len() >= 4 {
            let mut corrupted_chars: Vec<char> = valid_encoded.chars().collect();

            // Corrupt first and last characters
            corrupted_chars[0] = '2';
            let last_index = corrupted_chars.len() - 1;
            corrupted_chars[last_index] = '3';

            let corrupted_string: String = corrupted_chars.into_iter().collect();
            let result = decode_base58_check(&corrupted_string);
            assert!(result.is_err(), "Should detect multiple corruptions");
        }
    }

    #[test]
    fn test_decode_base58_check_deterministic() {
        // Test that decoding is deterministic
        let test_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let encoded = encode_base58_check(&test_data);

        let decoded1 = decode_base58_check(&encoded).unwrap();
        let decoded2 = decode_base58_check(&encoded).unwrap();
        let decoded3 = decode_base58_check(&encoded).unwrap();

        assert_eq!(decoded1, decoded2);
        assert_eq!(decoded2, decoded3);
        assert_eq!(decoded1, test_data);
    }

    #[test]
    fn test_decode_base58_check_edge_cases() {
        // Test edge cases for decoding
        let edge_cases = vec![
            vec![0x01],                   // Single byte
            vec![0xff],                   // Maximum single byte
            vec![0x00, 0x01],             // Leading zero
            vec![0x00, 0x00, 0x01],       // Multiple leading zeros
            vec![0xff, 0xff, 0xff, 0xff], // All high bits
            vec![0x80, 0x00, 0x00, 0x00], // High bit set
        ];

        for edge_case in edge_cases {
            let encoded = encode_base58_check(&edge_case);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(
                edge_case, decoded,
                "Edge case decode failed for: {:02x?}",
                edge_case
            );
        }
    }

    #[test]
    fn test_decode_base58_check_large_data() {
        // Test with larger data sets
        let large_cases = vec![
            vec![0x42; 100],               // 100 bytes of same value
            (0..200).collect::<Vec<u8>>(), // Sequential bytes 0-199
            vec![0x00; 50],                // 50 zero bytes
            vec![0xff; 75],                // 75 bytes of 0xff
        ];

        for large_data in large_cases {
            let encoded = encode_base58_check(&large_data);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(
                large_data,
                decoded,
                "Large data decode failed for length: {}",
                large_data.len()
            );
        }
    }

    #[test]
    fn test_decode_base58_check_vs_regular_base58_security() {
        // Demonstrate that Base58Check provides error detection that regular Base58 doesn't
        let original_data = vec![
            0x00, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ];

        let regular_encoded = encode_base58(&original_data);
        let check_encoded = encode_base58_check(&original_data);

        // Corrupt both encodings in the same way
        let mut regular_corrupted: Vec<char> = regular_encoded.chars().collect();
        let mut check_corrupted: Vec<char> = check_encoded.chars().collect();

        if regular_corrupted.len() > 0 && check_corrupted.len() > 0 {
            // Change the last character of both
            let last_index = regular_corrupted.len() - 1;
            regular_corrupted[last_index] = '2';
            let last_index = check_corrupted.len() - 1;
            check_corrupted[last_index] = '2';

            let regular_corrupted_string: String = regular_corrupted.into_iter().collect();
            let check_corrupted_string: String = check_corrupted.into_iter().collect();

            // Regular Base58 will decode corrupted data without error
            let regular_result = decode_base58(&regular_corrupted_string);
            assert!(
                regular_result.is_ok(),
                "Regular Base58 should decode corrupted data"
            );

            // Base58Check should detect the corruption
            let check_result = decode_base58_check(&check_corrupted_string);
            assert!(
                check_result.is_err(),
                "Base58Check should detect corruption"
            );
        }
    }

    #[test]
    fn test_decode_base58_check_checksum_boundary() {
        // Test that corruption right at the data/checksum boundary is detected
        let original_data = vec![0x12, 0x34, 0x56, 0x78];
        let encoded = encode_base58_check(&original_data);

        // Decode to get the full data with checksum
        let full_data = decode_base58(&encoded).unwrap();
        assert_eq!(full_data.len(), 8); // 4 bytes data + 4 bytes checksum

        // Corrupt the last byte of data (should affect checksum verification)
        let mut corrupted_full = full_data.clone();
        corrupted_full[3] = corrupted_full[3].wrapping_add(1); // Change last byte of original data
        let corrupted_encoded = encode_base58(&corrupted_full);

        let result = decode_base58_check(&corrupted_encoded);
        assert!(result.is_err(), "Should detect corruption in data portion");

        // Corrupt the first byte of checksum
        let mut corrupted_checksum = full_data.clone();
        corrupted_checksum[4] = corrupted_checksum[4].wrapping_add(1); // Change first byte of checksum
        let corrupted_checksum_encoded = encode_base58(&corrupted_checksum);

        let result2 = decode_base58_check(&corrupted_checksum_encoded);
        assert!(
            result2.is_err(),
            "Should detect corruption in checksum portion"
        );
    }

    #[test]
    fn test_decode_base58_check_minimum_valid_length() {
        // Test with exactly 4 bytes (minimum valid length)
        let min_data = vec![0x12, 0x34, 0x56, 0x78];
        let encoded = encode_base58_check(&min_data);
        let decoded = decode_base58_check(&encoded).unwrap();
        assert_eq!(min_data, decoded);

        // The encoded version should decode to 8 bytes total (4 data + 4 checksum)
        let full_decoded = decode_base58(&encoded).unwrap();
        assert_eq!(full_decoded.len(), 8);
    }

    #[test]
    fn test_decode_base58_check_error_propagation() {
        // Test that Base58 decoding errors are properly propagated
        let invalid_base58_inputs = vec![
            "0123456789", // Contains '0'
            "O123456789", // Contains 'O'
            "I123456789", // Contains 'I'
            "l123456789", // Contains 'l'
        ];

        for invalid_input in invalid_base58_inputs {
            let result = decode_base58_check(invalid_input);
            assert!(
                result.is_err(),
                "Should propagate Base58 decode error for: {}",
                invalid_input
            );
            // The error should be from Base58 decoding, not checksum verification
            let error_msg = result.unwrap_err();
            assert!(
                error_msg.contains("Invalid character"),
                "Should be Base58 decode error, got: {}",
                error_msg
            );
        }
    }

    #[test]
    fn test_decode_base58_check_leading_zeros_preservation() {
        // Test that leading zeros are preserved through Base58Check round-trip
        let test_cases = vec![
            vec![0x00],
            vec![0x00, 0x00],
            vec![0x00, 0x01],
            vec![0x00, 0x00, 0x01],
            vec![0x00, 0x12, 0x34, 0x56],
        ];

        for original in test_cases {
            let encoded = encode_base58_check(&original);
            let decoded = decode_base58_check(&encoded).unwrap();
            assert_eq!(
                original, decoded,
                "Leading zeros not preserved for: {:?}",
                original
            );

            // Verify the encoded version starts with '1' for leading zeros
            if original[0] == 0x00 {
                assert!(
                    encoded.starts_with('1'),
                    "Should start with '1' for leading zero"
                );
            }
        }
    }

    #[test]
    fn test_decode_base58_check_performance_large_input() {
        // Test decoding performance with large input
        let large_data = vec![0x42; 1000]; // 1KB of data
        let encoded = encode_base58_check(&large_data);
        let decoded = decode_base58_check(&encoded).unwrap();

        assert_eq!(large_data, decoded);
        assert_eq!(decoded.len(), 1000);
    }

    #[test]
    fn test_decode_base58_check_all_zero_data() {
        // Test with data that's all zeros (edge case for checksum calculation)
        let zero_data = vec![0x00; 20];
        let encoded = encode_base58_check(&zero_data);
        let decoded = decode_base58_check(&encoded).unwrap();
        assert_eq!(zero_data, decoded);

        // Should start with many '1's due to leading zeros
        let ones_count = encoded.chars().take_while(|&c| c == '1').count();
        assert!(
            ones_count >= 20,
            "Should have at least 20 leading '1's for 20 zero bytes"
        );
    }

    #[test]
    fn test_decode_base58_check_all_max_data() {
        // Test with data that's all 0xFF (edge case for checksum calculation)
        let max_data = vec![0xff; 20];
        let encoded = encode_base58_check(&max_data);
        let decoded = decode_base58_check(&encoded).unwrap();
        assert_eq!(max_data, decoded);

        // Should not start with '1' since no leading zeros
        assert!(!encoded.starts_with('1'));
    }

    #[test]
    fn test_decode_base58_check_single_bit_errors() {
        // Test detection of single bit flip errors
        let original_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let encoded = encode_base58_check(&original_data);
        let full_decoded = decode_base58(&encoded).unwrap();

        // Test flipping each bit in the data portion
        for byte_idx in 0..original_data.len() {
            for bit_idx in 0..8 {
                let mut corrupted = full_decoded.clone();
                corrupted[byte_idx] ^= 1 << bit_idx; // Flip one bit

                let corrupted_encoded = encode_base58(&corrupted);
                let result = decode_base58_check(&corrupted_encoded);

                assert!(
                    result.is_err(),
                    "Should detect single bit flip at byte {} bit {}",
                    byte_idx,
                    bit_idx
                );
            }
        }
    }

    #[test]
    fn test_decode_base58_check_checksum_collision_resistance() {
        // Test that different inputs produce different checksums
        let base_data = vec![0x12, 0x34, 0x56, 0x78];
        let base_encoded = encode_base58_check(&base_data);

        // Try many variations and ensure they all produce different encoded results
        let mut encoded_results = std::collections::HashSet::new();
        encoded_results.insert(base_encoded.clone());

        for i in 0..base_data.len() {
            for delta in 1u8..=10u8 {
                let mut modified_data = base_data.clone();
                modified_data[i] = modified_data[i].wrapping_add(delta);

                let modified_encoded = encode_base58_check(&modified_data);
                assert!(
                    encoded_results.insert(modified_encoded.clone()),
                    "Checksum collision detected for byte {} delta {}",
                    i,
                    delta
                );

                // Verify the modified version decodes correctly
                let decoded = decode_base58_check(&modified_encoded).unwrap();
                assert_eq!(decoded, modified_data);
            }
        }
    }

    #[test]
    fn test_decode_base58_check_empty_vs_minimal() {
        // Test distinction between empty input and minimal valid input
        let empty_result = decode_base58_check("").unwrap();
        assert_eq!(empty_result, Vec::<u8>::new());

        let minimal_data = vec![0x01];
        let minimal_encoded = encode_base58_check(&minimal_data);
        let minimal_decoded = decode_base58_check(&minimal_encoded).unwrap();
        assert_eq!(minimal_decoded, minimal_data);

        assert_ne!(empty_result, minimal_decoded);
    }
}
