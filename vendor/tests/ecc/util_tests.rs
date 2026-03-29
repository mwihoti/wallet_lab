#[cfg(test)]
mod tests {
    use bitcoin_dojo::ecc::util::{secure_random_bytes, sha256};

    #[test]
    fn test_sha256_empty_input() {
        let input = b"";
        let result = sha256(input);

        // SHA256 of empty string should be a known constant
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];

        assert_eq!(result, expected);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha256_known_input() {
        let input = b"hello world";
        let result = sha256(input);

        // SHA256 of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        assert_eq!(result, expected);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let input = b"test data for deterministic check";
        let result1 = sha256(input);
        let result2 = sha256(input);

        // Same input should always produce same output
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let input1 = b"input1";
        let input2 = b"input2";
        let result1 = sha256(input1);
        let result2 = sha256(input2);

        // Different inputs should produce different outputs
        assert_ne!(result1, result2);
        assert_eq!(result1.len(), 32);
        assert_eq!(result2.len(), 32);
    }

    #[test]
    fn test_sha256_large_input() {
        let input = vec![0x42u8; 1024]; // 1KB of data
        let result = sha256(&input);

        assert_eq!(result.len(), 32);
        // Verify it's not all zeros (which would indicate an error)
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_secure_random_bytes_length() {
        let lengths = [0, 1, 16, 32, 64, 128, 256];

        for &len in &lengths {
            let result = secure_random_bytes(len);
            assert_eq!(result.len(), len);
        }
    }

    #[test]
    fn test_secure_random_bytes_randomness() {
        let size = 32;
        let result1 = secure_random_bytes(size);
        let result2 = secure_random_bytes(size);

        // Two calls should produce different results (with very high probability)
        assert_ne!(result1, result2);
        assert_eq!(result1.len(), size);
        assert_eq!(result2.len(), size);
    }

    #[test]
    fn test_secure_random_bytes_not_all_zeros() {
        let size = 32;
        let result = secure_random_bytes(size);
        let all_zeros = vec![0u8; size];

        // Result should not be all zeros (with very high probability)
        assert_ne!(result, all_zeros);
        assert_eq!(result.len(), size);
    }

    #[test]
    fn test_secure_random_bytes_distribution() {
        let size = 1000;
        let result = secure_random_bytes(size);

        // Basic statistical test: count zeros and ones in the first bit
        let mut zeros = 0;
        let mut ones = 0;

        for &byte in &result {
            if byte & 1 == 0 {
                zeros += 1;
            } else {
                ones += 1;
            }
        }

        // With good randomness, we expect roughly equal distribution
        // Allow for some variance (within 20% of expected)
        let expected = size / 2;
        let tolerance = size / 5; // 20% tolerance

        assert!(
            zeros > expected - tolerance && zeros < expected + tolerance,
            "Zero count {} is outside expected range",
            zeros
        );
        assert!(
            ones > expected - tolerance && ones < expected + tolerance,
            "One count {} is outside expected range",
            ones
        );
    }

    #[test]
    fn test_secure_random_bytes_empty() {
        let result = secure_random_bytes(0);
        assert_eq!(result.len(), 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_secure_random_bytes_large() {
        let size = 10000;
        let result = secure_random_bytes(size);

        assert_eq!(result.len(), size);

        // Verify it's not all the same value
        let first_byte = result[0];
        let all_same = result.iter().all(|&b| b == first_byte);
        assert!(!all_same, "All bytes should not be the same value");
    }

    #[test]
    fn test_integration_sha256_with_random_data() {
        // Test that we can hash random data successfully
        let random_data = secure_random_bytes(64);
        let hash1 = sha256(&random_data);
        let hash2 = sha256(&random_data);

        // Same data should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Different random data should produce different hash
        let random_data2 = secure_random_bytes(64);
        let hash3 = sha256(&random_data2);

        // Very high probability that different random data produces different hash
        if random_data != random_data2 {
            assert_ne!(hash1, hash3);
        }
    }

    #[test]
    fn test_sha256_avalanche_effect() {
        // Small change in input should cause large change in output
        let input1 = b"test message";
        let input2 = b"test messag3"; // Changed last character

        let hash1 = sha256(input1);
        let hash2 = sha256(input2);

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
}
