#[cfg(test)]
mod tests {
    use bitcoin_dojo::ecc::curve::Point;
    use bitcoin_dojo::ecc::keys::{PrivateKey, PublicKey};
    use bitcoin_dojo::ecc::scalar::Scalar;
    use bitcoin_dojo::hash160;
    use bitcoin_dojo::utils::address_types::{AddressType, Network};
    use bitcoin_dojo::utils::base58::encode_base58_check;
    use num_bigint::BigUint;

    #[test]
    fn test_private_key_new() {
        let private_key = PrivateKey::new();

        // Verify that the private key has a scalar
        assert!(private_key.scalar().value() > &BigUint::from(0u32));

        // Verify that multiple calls to new() generate different keys
        let private_key2 = PrivateKey::new();
        assert_ne!(private_key.scalar().value(), private_key2.scalar().value());
    }

    #[test]
    fn test_private_key_default() {
        let private_key1 = PrivateKey::new();
        let private_key2 = PrivateKey::default();

        // Both should create valid private keys (though they'll be different due to randomness)
        assert!(private_key1.scalar().value() > &BigUint::from(0u32));
        assert!(private_key2.scalar().value() > &BigUint::from(0u32));

        // They should be different since they're randomly generated
        assert_ne!(private_key1.scalar().value(), private_key2.scalar().value());
    }

    #[test]
    fn test_private_key_from_scalar() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value.clone());
        let private_key = PrivateKey::from_scalar(scalar);

        assert_eq!(private_key.scalar().value(), &scalar_value);
    }

    #[test]
    fn test_public_key_generation() {
        let private_key = PrivateKey::new();
        let public_key: PublicKey = private_key.public_key();

        // Verify that the public key point is not the point at infinity
        assert!(public_key.point().x().is_some());
        assert!(public_key.point().y().is_some());
    }

    #[test]
    fn test_public_key_deterministic() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let public_key1: PublicKey = private_key.public_key();
        let public_key2: PublicKey = private_key.public_key();

        // Same private key should always generate the same public key
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_different_private_keys_generate_different_public_keys() {
        let scalar1 = Scalar::new(BigUint::from(111u32));
        let scalar2 = Scalar::new(BigUint::from(222u32));

        let private_key1 = PrivateKey::from_scalar(scalar1);
        let private_key2 = PrivateKey::from_scalar(scalar2);

        let public_key1: PublicKey = private_key1.public_key();
        let public_key2: PublicKey = private_key2.public_key();

        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn test_key_pair_consistency() {
        // Test that the public key is correctly derived from private key
        let scalar_value = BigUint::from(999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key: PublicKey = private_key.public_key();

        // Manually compute what the public key should be
        let generator = Point::generator();
        let expected_point = generator.multiply(private_key.scalar());

        // The public key point should match our manual calculation
        assert!(public_key.point().same_point(&expected_point));
    }

    #[test]
    fn test_edge_case_scalar_one() {
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);
        let public_key: PublicKey = private_key.public_key();

        // Public key should be the generator point when private key is 1
        let generator = Point::generator();
        assert!(public_key.point().same_point(&generator));
    }

    #[test]
    fn test_public_key_sec_uncompressed_format() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let sec_bytes = public_key.to_sec(false); // Uncompressed

        // SEC uncompressed format should be 65 bytes
        assert_eq!(sec_bytes.len(), 65);

        // First byte should be 0x04 (uncompressed format marker)
        assert_eq!(sec_bytes[0], 0x04);

        // Remaining 64 bytes should not be all zeros (valid coordinates)
        let coordinates = &sec_bytes[1..];
        assert!(coordinates.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_public_key_sec_compressed_format() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let sec_bytes = public_key.to_sec(true); // Compressed

        // SEC compressed format should be 33 bytes
        assert_eq!(sec_bytes.len(), 33);

        // First byte should be 0x02 or 0x03 (compressed format markers)
        assert!(sec_bytes[0] == 0x02 || sec_bytes[0] == 0x03);

        // Remaining 32 bytes should not be all zeros (valid x coordinate)
        let x_coordinate = &sec_bytes[1..];
        assert!(x_coordinate.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_sec_format_deterministic() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Test uncompressed format
        let sec_bytes1 = public_key.to_sec(false);
        let sec_bytes2 = public_key.to_sec(false);
        assert_eq!(sec_bytes1, sec_bytes2);

        // Test compressed format
        let sec_compressed1 = public_key.to_sec(true);
        let sec_compressed2 = public_key.to_sec(true);
        assert_eq!(sec_compressed1, sec_compressed2);
    }

    #[test]
    fn test_different_public_keys_different_sec() {
        let scalar1 = Scalar::new(BigUint::from(111u32));
        let scalar2 = Scalar::new(BigUint::from(222u32));

        let private_key1 = PrivateKey::from_scalar(scalar1);
        let private_key2 = PrivateKey::from_scalar(scalar2);

        let public_key1 = private_key1.public_key();
        let public_key2 = private_key2.public_key();

        // Test uncompressed format
        let sec_bytes1 = public_key1.to_sec(false);
        let sec_bytes2 = public_key2.to_sec(false);
        assert_ne!(sec_bytes1, sec_bytes2);

        // Test compressed format
        let sec_compressed1 = public_key1.to_sec(true);
        let sec_compressed2 = public_key2.to_sec(true);
        assert_ne!(sec_compressed1, sec_compressed2);
    }

    #[test]
    fn test_sec_uncompressed_format_structure() {
        let scalar_value = BigUint::from(999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let sec_bytes = public_key.to_sec(false); // Uncompressed

        // Verify structure: [0x04][32-byte x][32-byte y]
        assert_eq!(sec_bytes[0], 0x04);

        // Extract x and y coordinates from SEC format
        let x_bytes = &sec_bytes[1..33];
        let y_bytes = &sec_bytes[33..65];

        // Verify we have exactly 32 bytes for each coordinate
        assert_eq!(x_bytes.len(), 32);
        assert_eq!(y_bytes.len(), 32);

        // Verify the coordinates match the point's actual coordinates
        if let (Some(x), Some(y)) = (public_key.point().x(), public_key.point().y()) {
            let expected_x_bytes = x.to_bytes_fixed(32);
            let expected_y_bytes = y.to_bytes_fixed(32);

            assert_eq!(x_bytes, expected_x_bytes.as_slice());
            assert_eq!(y_bytes, expected_y_bytes.as_slice());
        } else {
            panic!("Public key should have valid x and y coordinates");
        }
    }

    #[test]
    fn test_sec_compressed_format_structure() {
        let scalar_value = BigUint::from(999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let sec_bytes = public_key.to_sec(true); // Compressed

        // Verify structure: [0x02/0x03][32-byte x]
        assert!(sec_bytes[0] == 0x02 || sec_bytes[0] == 0x03);

        // Extract x coordinate from SEC format
        let x_bytes = &sec_bytes[1..33];

        // Verify we have exactly 32 bytes for x coordinate
        assert_eq!(x_bytes.len(), 32);

        // Verify the x coordinate matches the point's actual x coordinate
        if let Some(x) = public_key.point().x() {
            let expected_x_bytes = x.to_bytes_fixed(32);
            assert_eq!(x_bytes, expected_x_bytes.as_slice());

            // Verify the prefix matches the y coordinate parity
            if let Some(y) = public_key.point().y() {
                let y_bytes = y.to_bytes_fixed(32);
                let y_is_even = y_bytes[31] & 1 == 0;
                let expected_prefix = if y_is_even { 0x02 } else { 0x03 };
                assert_eq!(sec_bytes[0], expected_prefix);
            }
        } else {
            panic!("Public key should have valid x coordinate");
        }
    }

    #[test]
    fn test_sec_generator_point() {
        // Test SEC format for the generator point (private key = 1)
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);
        let public_key = private_key.public_key();

        // Test uncompressed format
        let sec_uncompressed = public_key.to_sec(false);
        assert_eq!(sec_uncompressed.len(), 65);
        assert_eq!(sec_uncompressed[0], 0x04);

        // Test compressed format
        let sec_compressed = public_key.to_sec(true);
        assert_eq!(sec_compressed.len(), 33);
        assert!(sec_compressed[0] == 0x02 || sec_compressed[0] == 0x03);

        // The generator point should have known coordinates
        let generator = Point::generator();
        if let (Some(gx), Some(gy)) = (generator.x(), generator.y()) {
            let expected_x_bytes = gx.to_bytes_fixed(32);
            let expected_y_bytes = gy.to_bytes_fixed(32);

            // Verify uncompressed format
            assert_eq!(&sec_uncompressed[1..33], expected_x_bytes.as_slice());
            assert_eq!(&sec_uncompressed[33..65], expected_y_bytes.as_slice());

            // Verify compressed format x coordinate
            assert_eq!(&sec_compressed[1..33], expected_x_bytes.as_slice());
        }
    }

    #[test]
    fn test_sec_random_keys() {
        // Test SEC format with randomly generated keys
        for _ in 0..10 {
            let private_key = PrivateKey::new();
            let public_key = private_key.public_key();

            // Test uncompressed format
            let sec_uncompressed = public_key.to_sec(false);
            assert_eq!(sec_uncompressed.len(), 65);
            assert_eq!(sec_uncompressed[0], 0x04);

            let x_bytes = &sec_uncompressed[1..33];
            let y_bytes = &sec_uncompressed[33..65];
            assert!(
                x_bytes.iter().any(|&b| b != 0),
                "X coordinate should not be all zeros"
            );
            assert!(
                y_bytes.iter().any(|&b| b != 0),
                "Y coordinate should not be all zeros"
            );

            // Test compressed format
            let sec_compressed = public_key.to_sec(true);
            assert_eq!(sec_compressed.len(), 33);
            assert!(sec_compressed[0] == 0x02 || sec_compressed[0] == 0x03);

            let x_bytes_compressed = &sec_compressed[1..33];
            assert!(
                x_bytes_compressed.iter().any(|&b| b != 0),
                "X coordinate should not be all zeros"
            );

            // X coordinates should be the same in both formats
            assert_eq!(x_bytes, x_bytes_compressed);
        }
    }

    #[test]
    fn test_sec_coordinate_consistency() {
        // Test that SEC format coordinates are consistent with point coordinates
        let test_values = [1u32, 2, 100, 1000, 12345, 54321, 999999];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            let sec_uncompressed = public_key.to_sec(false);
            let sec_compressed = public_key.to_sec(true);

            // Extract coordinates from SEC formats
            let sec_x_bytes_uncompressed = &sec_uncompressed[1..33];
            let sec_y_bytes = &sec_uncompressed[33..65];
            let sec_x_bytes_compressed = &sec_compressed[1..33];

            // Get coordinates directly from the point
            if let (Some(point_x), Some(point_y)) = (public_key.point().x(), public_key.point().y())
            {
                let point_x_bytes = point_x.to_bytes_fixed(32);
                let point_y_bytes = point_y.to_bytes_fixed(32);

                // Verify uncompressed format coordinates
                assert_eq!(
                    sec_x_bytes_uncompressed,
                    point_x_bytes.as_slice(),
                    "Uncompressed SEC X coordinate should match point X coordinate for value {}",
                    val
                );
                assert_eq!(
                    sec_y_bytes,
                    point_y_bytes.as_slice(),
                    "Uncompressed SEC Y coordinate should match point Y coordinate for value {}",
                    val
                );

                // Verify compressed format x coordinate
                assert_eq!(
                    sec_x_bytes_compressed,
                    point_x_bytes.as_slice(),
                    "Compressed SEC X coordinate should match point X coordinate for value {}",
                    val
                );

                // Verify compressed format prefix matches y coordinate parity
                let y_is_even = point_y_bytes[31] & 1 == 0;
                let expected_prefix = if y_is_even { 0x02 } else { 0x03 };
                assert_eq!(
                    sec_compressed[0], expected_prefix,
                    "Compressed SEC prefix should match Y coordinate parity for value {}",
                    val
                );
            } else {
                panic!("Point should have valid coordinates for value {}", val);
            }
        }
    }

    #[test]
    fn test_sec_compressed_vs_uncompressed_consistency() {
        // Test that compressed and uncompressed formats are consistent
        let test_values = [1u32, 42, 1337, 65537, 1000000];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            let sec_uncompressed = public_key.to_sec(false);
            let sec_compressed = public_key.to_sec(true);

            // X coordinates should be identical
            assert_eq!(
                &sec_uncompressed[1..33],
                &sec_compressed[1..33],
                "X coordinates should match between compressed and uncompressed for value {}",
                val
            );

            // Verify prefix correctness
            let y_bytes = &sec_uncompressed[33..65];
            let y_is_even = y_bytes[31] & 1 == 0;
            let expected_prefix = if y_is_even { 0x02 } else { 0x03 };
            assert_eq!(
                sec_compressed[0], expected_prefix,
                "Compressed prefix should indicate Y coordinate parity for value {}",
                val
            );
        }
    }

    #[test]
    fn test_sec_format_edge_cases() {
        // Test edge cases for SEC format

        // Test with scalar value 2 (known to produce valid point)
        let scalar_two = Scalar::new(BigUint::from(2u32));
        let private_key = PrivateKey::from_scalar(scalar_two);
        let public_key = private_key.public_key();

        let sec_uncompressed = public_key.to_sec(false);
        let sec_compressed = public_key.to_sec(true);

        // Basic validation
        assert_eq!(sec_uncompressed.len(), 65);
        assert_eq!(sec_uncompressed[0], 0x04);
        assert_eq!(sec_compressed.len(), 33);
        assert!(sec_compressed[0] == 0x02 || sec_compressed[0] == 0x03);

        // Ensure both formats represent the same point
        assert_eq!(&sec_uncompressed[1..33], &sec_compressed[1..33]);
    }

    #[test]
    fn test_sec_format_large_scalars() {
        // Test SEC format with larger scalar values
        let large_values = [
            BigUint::from(u32::MAX),
            BigUint::from(u64::MAX),
            BigUint::parse_bytes(b"123456789abcdef", 16).unwrap(),
        ];

        for large_val in &large_values {
            let scalar = Scalar::new(large_val.clone());
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            let sec_uncompressed = public_key.to_sec(false);
            let sec_compressed = public_key.to_sec(true);

            // Basic format validation
            assert_eq!(sec_uncompressed.len(), 65);
            assert_eq!(sec_uncompressed[0], 0x04);
            assert_eq!(sec_compressed.len(), 33);
            assert!(sec_compressed[0] == 0x02 || sec_compressed[0] == 0x03);

            // Consistency check
            assert_eq!(&sec_uncompressed[1..33], &sec_compressed[1..33]);
        }
    }

    #[test]
    fn test_sec_format_y_coordinate_parity() {
        // Test that the compressed format correctly identifies y coordinate parity
        let mut even_count = 0;
        let mut odd_count = 0;

        // Generate multiple keys to test both even and odd y coordinates
        for i in 1u32..=100u32 {
            let scalar = Scalar::new(BigUint::from(i));
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            let sec_uncompressed = public_key.to_sec(false);
            let sec_compressed = public_key.to_sec(true);

            // Check y coordinate parity
            let y_bytes = &sec_uncompressed[33..65];
            let y_is_even = y_bytes[31] & 1 == 0;

            if y_is_even {
                assert_eq!(
                    sec_compressed[0], 0x02,
                    "Even Y should use 0x02 prefix for scalar {}",
                    i
                );
                even_count += 1;
            } else {
                assert_eq!(
                    sec_compressed[0], 0x03,
                    "Odd Y should use 0x03 prefix for scalar {}",
                    i
                );
                odd_count += 1;
            }
        }

        // We should have seen both even and odd y coordinates
        assert!(
            even_count > 0,
            "Should have encountered some even Y coordinates"
        );
        assert!(
            odd_count > 0,
            "Should have encountered some odd Y coordinates"
        );
    }

    #[test]
    fn test_public_key_parse_uncompressed() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let original_public_key = private_key.public_key();

        // Serialize to uncompressed SEC format
        let sec_bytes = original_public_key.to_sec(false);

        // Parse back from SEC format
        let parsed_public_key = PublicKey::parse(&sec_bytes).expect("Should parse successfully");

        // Should be equal to the original
        assert_eq!(original_public_key, parsed_public_key);
    }

    #[test]
    fn test_public_key_parse_compressed() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let original_public_key = private_key.public_key();

        // Serialize to compressed SEC format
        let sec_bytes = original_public_key.to_sec(true);

        // Parse back from SEC format
        let parsed_public_key = PublicKey::parse(&sec_bytes).expect("Should parse successfully");

        // Should be equal to the original
        assert_eq!(original_public_key, parsed_public_key);
    }

    #[test]
    fn test_parse_roundtrip_uncompressed() {
        // Test multiple values to ensure roundtrip consistency
        let test_values = [1u32, 2, 100, 1000, 12345, 54321, 999999];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let original_public_key = private_key.public_key();

            // Serialize and parse back
            let sec_bytes = original_public_key.to_sec(false);
            let parsed_public_key = PublicKey::parse(&sec_bytes)
                .expect(&format!("Should parse uncompressed SEC for value {}", val));

            assert_eq!(
                original_public_key, parsed_public_key,
                "Roundtrip should preserve public key for value {}",
                val
            );
        }
    }

    #[test]
    fn test_parse_roundtrip_compressed() {
        // Test multiple values to ensure roundtrip consistency
        let test_values = [1u32, 2, 100, 1000, 12345, 54321, 999999];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let original_public_key = private_key.public_key();

            // Serialize and parse back
            let sec_bytes = original_public_key.to_sec(true);
            let parsed_public_key = PublicKey::parse(&sec_bytes)
                .expect(&format!("Should parse compressed SEC for value {}", val));

            assert_eq!(
                original_public_key, parsed_public_key,
                "Roundtrip should preserve public key for value {}",
                val
            );
        }
    }

    #[test]
    fn test_parse_compressed_vs_uncompressed_equivalence() {
        // Test that parsing compressed and uncompressed formats of the same key yields the same result
        let test_values = [1u32, 42, 1337, 65537];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let original_public_key = private_key.public_key();

            // Get both formats
            let uncompressed_bytes = original_public_key.to_sec(false);
            let compressed_bytes = original_public_key.to_sec(true);

            // Parse both formats
            let parsed_uncompressed = PublicKey::parse(&uncompressed_bytes)
                .expect(&format!("Should parse uncompressed for value {}", val));
            let parsed_compressed = PublicKey::parse(&compressed_bytes)
                .expect(&format!("Should parse compressed for value {}", val));

            // All should be equal
            assert_eq!(
                original_public_key, parsed_uncompressed,
                "Uncompressed parsing should match original for value {}",
                val
            );
            assert_eq!(
                original_public_key, parsed_compressed,
                "Compressed parsing should match original for value {}",
                val
            );
            assert_eq!(
                parsed_uncompressed, parsed_compressed,
                "Compressed and uncompressed parsing should match for value {}",
                val
            );
        }
    }

    #[test]
    fn test_parse_generator_point() {
        // Test parsing the generator point (private key = 1)
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);
        let generator_public_key = private_key.public_key();

        // Test uncompressed format
        let uncompressed_bytes = generator_public_key.to_sec(false);
        let parsed_uncompressed = PublicKey::parse(&uncompressed_bytes)
            .expect("Should parse generator point uncompressed");
        assert_eq!(generator_public_key, parsed_uncompressed);

        // Test compressed format
        let compressed_bytes = generator_public_key.to_sec(true);
        let parsed_compressed =
            PublicKey::parse(&compressed_bytes).expect("Should parse generator point compressed");
        assert_eq!(generator_public_key, parsed_compressed);
    }

    #[test]
    fn test_parse_random_keys() {
        // Test parsing with randomly generated keys
        for _ in 0..10 {
            let private_key = PrivateKey::new();
            let original_public_key = private_key.public_key();

            // Test uncompressed roundtrip
            let uncompressed_bytes = original_public_key.to_sec(false);
            let parsed_uncompressed = PublicKey::parse(&uncompressed_bytes)
                .expect("Should parse random key uncompressed");
            assert_eq!(original_public_key, parsed_uncompressed);

            // Test compressed roundtrip
            let compressed_bytes = original_public_key.to_sec(true);
            let parsed_compressed =
                PublicKey::parse(&compressed_bytes).expect("Should parse random key compressed");
            assert_eq!(original_public_key, parsed_compressed);
        }
    }

    #[test]
    fn test_parse_invalid_length() {
        // Test with invalid lengths
        let invalid_lengths = [0, 1, 32, 34, 64, 66, 100];

        for &len in &invalid_lengths {
            let invalid_bytes = vec![0u8; len];
            let result = PublicKey::parse(&invalid_bytes);
            assert!(result.is_err(), "Should reject invalid length {}", len);

            if let Err(msg) = result {
                assert!(
                    msg.contains("33 bytes") || msg.contains("65 bytes"),
                    "Error message should mention valid lengths for length {}",
                    len
                );
            }
        }
    }

    #[test]
    fn test_parse_invalid_uncompressed_prefix() {
        // Test uncompressed format with invalid prefix
        let mut invalid_bytes = vec![0u8; 65];

        // Test various invalid prefixes for uncompressed format
        let invalid_prefixes = [0x00, 0x01, 0x02, 0x03, 0x05, 0xFF];

        for &prefix in &invalid_prefixes {
            invalid_bytes[0] = prefix;
            let result = PublicKey::parse(&invalid_bytes);
            assert!(
                result.is_err(),
                "Should reject invalid uncompressed prefix 0x{:02x}",
                prefix
            );

            if let Err(msg) = result {
                assert!(
                    msg.contains("0x04"),
                    "Error message should mention 0x04 for prefix 0x{:02x}",
                    prefix
                );
            }
        }
    }

    #[test]
    fn test_parse_invalid_compressed_prefix() {
        // Test compressed format with invalid prefix
        let mut invalid_bytes = vec![0u8; 33];

        // Test various invalid prefixes for compressed format
        let invalid_prefixes = [0x00, 0x01, 0x04, 0x05, 0xFF];

        for &prefix in &invalid_prefixes {
            invalid_bytes[0] = prefix;
            let result = PublicKey::parse(&invalid_bytes);
            assert!(
                result.is_err(),
                "Should reject invalid compressed prefix 0x{:02x}",
                prefix
            );

            if let Err(msg) = result {
                assert!(
                    msg.contains("0x02") || msg.contains("0x03"),
                    "Error message should mention 0x02 or 0x03 for prefix 0x{:02x}",
                    prefix
                );
            }
        }
    }

    #[test]
    fn test_parse_valid_compressed_prefixes() {
        // Test that both 0x02 and 0x03 prefixes work for compressed format
        let scalar = Scalar::new(BigUint::from(12345u32));
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let compressed_bytes = public_key.to_sec(true);

        // The prefix should be either 0x02 or 0x03
        assert!(compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03);

        // Parsing should work
        let parsed =
            PublicKey::parse(&compressed_bytes).expect("Should parse valid compressed format");
        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_parse_coordinate_validation() {
        // Test that parsing validates coordinates are on the curve
        // This test ensures that Point::new() validation is working in parse methods

        let scalar = Scalar::new(BigUint::from(999u32));
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Valid SEC formats should parse successfully
        let uncompressed_bytes = public_key.to_sec(false);
        let compressed_bytes = public_key.to_sec(true);

        assert!(
            PublicKey::parse(&uncompressed_bytes).is_ok(),
            "Valid uncompressed SEC should parse"
        );
        assert!(
            PublicKey::parse(&compressed_bytes).is_ok(),
            "Valid compressed SEC should parse"
        );
    }

    #[test]
    fn test_parse_large_scalar_values() {
        // Test parsing with larger scalar values
        let large_values = [
            BigUint::from(u32::MAX),
            BigUint::parse_bytes(b"123456789abcdef", 16).unwrap(),
        ];

        for large_val in &large_values {
            let scalar = Scalar::new(large_val.clone());
            let private_key = PrivateKey::from_scalar(scalar);
            let original_public_key = private_key.public_key();

            // Test uncompressed roundtrip
            let uncompressed_bytes = original_public_key.to_sec(false);
            let parsed_uncompressed = PublicKey::parse(&uncompressed_bytes)
                .expect("Should parse large scalar uncompressed");
            assert_eq!(original_public_key, parsed_uncompressed);

            // Test compressed roundtrip
            let compressed_bytes = original_public_key.to_sec(true);
            let parsed_compressed =
                PublicKey::parse(&compressed_bytes).expect("Should parse large scalar compressed");
            assert_eq!(original_public_key, parsed_compressed);
        }
    }

    #[test]
    fn test_parse_y_coordinate_parity_handling() {
        // Test that compressed format correctly handles y-coordinate parity
        let mut even_count = 0;
        let mut odd_count = 0;

        for i in 1u32..=50u32 {
            let scalar = Scalar::new(BigUint::from(i));
            let private_key = PrivateKey::from_scalar(scalar);
            let original_public_key = private_key.public_key();

            let compressed_bytes = original_public_key.to_sec(true);
            let parsed_public_key = PublicKey::parse(&compressed_bytes)
                .expect(&format!("Should parse compressed for scalar {}", i));

            assert_eq!(
                original_public_key, parsed_public_key,
                "Parsed key should match original for scalar {}",
                i
            );

            // Count parity distribution
            if compressed_bytes[0] == 0x02 {
                even_count += 1;
            } else if compressed_bytes[0] == 0x03 {
                odd_count += 1;
            }
        }

        // We should see both even and odd y-coordinates
        assert!(even_count > 0, "Should have some even y-coordinates");
        assert!(odd_count > 0, "Should have some odd y-coordinates");
    }

    #[test]
    fn test_parse_empty_input() {
        let empty_bytes = &[];
        let result = PublicKey::parse(empty_bytes);
        assert!(result.is_err(), "Should reject empty input");
    }

    #[test]
    fn test_parse_error_messages() {
        // Test that error messages are descriptive

        // Invalid length
        let wrong_length = vec![0u8; 50];
        if let Err(msg) = PublicKey::parse(&wrong_length) {
            assert!(
                msg.contains("33") && msg.contains("65"),
                "Error should mention valid lengths"
            );
        } else {
            panic!("Should return error for invalid length");
        }

        // Invalid uncompressed prefix
        let mut invalid_uncompressed = vec![0u8; 65];
        invalid_uncompressed[0] = 0x05;
        if let Err(msg) = PublicKey::parse(&invalid_uncompressed) {
            assert!(
                msg.contains("0x04"),
                "Error should mention correct uncompressed prefix"
            );
        } else {
            panic!("Should return error for invalid uncompressed prefix");
        }

        // Invalid compressed prefix
        let mut invalid_compressed = vec![0u8; 33];
        invalid_compressed[0] = 0x05;
        if let Err(msg) = PublicKey::parse(&invalid_compressed) {
            assert!(
                msg.contains("0x02") || msg.contains("0x03"),
                "Error should mention correct compressed prefixes"
            );
        } else {
            panic!("Should return error for invalid compressed prefix");
        }
    }

    #[test]
    fn test_p2pkh_address_generation() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Test mainnet address
        let mainnet_address = public_key.p2pkh_address(Network::Mainnet);

        // Should be a valid Base58 string
        assert!(!mainnet_address.is_empty());
        assert!(mainnet_address
            .chars()
            .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));

        // Mainnet P2PKH addresses typically start with '1'
        assert!(mainnet_address.starts_with('1'));

        // Should be reasonable length (25-34 characters typically)
        assert!(mainnet_address.len() >= 25 && mainnet_address.len() <= 34);
    }

    #[test]
    fn test_p2pkh_address_testnet() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Test testnet address
        let testnet_address = public_key.p2pkh_address(Network::Testnet);

        // Should be a valid Base58 string
        assert!(!testnet_address.is_empty());

        // Testnet P2PKH addresses typically start with 'm' or 'n'
        assert!(testnet_address.starts_with('m') || testnet_address.starts_with('n'));

        // Should be reasonable length
        assert!(testnet_address.len() >= 25 && testnet_address.len() <= 34);
    }

    #[test]
    fn test_address_method_p2pkh() {
        let scalar_value = BigUint::from(99999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Test that address() method with P2PKH type matches p2pkh_address()
        let address_via_method = public_key.address(AddressType::P2PKH, Network::Mainnet);
        let address_via_p2pkh = public_key.p2pkh_address(Network::Mainnet);

        assert_eq!(address_via_method, address_via_p2pkh);
    }

    #[test]
    fn test_address_deterministic() {
        let scalar_value = BigUint::from(777777u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Same public key should always generate the same address
        let address1 = public_key.p2pkh_address(Network::Mainnet);
        let address2 = public_key.p2pkh_address(Network::Mainnet);

        assert_eq!(address1, address2);

        // Test with address() method as well
        let address3 = public_key.address(AddressType::P2PKH, Network::Mainnet);
        assert_eq!(address1, address3);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let scalar1 = Scalar::new(BigUint::from(111111u32));
        let scalar2 = Scalar::new(BigUint::from(222222u32));

        let private_key1 = PrivateKey::from_scalar(scalar1);
        let private_key2 = PrivateKey::from_scalar(scalar2);

        let public_key1 = private_key1.public_key();
        let public_key2 = private_key2.public_key();

        let address1 = public_key1.p2pkh_address(Network::Mainnet);
        let address2 = public_key2.p2pkh_address(Network::Mainnet);

        assert_ne!(address1, address2);
    }

    #[test]
    fn test_mainnet_vs_testnet_addresses() {
        let scalar_value = BigUint::from(888888u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        let mainnet_address = public_key.p2pkh_address(Network::Mainnet);
        let testnet_address = public_key.p2pkh_address(Network::Testnet);

        // Should be different addresses
        assert_ne!(mainnet_address, testnet_address);

        // Check prefixes
        assert!(mainnet_address.starts_with('1'));
        assert!(testnet_address.starts_with('m') || testnet_address.starts_with('n'));
    }

    #[test]
    fn test_address_generator_point() {
        // Test address generation for the generator point (private key = 1)
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);
        let public_key = private_key.public_key();

        let address = public_key.p2pkh_address(Network::Mainnet);

        // Should be a valid address
        assert!(!address.is_empty());
        assert!(address.starts_with('1'));
        assert!(address.len() >= 25 && address.len() <= 34);
    }

    #[test]
    fn test_address_random_keys() {
        // Test address generation with randomly generated keys
        for _ in 0..10 {
            let private_key = PrivateKey::new();
            let public_key = private_key.public_key();

            let mainnet_address = public_key.p2pkh_address(Network::Mainnet);
            let testnet_address = public_key.p2pkh_address(Network::Testnet);

            // Mainnet addresses
            assert!(!mainnet_address.is_empty());
            assert!(mainnet_address.starts_with('1'));
            assert!(mainnet_address.len() >= 25 && mainnet_address.len() <= 34);

            // Testnet addresses
            assert!(!testnet_address.is_empty());
            assert!(testnet_address.starts_with('m') || testnet_address.starts_with('n'));
            assert!(testnet_address.len() >= 25 && testnet_address.len() <= 34);

            // Should be different
            assert_ne!(mainnet_address, testnet_address);
        }
    }

    #[test]
    fn test_address_uses_compressed_pubkey() {
        // Verify that address generation uses compressed public key format
        let scalar_value = BigUint::from(123456u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key = private_key.public_key();

        // Generate address
        let address = public_key.p2pkh_address(Network::Mainnet);

        // Manually create address using compressed SEC format
        let compressed_sec = public_key.to_sec(true);
        let hash160_result = hash160(&compressed_sec);
        let mut versioned_hash = vec![0x00]; // Mainnet P2PKH version
        versioned_hash.extend_from_slice(&hash160_result);
        let expected_address = encode_base58_check(&versioned_hash);

        assert_eq!(address, expected_address);
    }

    #[test]
    fn test_address_edge_cases() {
        // Test with various scalar values to ensure robustness
        let test_values = [
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(u32::MAX),
            BigUint::parse_bytes(b"123456789abcdef", 16).unwrap(),
        ];

        for (i, val) in test_values.iter().enumerate() {
            let scalar = Scalar::new(val.clone());
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            let mainnet_address = public_key.p2pkh_address(Network::Mainnet);
            let testnet_address = public_key.p2pkh_address(Network::Testnet);

            assert!(
                !mainnet_address.is_empty(),
                "Mainnet address should not be empty for test case {}",
                i
            );
            assert!(
                !testnet_address.is_empty(),
                "Testnet address should not be empty for test case {}",
                i
            );
            assert!(
                mainnet_address.starts_with('1'),
                "Mainnet address should start with '1' for test case {}",
                i
            );
            assert!(
                testnet_address.starts_with('m') || testnet_address.starts_with('n'),
                "Testnet address should start with 'm' or 'n' for test case {}",
                i
            );
        }
    }

    #[test]
    fn test_address_consistency_with_sec_format() {
        // Test that the address generation is consistent with SEC format serialization
        let test_values = [1u32, 42, 1337, 65537];

        for &val in &test_values {
            let scalar = Scalar::new(BigUint::from(val));
            let private_key = PrivateKey::from_scalar(scalar);
            let public_key = private_key.public_key();

            // Generate address using the method
            let address = public_key.p2pkh_address(Network::Mainnet);

            // Generate address manually using SEC format
            let sec_bytes = public_key.to_sec(true); // Should use compressed
            let hash160_result = hash160(&sec_bytes);
            let mut versioned_hash = vec![0x00]; // Mainnet version
            versioned_hash.extend_from_slice(&hash160_result);
            let manual_address = encode_base58_check(&versioned_hash);

            assert_eq!(
                address, manual_address,
                "Address should match manual calculation for value {}",
                val
            );
        }
    }

    #[test]
    fn test_wif_uncompressed_mainnet() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let wif = private_key.to_wif(Network::Mainnet, false);

        // Should be a valid Base58 string
        assert!(!wif.is_empty());
        assert!(wif
            .chars()
            .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));

        // Mainnet uncompressed WIF should start with '5'
        assert!(wif.starts_with('5'));

        // Should be correct length for uncompressed WIF (51 characters typically)
        assert_eq!(wif.len(), 51);
    }

    #[test]
    fn test_wif_compressed_mainnet() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let wif = private_key.to_wif(Network::Mainnet, true);

        // Should be a valid Base58 string
        assert!(!wif.is_empty());
        assert!(wif
            .chars()
            .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)));

        // Mainnet compressed WIF should start with 'K' or 'L'
        assert!(wif.starts_with('K') || wif.starts_with('L'));

        // Should be correct length for compressed WIF (52 characters typically)
        assert_eq!(wif.len(), 52);
    }

    #[test]
    fn test_wif_testnet() {
        let scalar_value = BigUint::from(99999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        // Test uncompressed testnet WIF
        let wif_uncompressed = private_key.to_wif(Network::Testnet, false);
        assert!(wif_uncompressed.starts_with('9'));
        assert_eq!(wif_uncompressed.len(), 51);

        // Test compressed testnet WIF
        let wif_compressed = private_key.to_wif(Network::Testnet, true);
        assert!(wif_compressed.starts_with('c'));
        assert_eq!(wif_compressed.len(), 52);
    }

    #[test]
    fn test_wif_deterministic() {
        let scalar_value = BigUint::from(777777u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        // Same private key should always generate the same WIF
        let wif1 = private_key.to_wif(Network::Mainnet, false);
        let wif2 = private_key.to_wif(Network::Mainnet, false);
        assert_eq!(wif1, wif2);

        // Same for compressed
        let wif_compressed1 = private_key.to_wif(Network::Mainnet, true);
        let wif_compressed2 = private_key.to_wif(Network::Mainnet, true);
        assert_eq!(wif_compressed1, wif_compressed2);
    }

    #[test]
    fn test_wif_different_keys_different_wif() {
        let scalar1 = Scalar::new(BigUint::from(111111u32));
        let scalar2 = Scalar::new(BigUint::from(222222u32));

        let private_key1 = PrivateKey::from_scalar(scalar1);
        let private_key2 = PrivateKey::from_scalar(scalar2);

        let wif1 = private_key1.to_wif(Network::Mainnet, false);
        let wif2 = private_key2.to_wif(Network::Mainnet, false);

        assert_ne!(wif1, wif2);
    }

    #[test]
    fn test_wif_compressed_vs_uncompressed() {
        let scalar_value = BigUint::from(888888u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let wif_uncompressed = private_key.to_wif(Network::Mainnet, false);
        let wif_compressed = private_key.to_wif(Network::Mainnet, true);

        // Should be different
        assert_ne!(wif_uncompressed, wif_compressed);

        // Should have different lengths
        assert_eq!(wif_uncompressed.len(), 51);
        assert_eq!(wif_compressed.len(), 52);

        // Should have different prefixes
        assert!(wif_uncompressed.starts_with('5'));
        assert!(wif_compressed.starts_with('K') || wif_compressed.starts_with('L'));
    }

    #[test]
    fn test_wif_mainnet_vs_testnet() {
        let scalar_value = BigUint::from(333333u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let mainnet_wif = private_key.to_wif(Network::Mainnet, false);
        let testnet_wif = private_key.to_wif(Network::Testnet, false);

        // Should be different
        assert_ne!(mainnet_wif, testnet_wif);

        // Should have different prefixes
        assert!(mainnet_wif.starts_with('5'));
        assert!(testnet_wif.starts_with('9'));
    }

    #[test]
    fn test_wif_known_value() {
        // Test with private key = 1 (generator point)
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);

        let wif_uncompressed = private_key.to_wif(Network::Mainnet, false);
        let wif_compressed = private_key.to_wif(Network::Mainnet, true);

        // Should be valid WIF formats
        assert!(wif_uncompressed.starts_with('5'));
        assert!(wif_compressed.starts_with('K') || wif_compressed.starts_with('L'));

        // Should have correct lengths
        assert_eq!(wif_uncompressed.len(), 51);
        assert_eq!(wif_compressed.len(), 52);
    }

    #[test]
    fn test_wif_random_keys() {
        // Test WIF generation with random keys
        for _ in 0..5 {
            let private_key = PrivateKey::new();

            let wif_mainnet_uncompressed = private_key.to_wif(Network::Mainnet, false);
            let wif_mainnet_compressed = private_key.to_wif(Network::Mainnet, true);
            let wif_testnet_uncompressed = private_key.to_wif(Network::Testnet, false);
            let wif_testnet_compressed = private_key.to_wif(Network::Testnet, true);

            // Verify prefixes
            assert!(wif_mainnet_uncompressed.starts_with('5'));
            assert!(
                wif_mainnet_compressed.starts_with('K') || wif_mainnet_compressed.starts_with('L')
            );
            assert!(wif_testnet_uncompressed.starts_with('9'));
            assert!(wif_testnet_compressed.starts_with('c'));

            // Verify lengths
            assert_eq!(wif_mainnet_uncompressed.len(), 51);
            assert_eq!(wif_mainnet_compressed.len(), 52);
            assert_eq!(wif_testnet_uncompressed.len(), 51);
            assert_eq!(wif_testnet_compressed.len(), 52);
        }
    }
}
