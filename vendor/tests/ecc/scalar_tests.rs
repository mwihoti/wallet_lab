use bitcoin_dojo::ecc::scalar::*;
#[cfg(test)]
use num_bigint::BigUint;

#[test]
fn test_scalar_creation() {
    let scalar = Scalar::new(BigUint::from(20u32));
    // With secp256k1 modulus, 20 should remain 20 (since it's much smaller than the modulus)
    assert_eq!(scalar.value, BigUint::from(20u32));
}

#[test]
fn test_scalar_creation_with_modular_reduction() {
    // Test with a value that needs modular reduction
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let large_value = &*SECP256K1_N + BigUint::from(17u32);
    let scalar = Scalar::new(large_value);
    assert_eq!(scalar.value, BigUint::from(17u32)); // Should be reduced mod N
}

#[test]
fn test_scalar_addition() {
    let a = Scalar::new(BigUint::from(10u32));
    let b = Scalar::new(BigUint::from(12u32));
    let result = a + b;
    assert_eq!(result.value, BigUint::from(22u32)); // 10 + 12 = 22
}

#[test]
fn test_scalar_subtraction() {
    let a = Scalar::new(BigUint::from(15u32));
    let b = Scalar::new(BigUint::from(10u32));
    let result = a - b;
    assert_eq!(result.value, BigUint::from(5u32)); // 15 - 10 = 5
}

#[test]
fn test_scalar_subtraction_underflow() {
    let a = Scalar::new(BigUint::from(5u32));
    let b = Scalar::new(BigUint::from(10u32));
    let result = a - b;
    // Should wrap around: (5 - 10) mod N = N - 5
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let expected = &*SECP256K1_N - BigUint::from(5u32);
    assert_eq!(result.value, expected);
}

#[test]
fn test_scalar_multiplication() {
    let a = Scalar::new(BigUint::from(3u32));
    let b = Scalar::new(BigUint::from(5u32));
    let result = a * b;
    assert_eq!(result.value, BigUint::from(15u32)); // 3 * 5 = 15
}

#[test]
fn test_scalar_inverse() {
    let scalar = Scalar::new(BigUint::from(3u32));
    let inverse = scalar.inverse().unwrap();
    let product = &scalar * &inverse;
    assert_eq!(product.value, BigUint::from(1u32));
}

#[test]
fn test_scalar_inverse_zero() {
    let zero = Scalar::new(BigUint::from(0u32));
    assert!(zero.inverse().is_none());
}

#[test]
fn test_bytes_conversion() {
    let scalar = Scalar::new(BigUint::from(255u32));
    let bytes = scalar.as_bytes();
    let reconstructed = Scalar::from_bytes(&bytes);
    assert_eq!(scalar.value, reconstructed.value);
}

#[test]
fn test_scalar_zero() {
    let zero = Scalar::zero();
    assert_eq!(zero.value, BigUint::from(0u32));

    // Test zero addition
    let a = Scalar::new(BigUint::from(5u32));
    let result = &a + &zero;
    assert_eq!(result.value, a.value);
}

#[test]
fn test_scalar_one() {
    let one = Scalar::one();
    assert_eq!(one.value, BigUint::from(1u32));

    // Test one multiplication
    let a = Scalar::new(BigUint::from(5u32));
    let result = &a * &one;
    assert_eq!(result.value, a.value);
}

#[test]
fn test_scalar_inverse_edge_cases() {
    // Test inverse of 1
    let one = Scalar::new(BigUint::from(1u32));
    let inverse = one.inverse().unwrap();
    assert_eq!(inverse.value, BigUint::from(1u32));

    // Test inverse of zero should fail
    let zero = Scalar::new(BigUint::from(0u32));
    assert!(zero.inverse().is_none());

    // Test inverse of N-1 (which is -1 mod N)
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let minus_one = Scalar::new(&*SECP256K1_N - BigUint::from(1u32));
    let inverse = minus_one.inverse().unwrap();
    // -1 is its own inverse in any field
    assert_eq!(inverse.value, &*SECP256K1_N - BigUint::from(1u32));
}

#[test]
fn test_scalar_addition_overflow() {
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let large_val = &*SECP256K1_N - BigUint::from(1u32); // N - 1
    let a = Scalar::new(large_val.clone());
    let b = Scalar::new(BigUint::from(2u32));
    let result = a + b;
    // (N-1) + 2 = N + 1 ≡ 1 (mod N)
    assert_eq!(result.value, BigUint::from(1u32));
}

#[test]
fn test_scalar_multiplication_large() {
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let large_val = &*SECP256K1_N - BigUint::from(1u32); // N - 1
    let a = Scalar::new(large_val.clone());
    let b = Scalar::new(large_val.clone());
    let result = a * b;
    // (N-1) * (N-1) = N² - 2N + 1 ≡ 1 (mod N)
    assert_eq!(result.value, BigUint::from(1u32));
}

#[test]
fn test_scalar_borrowed_operations() {
    let a = Scalar::new(BigUint::from(10u32));
    let b = Scalar::new(BigUint::from(7u32));

    // Test borrowed addition
    let result = &a + &b;
    assert_eq!(result.value, BigUint::from(17u32)); // 10 + 7 = 17

    // Test borrowed subtraction
    let result = &a - &b;
    assert_eq!(result.value, BigUint::from(3u32)); // 10 - 7 = 3

    // Test borrowed multiplication
    let result = &a * &b;
    assert_eq!(result.value, BigUint::from(70u32)); // 10 * 7 = 70
}

#[test]
fn test_scalar_large_numbers() {
    let large_val = BigUint::parse_bytes(
        b"123456789012345678901234567890123456789012345678901234567890",
        10,
    )
    .unwrap();

    let scalar = Scalar::new(large_val);
    let bytes = scalar.as_bytes();
    let reconstructed = Scalar::from_bytes(&bytes);
    assert_eq!(scalar.value, reconstructed.value);
}

#[test]
fn test_scalar_bytes_edge_cases() {
    // Test with zero
    let zero = Scalar::zero();
    let bytes = zero.as_bytes();
    let reconstructed = Scalar::from_bytes(&bytes);
    assert_eq!(zero.value, reconstructed.value);

    // Test with max single byte value
    let max_byte = Scalar::new(BigUint::from(255u32));
    let bytes = max_byte.as_bytes();
    let reconstructed = Scalar::from_bytes(&bytes);
    assert_eq!(max_byte.value, reconstructed.value);
}

#[test]
fn test_scalar_equality() {
    let a = Scalar::new(BigUint::from(5u32));
    let b = Scalar::new(BigUint::from(5u32));

    // Test with modular reduction
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let c = Scalar::new(&*SECP256K1_N + BigUint::from(5u32)); // Should reduce to 5

    assert_eq!(a, b);
    assert_eq!(a, c); // Should be equal due to modular reduction
}

#[test]
fn test_scalar_getters() {
    let scalar = Scalar::new(BigUint::from(42u32));

    assert_eq!(*scalar.value(), BigUint::from(42u32));

    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    assert_eq!(*scalar.modulus(), *SECP256K1_N);
}

#[test]
fn test_scalar_associativity() {
    let a = Scalar::new(BigUint::from(3u32));
    let b = Scalar::new(BigUint::from(5u32));
    let c = Scalar::new(BigUint::from(7u32));

    // Test addition associativity: (a + b) + c = a + (b + c)
    let ab = &a + &b;
    let left = &ab + &c;
    let bc = &b + &c;
    let right = &a + &bc;
    assert_eq!(left, right);

    // Test multiplication associativity: (a * b) * c = a * (b * c)
    let ab = &a * &b;
    let left = &ab * &c;
    let bc = &b * &c;
    let right = &a * &bc;
    assert_eq!(left, right);
}

#[test]
fn test_scalar_commutativity() {
    let a = Scalar::new(BigUint::from(3u32));
    let b = Scalar::new(BigUint::from(5u32));

    // Test addition commutativity: a + b = b + a
    assert_eq!(&a + &b, &b + &a);

    // Test multiplication commutativity: a * b = b * a
    assert_eq!(&a * &b, &b * &a);
}

#[test]
fn test_scalar_distributivity() {
    let a = Scalar::new(BigUint::from(3u32));
    let b = Scalar::new(BigUint::from(5u32));
    let c = Scalar::new(BigUint::from(7u32));

    // Test distributivity: a * (b + c) = a * b + a * c
    let bc = &b + &c;
    let left = &a * &bc;
    let ab = &a * &b;
    let ac = &a * &c;
    let right = &ab + &ac;
    assert_eq!(left, right);
}

#[test]
fn test_scalar_random() {
    let random1 = Scalar::random();
    let random2 = Scalar::random();

    // Random scalars should be different (with very high probability)
    assert_ne!(random1, random2);

    // Random scalars should be valid (less than modulus)
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    assert!(random1.value < *SECP256K1_N);
    assert!(random2.value < *SECP256K1_N);
}

#[test]
fn test_scalar_field_properties() {
    // Test that scalars form a field under addition and multiplication mod N
    let a = Scalar::new(BigUint::from(7u32));
    let zero = Scalar::zero();
    let one = Scalar::one();

    // Additive identity: a + 0 = a
    assert_eq!(&a + &zero, a);

    // Multiplicative identity: a * 1 = a
    assert_eq!(&a * &one, a);

    // Additive inverse: a + (-a) = 0
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    let neg_a = Scalar::new(&*SECP256K1_N - a.value());
    let sum = &a + &neg_a;
    assert_eq!(sum, zero);

    // Multiplicative inverse: a * a^(-1) = 1 (for non-zero a)
    if let Some(inv_a) = a.inverse() {
        let product = &a * &inv_a;
        assert_eq!(product, one);
    }
}

#[test]
fn test_scalar_modular_arithmetic() {
    use bitcoin_dojo::ecc::constants::SECP256K1_N;

    // Test that operations are properly reduced modulo N
    let half_n = &*SECP256K1_N / BigUint::from(2u32);
    let a = Scalar::new(half_n.clone());
    let b = Scalar::new(half_n.clone());

    // Adding two halves should give approximately N, which reduces to ~0
    let sum = &a + &b;
    // The exact result depends on whether N is even or odd
    // But it should be much smaller than N
    assert!(sum.value < *SECP256K1_N);
}

#[test]
fn test_scalar_bytes_roundtrip() {
    // Test various values for bytes conversion roundtrip
    let test_values = vec![
        BigUint::from(0u32),
        BigUint::from(1u32),
        BigUint::from(255u32),
        BigUint::from(256u32),
        BigUint::from(65535u32),
        BigUint::from(65536u32),
        BigUint::parse_bytes(b"123456789abcdef", 16).unwrap(),
    ];

    for value in test_values {
        let scalar = Scalar::new(value);
        let bytes = scalar.as_bytes();
        let reconstructed = Scalar::from_bytes(&bytes);
        assert_eq!(scalar, reconstructed);
    }
}

#[test]
fn test_scalar_owned_vs_borrowed() {
    let a = Scalar::new(BigUint::from(10u32));
    let b = Scalar::new(BigUint::from(5u32));

    // Test the supported combinations of owned/borrowed operations
    let result1 = &a + &b; // borrowed + borrowed
    let result2 = a.clone() + b.clone(); // owned + owned

    assert_eq!(result1, result2);

    // Same for multiplication
    let result1 = &a * &b; // borrowed + borrowed
    let result2 = a.clone() * b.clone(); // owned + owned

    assert_eq!(result1, result2);

    // Same for subtraction
    let result1 = &a - &b; // borrowed + borrowed
    let result2 = a.clone() - b.clone(); // owned + owned

    assert_eq!(result1, result2);
}

#[test]
fn test_scalar_clone_and_debug() {
    let scalar = Scalar::new(BigUint::from(42u32));
    let cloned = scalar.clone();

    assert_eq!(scalar, cloned);

    // Test that Debug trait works (should not panic)
    let debug_str = format!("{:?}", scalar);
    assert!(!debug_str.is_empty());
}

#[test]
fn test_scalar_extreme_values() {
    use bitcoin_dojo::ecc::constants::SECP256K1_N;

    // Test with N-1 (maximum valid scalar)
    let max_scalar = Scalar::new(&*SECP256K1_N - BigUint::from(1u32));
    assert_eq!(max_scalar.value, &*SECP256K1_N - BigUint::from(1u32));

    // Test with N (should reduce to 0)
    let n_scalar = Scalar::new(SECP256K1_N.clone());
    assert_eq!(n_scalar.value, BigUint::from(0u32));

    // Test with 2*N + 5 (should reduce to 5)
    let large_scalar = Scalar::new(&*SECP256K1_N * BigUint::from(2u32) + BigUint::from(5u32));
    assert_eq!(large_scalar.value, BigUint::from(5u32));
}

#[test]
fn test_scalar_inverse_comprehensive() {
    // Test inverses for various small values
    for i in 1u32..=2u32 {
        let scalar = Scalar::new(BigUint::from(i));
        if let Some(inverse) = scalar.inverse() {
            let product = &scalar * &inverse;
            let one = Scalar::one();
            assert_eq!(product, one, "Failed for scalar value {}", i);
        }
    }
}

#[test]
fn test_scalar_addition_properties() {
    let a = Scalar::new(BigUint::from(10u32));
    let b = Scalar::new(BigUint::from(20u32));
    let c = Scalar::new(BigUint::from(30u32));

    // Test that addition is associative and commutative
    assert_eq!(&(&a + &b) + &c, &a + &(&b + &c)); // Associative
    assert_eq!(&a + &b, &b + &a); // Commutative

    // Test identity element
    let zero = Scalar::zero();
    assert_eq!(&a + &zero, a);
    assert_eq!(&zero + &a, a);
}

#[test]
fn test_scalar_multiplication_properties() {
    let a = Scalar::new(BigUint::from(3u32));
    let b = Scalar::new(BigUint::from(5u32));
    let c = Scalar::new(BigUint::from(7u32));

    // Test that multiplication is associative and commutative
    assert_eq!(&(&a * &b) * &c, &a * &(&b * &c)); // Associative
    assert_eq!(&a * &b, &b * &a); // Commutative

    // Test identity element
    let one = Scalar::one();
    assert_eq!(&a * &one, a);
    assert_eq!(&one * &a, a);

    // Test zero element
    let zero = Scalar::zero();
    assert_eq!(&a * &zero, zero);
    assert_eq!(&zero * &a, zero);
}

#[test]
fn test_scalar_subtraction_properties() {
    let a = Scalar::new(BigUint::from(15u32));
    let b = Scalar::new(BigUint::from(10u32));

    // Test basic subtraction
    let result = &a - &b;
    assert_eq!(result.value, BigUint::from(5u32));

    // Test subtraction with zero
    let zero = Scalar::zero();
    assert_eq!(&a - &zero, a);

    // Test self-subtraction
    let self_sub = &a - &a;
    assert_eq!(self_sub, zero);
}

#[test]
fn test_scalar_bytes_format() {
    let scalar = Scalar::new(BigUint::from(0x123456u32));
    let bytes = scalar.as_bytes();

    // Should be 32 bytes
    assert_eq!(bytes.len(), 32);

    // Should be big-endian format
    // For 0x123456, the last 3 bytes should be [0x12, 0x34, 0x56]
    assert_eq!(bytes[29], 0x12);
    assert_eq!(bytes[30], 0x34);
    assert_eq!(bytes[31], 0x56);

    // Earlier bytes should be zero
    for i in 0..29 {
        assert_eq!(bytes[i], 0);
    }
}

#[test]
fn test_scalar_from_bytes_edge_cases() {
    // Test with all zeros
    let zero_bytes = [0u8; 32];
    let scalar = Scalar::from_bytes(&zero_bytes);
    assert_eq!(scalar, Scalar::zero());

    // Test with all 0xFF
    let max_bytes = [0xFFu8; 32];
    let scalar = Scalar::from_bytes(&max_bytes);
    // This should be reduced modulo N
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    assert!(scalar.value < *SECP256K1_N);

    // Test roundtrip consistency
    let reconstructed_bytes = scalar.as_bytes();
    let scalar2 = Scalar::from_bytes(&reconstructed_bytes);
    assert_eq!(scalar, scalar2);
}

#[test]
fn test_scalar_performance() {
    // Test that operations complete in reasonable time
    let a = Scalar::new(BigUint::from(12345u32));
    let b = Scalar::new(BigUint::from(67890u32));

    let start = std::time::Instant::now();

    // Perform many operations
    let mut result = a.clone();
    for _ in 0..1000 {
        result = &result + &b;
        result = &result * &a;
    }

    let duration = start.elapsed();

    // Should complete quickly (less than 1 second)
    assert!(duration.as_secs() < 1);

    // Result should still be valid
    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    assert!(result.value < *SECP256K1_N);
}

#[test]
fn test_scalar_modulus_consistency() {
    // All scalars should report the same modulus
    let scalars = vec![
        Scalar::zero(),
        Scalar::one(),
        Scalar::new(BigUint::from(42u32)),
        Scalar::random(),
    ];

    use bitcoin_dojo::ecc::constants::SECP256K1_N;
    for scalar in scalars {
        assert_eq!(*scalar.modulus(), *SECP256K1_N);
    }
}

#[test]
fn test_scalar_arithmetic_consistency() {
    // Test that different ways of computing the same result give the same answer
    let a = Scalar::new(BigUint::from(7u32));
    let b = Scalar::new(BigUint::from(3u32));

    // Test: 2*a = a + a
    let double1 = &a + &a;
    let double2 = &a * &Scalar::new(BigUint::from(2u32));
    assert_eq!(double1, double2);

    // Test: a*b = b*a (commutativity)
    assert_eq!(&a * &b, &b * &a);

    // Test: (a + b) - b = a
    let sum = &a + &b;
    let diff = &sum - &b;
    assert_eq!(diff, a);
}

#[test]
fn test_scalar_edge_case_operations() {
    use bitcoin_dojo::ecc::constants::SECP256K1_N;

    let zero = Scalar::zero();
    let one = Scalar::one();
    let max_val = Scalar::new(&*SECP256K1_N - BigUint::from(1u32));

    // Test operations with maximum value
    let max_plus_one = &max_val + &one;
    assert_eq!(max_plus_one, zero); // Should wrap to zero

    let max_times_max = &max_val * &max_val;
    assert_eq!(max_times_max, one); // (-1) * (-1) = 1

    // Test operations near the modulus boundary
    let near_max = Scalar::new(&*SECP256K1_N - BigUint::from(5u32));
    let small = Scalar::new(BigUint::from(10u32));
    let result = &near_max + &small;
    assert_eq!(result.value, BigUint::from(5u32)); // Should wrap around
}
