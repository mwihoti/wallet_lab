#[cfg(test)]
use bitcoin_dojo::ecc::constants::SECP256K1_P;
use bitcoin_dojo::ecc::field::{FieldElement, Pow};
use num_bigint::BigUint;

#[test]
fn test_new_valid() {
    let fe = FieldElement::new(BigUint::from(5u32));
    assert_eq!(*fe.value(), BigUint::from(5u32));
    assert_eq!(*fe.prime(), *SECP256K1_P);
}

#[test]
fn test_new_with_modular_reduction() {
    // Test that values >= SECP256K1_P are reduced
    let large_value = &*SECP256K1_P + BigUint::from(5u32);
    let fe = FieldElement::new(large_value);
    assert_eq!(*fe.value(), BigUint::from(5u32));
}

#[test]
fn test_from_u64() {
    let fe = FieldElement::from_u64(3);
    assert_eq!(*fe.value(), BigUint::from(3u32));
    assert_eq!(*fe.prime(), *SECP256K1_P);
}

#[test]
fn test_from_hex_valid() {
    let fe = FieldElement::from_hex("a").unwrap();
    assert_eq!(*fe.value(), BigUint::from(10u32));
    assert_eq!(*fe.prime(), *SECP256K1_P);
}

#[test]
fn test_from_hex_invalid() {
    let result = FieldElement::from_hex("xyz");
    assert!(result.is_err());
}

#[test]
fn test_from_bytes() {
    let bytes = [0x12, 0x34];
    let fe = FieldElement::from_bytes(&bytes);
    assert_eq!(*fe.value(), BigUint::from(0x1234u32));
}

#[test]
fn test_to_bytes() {
    let fe = FieldElement::new(BigUint::from(0x1234u32));
    let bytes = fe.to_bytes();
    assert_eq!(bytes, vec![0x12, 0x34]);
}

#[test]
fn test_to_bytes_fixed() {
    let fe = FieldElement::new(BigUint::from(0x1234u32));
    let bytes = fe.to_bytes_fixed(4);
    assert_eq!(bytes, vec![0x00, 0x00, 0x12, 0x34]);

    // Test truncation
    let bytes = fe.to_bytes_fixed(1);
    assert_eq!(bytes, vec![0x34]);
}

#[test]
fn test_zero() {
    let fe = FieldElement::zero();
    assert!(fe.is_zero());
    assert_eq!(*fe.value(), BigUint::from(0u32));
}

#[test]
fn test_one() {
    let fe = FieldElement::one();
    assert!(!fe.is_zero());
    assert_eq!(*fe.value(), BigUint::from(1u32));
}

#[test]
fn test_is_zero_true() {
    let fe = FieldElement::new(BigUint::from(0u32));
    assert!(fe.is_zero());
}

#[test]
fn test_is_zero_false() {
    let fe = FieldElement::new(BigUint::from(3u32));
    assert!(!fe.is_zero());
}

#[test]
fn test_display() {
    let fe = FieldElement::from_u64(10);
    let display_str = format!("{}", fe);
    assert_eq!(display_str, "FieldElement_a");
}

#[test]
fn test_partial_eq_equal() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::from_u64(5);
    assert_eq!(&fe1, &fe2);
}

#[test]
fn test_partial_eq_different() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::from_u64(3);
    assert_ne!(&fe1, &fe2);
}

#[test]
fn test_add_basic() {
    let fe1 = FieldElement::from_u64(2);
    let fe2 = FieldElement::from_u64(3);
    let result = &fe1 + &fe2;
    assert_eq!(*result.value(), BigUint::from(5u32));
}

#[test]
fn test_add_with_modulo() {
    // Test addition that wraps around the modulus
    let fe1 = FieldElement::new(&*SECP256K1_P - BigUint::from(1u32));
    let fe2 = FieldElement::from_u64(2);
    let result = &fe1 + &fe2;
    assert_eq!(*result.value(), BigUint::from(1u32));
}

#[test]
fn test_add_owned() {
    let fe1 = FieldElement::from_u64(2);
    let fe2 = FieldElement::from_u64(3);
    let result = fe1 + fe2;
    assert_eq!(*result.value(), BigUint::from(5u32));
}

#[test]
fn test_sub_basic() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::from_u64(2);
    let result = &fe1 - &fe2;
    assert_eq!(*result.value(), BigUint::from(3u32));
}

#[test]
fn test_sub_with_wrap_around() {
    let fe1 = FieldElement::from_u64(2);
    let fe2 = FieldElement::from_u64(5);
    let result = &fe1 - &fe2;
    let expected = &*SECP256K1_P - BigUint::from(3u32);
    assert_eq!(*result.value(), expected);
}

#[test]
fn test_sub_owned() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::from_u64(2);
    let result = fe1 - fe2;
    assert_eq!(*result.value(), BigUint::from(3u32));
}

#[test]
fn test_mul_basic() {
    let fe1 = FieldElement::from_u64(3);
    let fe2 = FieldElement::from_u64(4);
    let result = &fe1 * &fe2;
    assert_eq!(*result.value(), BigUint::from(12u32));
}

#[test]
fn test_mul_with_modulo() {
    // Test multiplication that requires modular reduction
    let large_val = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
        16,
    )
    .unwrap();
    let fe1 = FieldElement::new(large_val);
    let fe2 = FieldElement::from_u64(2);
    let result = &fe1 * &fe2;
    // Should be reduced modulo SECP256K1_P
    assert!(*result.value() < *SECP256K1_P);
}

#[test]
fn test_mul_owned() {
    let fe1 = FieldElement::from_u64(3);
    let fe2 = FieldElement::from_u64(4);
    let result = fe1 * fe2;
    assert_eq!(*result.value(), BigUint::from(12u32));
}

#[test]
fn test_mul_u32() {
    let fe = FieldElement::from_u64(3);
    let result = &fe * 4u32;
    assert_eq!(*result.value(), BigUint::from(12u32));
}

#[test]
fn test_mul_u32_owned() {
    let fe = FieldElement::from_u64(3);
    let result = fe * 4u32;
    assert_eq!(*result.value(), BigUint::from(12u32));
}

#[test]
fn test_div_basic() {
    let fe1 = FieldElement::from_u64(6);
    let fe2 = FieldElement::from_u64(2);
    let result = &fe1 / &fe2;
    assert_eq!(*result.value(), BigUint::from(3u32));
}

#[test]
fn test_div_with_inverse() {
    let fe1 = FieldElement::from_u64(1);
    let fe2 = FieldElement::from_u64(2);
    let result = &fe1 / &fe2;

    // Verify: result * fe2 should equal fe1
    let verification = &result * &fe2;
    assert_eq!(verification, fe1);
}

#[test]
fn test_div_owned() {
    let fe1 = FieldElement::from_u64(6);
    let fe2 = FieldElement::from_u64(2);
    let result = fe1 / fe2;
    assert_eq!(*result.value(), BigUint::from(3u32));
}

#[test]
#[should_panic(expected = "Division by zero")]
fn test_div_by_zero() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::zero();
    let _ = &fe1 / &fe2;
}

#[test]
fn test_inverse() {
    let fe = FieldElement::from_u64(3);
    let inverse = fe.inverse().unwrap();

    // Verify: fe * inverse should equal 1
    let product = &fe * &inverse;
    assert_eq!(*product.value(), BigUint::from(1u32));
}

#[test]
fn test_inverse_zero() {
    let zero = FieldElement::zero();
    assert!(zero.inverse().is_none());
}

#[test]
fn test_inverse_one() {
    let one = FieldElement::one();
    let inverse = one.inverse().unwrap();
    assert_eq!(inverse, one);
}

#[test]
fn test_pow_biguint_ref() {
    let fe = FieldElement::from_u64(3);
    let exp = BigUint::from(2u32);
    let result = (&fe).pow(&exp);
    assert_eq!(*result.value(), BigUint::from(9u32));
}

#[test]
fn test_pow_biguint() {
    let fe = FieldElement::from_u64(3);
    let exp = BigUint::from(3u32);
    let result = (&fe).pow(&exp);
    assert_eq!(*result.value(), BigUint::from(27u32));
}

#[test]
fn test_pow_u32() {
    let fe = FieldElement::from_u64(2);
    let result = (fe).pow(3u32);
    assert_eq!(*result.value(), BigUint::from(8u32));
}

#[test]
fn test_pow_zero() {
    let fe = FieldElement::from_u64(5);
    let result = (fe).pow(0u32);
    assert_eq!(*result.value(), BigUint::from(1u32));
}

#[test]
fn test_pow_owned() {
    let fe = FieldElement::from_u64(2);
    let result = fe.pow(3u32);
    assert_eq!(*result.value(), BigUint::from(8u32));
}

#[test]
fn test_sqrt() {
    // Test with a known quadratic residue
    let fe = FieldElement::from_u64(4);
    let sqrt_result = fe.sqrt();

    // Verify that sqrt_result^2 equals the original value
    let squared = (sqrt_result).pow(2u32);
    assert_eq!(squared, fe);
}

#[test]
fn test_clone() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = fe1.clone();
    assert_eq!(&fe1, &fe2);
    assert_eq!(*fe2.value(), BigUint::from(5u32));
}

#[test]
fn test_debug() {
    let fe = FieldElement::from_u64(5);
    let debug_str = format!("{:?}", fe);
    assert!(debug_str.contains("FieldElement"));
    assert!(debug_str.contains("value"));
}

#[test]
fn test_large_numbers() {
    let large_hex = "123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234";
    let fe1 = FieldElement::from_hex(large_hex).unwrap();
    let fe2 = FieldElement::from_hex(large_hex).unwrap();

    // Test operations with large numbers
    let sum = &fe1 + &fe2;
    assert!(*sum.value() < *SECP256K1_P);

    let product = &fe1 * &fe2;
    assert!(*product.value() < *SECP256K1_P);
}

#[test]
fn test_field_arithmetic_properties() {
    let fe1 = FieldElement::from_u64(3);
    let fe2 = FieldElement::from_u64(4);
    let fe3 = FieldElement::from_u64(2);

    // Test commutativity of addition
    let add1 = &fe1 + &fe2;
    let add2 = &fe2 + &fe1;
    assert_eq!(&add1, &add2);

    // Test commutativity of multiplication
    let mul1 = &fe1 * &fe2;
    let mul2 = &fe2 * &fe1;
    assert_eq!(&mul1, &mul2);

    // Test associativity of addition
    let add_assoc1 = &(&fe1 + &fe2) + &fe3;
    let add_assoc2 = &fe1 + &(&fe2 + &fe3);
    assert_eq!(&add_assoc1, &add_assoc2);

    // Test associativity of multiplication
    let mul_assoc1 = &(&fe1 * &fe2) * &fe3;
    let mul_assoc2 = &fe1 * &(&fe2 * &fe3);
    assert_eq!(&mul_assoc1, &mul_assoc2);
}

#[test]
fn test_additive_identity() {
    let fe = FieldElement::from_u64(42);
    let zero = FieldElement::zero();

    assert_eq!(&fe + &zero, fe);
    assert_eq!(&zero + &fe, fe);
}

#[test]
fn test_multiplicative_identity() {
    let fe = FieldElement::from_u64(42);
    let one = FieldElement::one();

    assert_eq!(&one * &fe, fe);
}

#[test]
fn test_additive_inverse() {
    let fe = FieldElement::from_u64(42);
    let zero = FieldElement::zero();

    // fe + (-fe) should equal zero
    // In modular arithmetic, -fe = p - fe
    let neg_fe = FieldElement::new(&*SECP256K1_P - fe.value());
    let result = &fe + &neg_fe;
    assert_eq!(result, zero);
}

#[test]
fn test_distributivity() {
    let a = FieldElement::from_u64(3);
    let b = FieldElement::from_u64(4);
    let c = FieldElement::from_u64(5);

    // Test: a * (b + c) = a * b + a * c
    let left = &a * &(&b + &c);
    let right = &(&a * &b) + &(&a * &c);
    assert_eq!(left, right);
}

#[test]
fn test_secp256k1_specific_values() {
    // Test with secp256k1-specific values
    let p_minus_1 = FieldElement::new(&*SECP256K1_P - BigUint::from(1u32));
    let one = FieldElement::one();

    // (p-1) + 1 should equal 0
    let result = &p_minus_1 + &one;
    assert!(result.is_zero());

    // (p-1) * (p-1) should equal 1 (since (p-1) ≡ -1 mod p)
    let result = &p_minus_1 * &p_minus_1;
    assert_eq!(result, one);
}

#[test]
fn test_modular_reduction_consistency() {
    // Test that creating elements with values >= p gives consistent results
    let val1 = BigUint::from(5u32);
    let val2 = &*SECP256K1_P + BigUint::from(5u32);
    let val3 = &*SECP256K1_P * BigUint::from(2u32) + BigUint::from(5u32);

    let fe1 = FieldElement::new(val1);
    let fe2 = FieldElement::new(val2);
    let fe3 = FieldElement::new(val3);

    assert_eq!(fe1, fe2);
    assert_eq!(fe2, fe3);
}

#[test]
fn test_bytes_roundtrip() {
    let original = FieldElement::from_u64(0x123456789abcdef0);
    let bytes = original.to_bytes();
    let reconstructed = FieldElement::from_bytes(&bytes);
    assert_eq!(original, reconstructed);
}

#[test]
fn test_hex_roundtrip() {
    let hex_str = "0123456789abcdef";
    let fe = FieldElement::from_hex(hex_str).unwrap();
    let bytes = fe.to_bytes();
    let hex_result = hex::encode(&bytes);
    assert_eq!(hex_str, hex_result);
}

#[test]
fn test_performance_large_exponent() {
    let base = FieldElement::from_u64(2);
    let large_exp = BigUint::from(1000u32);

    let start = std::time::Instant::now();
    let result = (&base).pow(&large_exp);
    let duration = start.elapsed();

    // Should complete quickly (modular exponentiation is efficient)
    assert!(duration.as_millis() < 100);
    assert!(*result.value() < *SECP256K1_P);
}

#[test]
fn test_edge_case_zero_operations() {
    let zero = FieldElement::zero();
    let fe = FieldElement::from_u64(42);

    // Zero operations
    assert_eq!(&zero + &fe, fe);
    assert_eq!(&fe + &zero, fe);
    assert_eq!(&zero * &fe, zero);
    assert_eq!(&fe * &zero, zero);
    assert_eq!(&fe - &fe, zero);

    // Zero power
    let result = (zero).pow(5u32);
    assert!(result.is_zero());

    // Anything to power 0 equals 1
    let result = (fe).pow(0u32);
    assert_eq!(result, FieldElement::one());
}

#[test]
fn test_edge_case_one_operations() {
    let one = FieldElement::one();
    let fe = FieldElement::from_u64(42);

    // One operations
    assert_eq!(&one * &fe, fe);
    assert_eq!(&fe * &one, fe);
    assert_eq!(&fe / &one, fe);

    // One powers
    let result = (one.clone()).pow(1000u32);
    assert_eq!(result, one);
}

#[test]
fn test_field_element_ordering() {
    let fe1 = FieldElement::from_u64(5);
    let fe2 = FieldElement::from_u64(10);
    let fe3 = FieldElement::from_u64(5);

    assert_eq!(fe1, fe3);
    assert_ne!(fe1, fe2);

    // Test that values are properly reduced
    let fe4 = FieldElement::new(&*SECP256K1_P + BigUint::from(5u32));
    assert_eq!(fe1, fe4);
}

#[test]
fn test_secp256k1_generator_coordinates() {
    // Test with actual secp256k1 generator point coordinates
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    let gx = FieldElement::from_hex(gx_hex).unwrap();
    let gy = FieldElement::from_hex(gy_hex).unwrap();

    // These should be valid field elements
    assert!(*gx.value() < *SECP256K1_P);
    assert!(*gy.value() < *SECP256K1_P);

    // Test that they satisfy the curve equation: y² = x³ + 7
    let y_squared = (gy).pow(2u32);
    let x_cubed = (gx).pow(3u32);
    let seven = FieldElement::from_u64(7);
    let right_side = &x_cubed + &seven;

    assert_eq!(y_squared, right_side);
}

#[test]
fn test_field_element_max_value() {
    // Test with the maximum valid field element value (p-1)
    let max_val = &*SECP256K1_P - BigUint::from(1u32);
    let fe = FieldElement::new(max_val.clone());
    assert_eq!(*fe.value(), max_val);

    // Adding 1 should wrap to 0
    let one = FieldElement::one();
    let result = &fe + &one;
    assert!(result.is_zero());
}

#[test]
fn test_mixed_operation_types() {
    let fe1 = FieldElement::from_u64(3);
    let fe2 = FieldElement::from_u64(4);

    // Test mixing owned and borrowed operations
    let result1 = &fe1 + &fe2;
    let result2 = fe1.clone() + &fe2;
    let result3 = &fe1 + fe2.clone();
    let result4 = fe1.clone() + fe2.clone();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(result3, result4);
}
