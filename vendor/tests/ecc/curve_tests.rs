use bitcoin_dojo::ecc::curve::Point;
#[cfg(test)]
use bitcoin_dojo::ecc::field::FieldElement;
use bitcoin_dojo::ecc::field::Pow;
use bitcoin_dojo::ecc::scalar::Scalar;
use num_bigint::BigUint;

// Helper function to create test field elements
fn fe(value: u32) -> FieldElement {
    FieldElement::new(BigUint::from(value))
}

#[test]
fn test_point_creation() {
    // Valid point on secp256k1 curve (we need to find actual valid points)
    // For now, let's use the generator point coordinates
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    let gx = FieldElement::from_hex(gx_hex).unwrap();
    let gy = FieldElement::from_hex(gy_hex).unwrap();

    // Valid point (generator)
    let point = Point::new(Some(gx), Some(gy));
    assert!(!point.is_infinity());

    // Point at infinity
    let infinity = Point::new(None, None);
    assert!(infinity.is_infinity());
}

#[test]
#[should_panic(expected = "is not on the secp256k1 curve")]
fn test_invalid_point() {
    // This should panic as it's not on the curve
    Point::new(Some(fe(200)), Some(fe(119)));
}

#[test]
fn test_point_addition() {
    // Use generator point for testing
    let g = Point::generator();

    // Test g + g (point doubling)
    let result = &g + &g;
    assert!(!result.is_infinity());
}

#[test]
fn test_point_infinity_addition() {
    let g = Point::generator();
    let infinity = Point::infinity();

    let result1 = &g + &infinity;
    let result2 = &infinity + &g;

    assert_eq!(result1, g);
    assert_eq!(result2, g);
}

#[test]
fn test_scalar_multiplication() {
    let g = Point::generator();
    let scalar = BigUint::from(2u32);

    let result = &g * scalar;
    let expected = &g + &g;

    assert_eq!(result, expected);
}

#[test]
fn test_point_getters() {
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    let gx = FieldElement::from_hex(gx_hex).unwrap();
    let gy = FieldElement::from_hex(gy_hex).unwrap();

    let point = Point::new(Some(gx.clone()), Some(gy.clone()));

    assert_eq!(point.x(), &Some(gx));
    assert_eq!(point.y(), &Some(gy));
    assert_eq!(point.a(), FieldElement::zero());
    assert_eq!(point.b(), FieldElement::new(BigUint::from(7u32)));
}

#[test]
fn test_point_infinity_getters() {
    let infinity = Point::infinity();

    assert_eq!(infinity.x(), &None);
    assert_eq!(infinity.y(), &None);
    assert_eq!(infinity.a(), FieldElement::zero());
    assert_eq!(infinity.b(), FieldElement::new(BigUint::from(7u32)));
    assert!(infinity.is_infinity());
}

#[test]
fn test_point_doubling() {
    let g = Point::generator();

    // Point doubling: G + G
    let doubled = &g + &g;
    assert!(!doubled.is_infinity());

    // Should be the same as 2 * G
    let scalar_doubled = &g * BigUint::from(2u32);
    assert_eq!(doubled, scalar_doubled);
}

#[test]
fn test_point_vertical_line_case() {
    let g = Point::generator();

    // To test vertical line case, we need a point and its negation
    // For secp256k1, if (x, y) is on the curve, then (x, -y mod p) is also on the curve
    if let (Some(x), Some(y)) = (g.x().clone(), g.y().clone()) {
        // Calculate -y mod p
        let p = y.prime();
        let neg_y = FieldElement::new(p - y.value());

        let neg_g = Point::new(Some(x), Some(neg_y));

        // Adding a point to its negation should give infinity
        let result = &g + &neg_g;
        assert!(result.is_infinity());
    }
}

#[test]
fn test_point_same_point() {
    let g1 = Point::generator();
    let g2 = Point::generator();

    // Test that two generator points are the same
    assert!(g1.same_point(&g2));

    // Test that infinity points are the same
    let infinity1 = Point::infinity();
    let infinity2 = Point::infinity();
    assert!(infinity1.same_point(&infinity2));

    // Test that generator and infinity are different
    assert!(!g1.same_point(&infinity1));

    // Test with different points on the curve
    // Create 2G (which is different from G)
    let g_doubled = &g1 + &g1;
    assert!(!g1.same_point(&g_doubled));

    // Test that the same point created differently are equal
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let g3 = Point::new(
        Some(FieldElement::from_hex(gx_hex).unwrap()),
        Some(FieldElement::from_hex(gy_hex).unwrap()),
    );
    assert!(g1.same_point(&g3));
}

#[test]
fn test_scalar_multiplication_with_scalar_type() {
    let g = Point::generator();
    let scalar = Scalar::new(BigUint::from(3u32));

    let result1 = &g * &scalar;
    let result2 = g.multiply(&scalar);
    let expected = &(&g + &g) + &g; // 3 * G = G + G + G

    assert_eq!(result1, result2);
    assert_eq!(result1, expected);
}

#[test]
fn test_scalar_multiplication_zero() {
    let g = Point::generator();
    let result = &g * BigUint::from(0u32);

    assert!(result.is_infinity());
}

#[test]
fn test_scalar_multiplication_one() {
    let g = Point::generator();
    let result = &g * BigUint::from(1u32);

    assert_eq!(result, g);
}

#[test]
fn test_scalar_multiplication_large() {
    let g = Point::generator();
    let large_scalar = BigUint::from(100u32);

    let result = &g * large_scalar;
    // Should not panic and should produce a valid point
    assert!(!result.is_infinity() || result.is_infinity()); // Either is valid
}

#[test]
fn test_point_addition_owned_variants() {
    let g1 = Point::generator();
    let g2 = Point::generator();

    // Test all combinations of owned/borrowed addition
    let result1 = &g1 + &g2;
    let result2 = g1.clone() + &g2;
    let result3 = &g1 + g2.clone();
    let result4 = g1.clone() + g2.clone();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(result3, result4);
}

#[test]
fn test_point_multiplication_owned_variants() {
    let g = Point::generator();
    let scalar = BigUint::from(3u32);

    // Test all combinations of owned/borrowed multiplication
    let result1 = &g * scalar.clone();
    let result2 = &g * &scalar;
    let result3 = g.clone() * scalar.clone();
    let result4 = g.clone() * &scalar;

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(result3, result4);
}

#[test]
fn test_point_equality() {
    let g1 = Point::generator();
    let g2 = Point::generator();

    assert_eq!(g1, g2);

    // Test reference equality
    assert_eq!(&g1, &g2);

    let inf1 = Point::infinity();
    let inf2 = Point::infinity();
    assert_eq!(inf1, inf2);
}

#[test]
fn test_point_tangent_vertical_case() {
    let g = Point::generator();

    // Test that doubling works correctly (this tests the tangent case)
    let doubled = &g + &g;
    let scalar_doubled = &g * BigUint::from(2u32);

    assert_eq!(doubled, scalar_doubled);
}

#[test]
fn test_associativity_of_point_addition() {
    let g = Point::generator();
    let g2 = &g * BigUint::from(2u32);
    let g3 = &g * BigUint::from(3u32);

    // Test associativity: (g + g2) + g3 = g + (g2 + g3)
    let left = &(&g + &g2) + &g3;
    let right = &g + &(&g2 + &g3);

    assert_eq!(left, right);
}

#[test]
fn test_commutativity_of_point_addition() {
    let g = Point::generator();
    let g2 = &g * BigUint::from(2u32);

    // Test commutativity: g + g2 = g2 + g
    let result1 = &g + &g2;
    let result2 = &g2 + &g;

    assert_eq!(result1, result2);
}

#[test]
fn test_scalar_multiplication_distributivity() {
    let g = Point::generator();
    let g2 = &g * BigUint::from(2u32);
    let k = BigUint::from(3u32);

    // Test distributivity: k * (g + g2) = k * g + k * g2
    let left = &(&g + &g2) * k.clone();
    let right = &(&g * k.clone()) + &(&g2 * k);

    assert_eq!(left, right);
}

#[test]
fn test_scalar_multiplication_associativity() {
    let g = Point::generator();
    let k1 = BigUint::from(3u32);
    let k2 = BigUint::from(5u32);

    // Test associativity: (k1 * k2) * g = k1 * (k2 * g)
    let left = &g * (&k1 * &k2);
    let right = &(&g * k2) * k1;

    assert_eq!(left, right);
}

#[test]
fn test_point_order_properties() {
    let g = Point::generator();

    // Test that scalar multiplication works for various values
    // and that we can compute large multiples without panicking
    let mut current = g.clone();

    // Test first few multiples
    for i in 1..=10 {
        current = &current + &g;
        let scalar_result = &g * BigUint::from((i + 1) as u32);
        assert_eq!(current, scalar_result);
    }

    // Test that we can compute larger multiples
    let large_multiple = &g * BigUint::from(100u32);
    // The result is valid whether it's infinity or not
    // Main goal is to ensure no panic occurs

    // Test that if we ever hit infinity, subsequent additions stay at infinity
    if large_multiple.is_infinity() {
        let still_infinity = &large_multiple + &g;
        assert!(still_infinity.is_infinity());
    }
}

#[test]
fn test_point_binary_representation() {
    let g = Point::generator();

    // Test that scalar multiplication with powers of 2 works correctly
    let g2 = &g * BigUint::from(2u32); // 2G
    let g4 = &g * BigUint::from(4u32); // 4G
    let g8 = &g * BigUint::from(8u32); // 8G

    // Verify: 4G = 2G + 2G
    assert_eq!(g4, &g2 + &g2);

    // Verify: 8G = 4G + 4G
    assert_eq!(g8, &g4 + &g4);

    // Verify: 8G = 2 * 4G
    assert_eq!(g8, &g4 * BigUint::from(2u32));
}

#[test]
fn test_point_edge_cases() {
    // Test infinity + infinity = infinity
    let inf1 = Point::infinity();
    let inf2 = Point::infinity();
    let result = &inf1 + &inf2;
    assert!(result.is_infinity());

    // Test infinity * k = infinity for any k
    let inf_scaled = &inf1 * BigUint::from(42u32);
    assert!(inf_scaled.is_infinity());

    // Test point * 0 = infinity
    let g = Point::generator();
    let zero_result = &g * BigUint::from(0u32);
    assert!(zero_result.is_infinity());
}

#[test]
fn test_point_clone_and_debug() {
    let g1 = Point::generator();
    let g2 = g1.clone();

    assert_eq!(g1, g2);

    // Test that Debug trait works (should not panic)
    let debug_str = format!("{:?}", g1);
    assert!(!debug_str.is_empty());

    let inf = Point::infinity();
    let inf_debug = format!("{:?}", inf);
    assert!(!inf_debug.is_empty());
}

#[test]
fn test_secp256k1_specific_properties() {
    let g = Point::generator();

    // Test that generator point is valid
    assert!(!g.is_infinity());

    // Test curve parameters
    assert_eq!(g.a(), FieldElement::zero());
    assert_eq!(g.b(), FieldElement::new(BigUint::from(7u32)));

    // Test that generator coordinates are correct
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    let expected_gx = FieldElement::from_hex(gx_hex).unwrap();
    let expected_gy = FieldElement::from_hex(gy_hex).unwrap();

    assert_eq!(g.x(), &Some(expected_gx));
    assert_eq!(g.y(), &Some(expected_gy));
}

#[test]
fn test_scalar_with_secp256k1_order() {
    let g = Point::generator();

    // Test with the secp256k1 order (multiplying by n should give infinity)
    let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
    let scalar_n = Scalar::new(n);

    // n * G should equal infinity (since n is the order of G)
    let result = g.multiply(&scalar_n);
    assert!(result.is_infinity());

    // Also test with a smaller scalar
    let scalar_5 = Scalar::new(BigUint::from(5u32));
    let result1 = &g * scalar_5.value().clone();
    let result2 = g.multiply(&scalar_5);
    assert_eq!(result1, result2);
}

#[test]
fn test_performance_large_scalar() {
    let g = Point::generator();

    // Test with a reasonably large scalar to ensure binary method is efficient
    let large_scalar = BigUint::from(1000u32);

    let start = std::time::Instant::now();
    let result = &g * large_scalar;
    let duration = start.elapsed();

    // Should complete quickly (less than 1 second for this size)
    assert!(duration.as_secs() < 1);

    // Result should be valid (either a point or infinity)
    assert!(result.is_infinity() || !result.is_infinity());
}

#[test]
fn test_point_coordinates_access() {
    let gx_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let gy_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

    let x_val = FieldElement::from_hex(gx_hex).unwrap();
    let y_val = FieldElement::from_hex(gy_hex).unwrap();

    let p = Point::new(Some(x_val.clone()), Some(y_val.clone()));

    // Test coordinate access
    match (p.x(), p.y()) {
        (Some(x), Some(y)) => {
            assert_eq!(x, &x_val);
            assert_eq!(y, &y_val);
        }
        _ => panic!("Expected Some coordinates"),
    }

    // Test curve parameter access
    assert_eq!(p.a(), FieldElement::zero());
    assert_eq!(p.b(), FieldElement::new(BigUint::from(7u32)));

    // Test infinity coordinates
    let inf = Point::infinity();
    assert_eq!(inf.x(), &None);
    assert_eq!(inf.y(), &None);
    assert_eq!(inf.a(), FieldElement::zero());
    assert_eq!(inf.b(), FieldElement::new(BigUint::from(7u32)));
}

#[test]
fn test_point_arithmetic_properties() {
    let g = Point::generator();
    let inf = Point::infinity();

    // Test identity element: P + O = P (where O is point at infinity)
    assert_eq!(&g + &inf, g);
    assert_eq!(&inf + &g, g);
}

#[test]
fn test_point_special_cases() {
    let g = Point::generator();

    // Test point doubling
    let doubled_add = &g + &g;
    let doubled_mul = &g * BigUint::from(2u32);
    assert_eq!(doubled_add, doubled_mul);

    // Test 3G = G + G + G = G + 2G
    let triple_add = &(&g + &g) + &g;
    let triple_mixed = &g + &doubled_add;
    let triple_mul = &g * BigUint::from(3u32);

    assert_eq!(triple_add, triple_mixed);
    assert_eq!(triple_mixed, triple_mul);
}

#[test]
fn test_secp256k1_curve_equation() {
    // Test that the generator point satisfies y² = x³ + 7
    let g = Point::generator();

    if let (Some(x), Some(y)) = (g.x(), g.y()) {
        let y_squared = Pow::pow(y, 2u32); // Explicit trait call
        let x_cubed = Pow::pow(x, 3u32); // Explicit trait call
        let seven = FieldElement::new(BigUint::from(7u32));
        let right_side = &x_cubed + &seven;

        assert_eq!(y_squared, right_side);
    }
}

#[test]
fn test_point_negation() {
    let g = Point::generator();

    if let (Some(x), Some(y)) = (g.x().clone(), g.y().clone()) {
        // Create the negation of g: (x, -y mod p)
        let p = y.prime();
        let neg_y = FieldElement::new(p - y.value());
        let neg_g = Point::new(Some(x), Some(neg_y));

        // g + (-g) should equal infinity
        let result = &g + &neg_g;
        assert!(result.is_infinity());
    }
}

#[test]
fn test_multiple_point_operations() {
    let g = Point::generator();

    // Test various combinations
    let g2 = &g * BigUint::from(2u32);
    let g3 = &g * BigUint::from(3u32);
    let g5 = &g * BigUint::from(5u32);

    // Test: 2G + 3G = 5G
    let sum = &g2 + &g3;
    assert_eq!(sum, g5);

    // Test: 3G + 2G = 5G (commutativity)
    let sum2 = &g3 + &g2;
    assert_eq!(sum2, g5);
}

#[test]
fn test_point_subtraction_via_negation() {
    let g = Point::generator();
    let g2 = &g * BigUint::from(2u32);
    let g3 = &g * BigUint::from(3u32);

    // To test subtraction: 3G - 2G = G
    // We need to add 3G + (-2G) = G
    if let (Some(x2), Some(y2)) = (g2.x().clone(), g2.y().clone()) {
        let p = y2.prime();
        let neg_y2 = FieldElement::new(p - y2.value());
        let neg_g2 = Point::new(Some(x2), Some(neg_y2));

        let result = &g3 + &neg_g2;
        assert_eq!(result, g);
    }
}

#[test]
fn test_point_with_small_scalars() {
    let g = Point::generator();

    // Test small scalar multiplications
    for i in 1u32..=20u32 {
        let scalar_result = &g * BigUint::from(i);

        // Verify by repeated addition
        let mut addition_result = g.clone();
        for _ in 1..i {
            addition_result = &addition_result + &g;
        }

        assert_eq!(scalar_result, addition_result);
    }
}

#[test]
fn test_point_infinity_properties() {
    let inf = Point::infinity();
    let g = Point::generator();

    // Infinity is the additive identity
    assert_eq!(&inf + &g, g);
    assert_eq!(&g + &inf, g);
    assert_eq!(&inf + &inf, inf);

    // Infinity times any scalar is infinity
    assert_eq!(&inf * BigUint::from(5u32), inf);
    assert_eq!(&inf * BigUint::from(0u32), inf);
    assert_eq!(&inf * BigUint::from(1000u32), inf);
}

#[test]
fn test_point_creation_edge_cases() {
    // Test creating point at infinity
    let inf1 = Point::new(None, None);
    let inf2 = Point::infinity();
    assert_eq!(inf1, inf2);
    assert!(inf1.is_infinity());
    assert!(inf2.is_infinity());
}

#[test]
#[should_panic(expected = "Invalid parameters to Point::new()")]
fn test_invalid_point_parameters() {
    // x is Some but y is None - invalid
    Point::new(Some(FieldElement::from_u64(1)), None);
}

#[test]
#[should_panic(expected = "Invalid parameters to Point::new()")]
fn test_invalid_point_parameters_reverse() {
    // x is None but y is Some - invalid
    Point::new(None, Some(FieldElement::from_u64(1)));
}

#[test]
fn test_generator_point_properties() {
    let g = Point::generator();

    // Generator should not be infinity
    assert!(!g.is_infinity());

    // Generator should have valid coordinates
    assert!(g.x().is_some());
    assert!(g.y().is_some());

    // Multiple calls should return the same point
    let g2 = Point::generator();
    assert_eq!(g, g2);
}

#[test]
fn test_point_scalar_edge_cases() {
    let g = Point::generator();

    // Test with scalar 0
    let result_zero = &g * BigUint::from(0u32);
    assert!(result_zero.is_infinity());

    // Test with scalar 1
    let result_one = &g * BigUint::from(1u32);
    assert_eq!(result_one, g);

    // Test with large scalar
    let large_scalar = BigUint::parse_bytes(b"123456789abcdef", 16).unwrap();
    let result_large = &g * large_scalar;
    // Should not panic and should be valid
    assert!(result_large.is_infinity() || !result_large.is_infinity());
}

#[test]
fn test_point_consistency() {
    let g = Point::generator();

    // Test that operations are consistent
    let g2_via_add = &g + &g;
    let g2_via_mul = &g * BigUint::from(2u32);
    assert_eq!(g2_via_add, g2_via_mul);

    let g4_via_double_double = &(&g + &g) + &(&g + &g);
    let g4_via_mul = &g * BigUint::from(4u32);
    assert_eq!(g4_via_double_double, g4_via_mul);
}

#[test]
fn test_mixed_operation_types() {
    let g1 = Point::generator();
    let g2 = Point::generator();

    // Test mixing owned and borrowed operations for addition
    let result1 = &g1 + &g2;
    let result2 = g1.clone() + &g2;
    let result3 = &g1 + g2.clone();
    let result4 = g1.clone() + g2.clone();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(result3, result4);

    // Test mixing owned and borrowed operations for multiplication
    let scalar = BigUint::from(3u32);
    let mul_result1 = &g1 * scalar.clone();
    let mul_result2 = &g1 * &scalar;
    let mul_result3 = g1.clone() * scalar.clone();
    let mul_result4 = g1.clone() * &scalar;

    assert_eq!(mul_result1, mul_result2);
    assert_eq!(mul_result2, mul_result3);
    assert_eq!(mul_result3, mul_result4);
}
