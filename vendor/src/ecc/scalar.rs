use std::fmt;
use num_bigint::BigUint;
use std::ops::{Add, Sub, Mul};
use crate::ecc::constants::SECP256K1_N;

#[derive(Debug, Clone, PartialEq)]
pub struct Scalar {
    pub value: BigUint
}

impl Scalar {
    pub fn new(value: BigUint) -> Self {
        Self { value: value % &*SECP256K1_N }
    }

    pub fn inverse(&self) -> Option<Self> {
        if self.value == BigUint::from(0u32) {
            return None;
        }

        let (gcd, inv) = extended_gcd_for_inverse(self.value.clone(), SECP256K1_N.clone());

        if gcd != BigUint::from(1u32) {
            None
        } else {
            Some(Scalar::new(inv))
        }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = self.value.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32 - bytes.len();
        result[start..].copy_from_slice(&bytes);
        result
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::new(BigUint::from_bytes_be(bytes))
    }

    pub fn zero() -> Self {
        Self::new(BigUint::from(0u32))
    }

    pub fn one() -> Self {
        Self::new(BigUint::from(1u32))
    }

    pub fn value(&self) -> &BigUint {
        &self.value
    }

    pub fn modulus(&self) -> &BigUint {
        &*SECP256K1_N
    }

    pub fn random() -> Self {
        use crate::ecc::util::secure_random_scalar;
        Self::new(secure_random_scalar())
    }
}

// Extended Euclidean Algorithm for modular inverse
// Returns (gcd, x) where x is the modular inverse of a mod m
fn extended_gcd_for_inverse(a: BigUint, m: BigUint) -> (BigUint, BigUint) {
    if a == BigUint::from(0u32) {
        return (m, BigUint::from(0u32));
    }

    let mut old_r = a.clone();
    let mut r = m.clone();
    let mut old_s = BigUint::from(1u32);
    let mut s = BigUint::from(0u32);
    let mut old_s_neg = false;
    let mut s_neg = false;

    while r != BigUint::from(0u32) {
        let quotient = &old_r / &r;

        // Update r
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        // Update s (handling signs)
        let temp_s = s.clone();
        let temp_s_neg = s_neg;

        let product = &quotient * &s;
        if old_s_neg == s_neg {
            if old_s >= product {
                s = &old_s - &product;
                s_neg = old_s_neg;
            } else {
                s = &product - &old_s;
                s_neg = !old_s_neg;
            }
        } else {
            s = &old_s + &product;
            s_neg = old_s_neg;
        }

        old_s = temp_s;
        old_s_neg = temp_s_neg;
    }

    // If old_s is negative, convert to positive equivalent
    let result = if old_s_neg {
        &m - (&old_s % &m)
    } else {
        old_s % &m
    };

    (old_r, result)
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Scalar_{}", self.value.to_str_radix(16))
    }
}

// Implement arithmetic traits
impl Add for Scalar {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let result = (&self.value + &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        let result = (&self.value + &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        // Add N before subtracting to avoid underflow with unsigned BigUint
        let result = (&*SECP256K1_N + &self.value - &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        let result = (&*SECP256K1_N + &self.value - &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Mul for Scalar {
    type Output = Scalar;

    fn mul(self, other: Self) -> Self {
        let result = (&self.value * &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        let result = (&self.value * &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}
