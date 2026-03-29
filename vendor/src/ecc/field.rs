
use num_bigint::BigUint;
use std::fmt;
use std::ops::{Add, Sub, Mul, Div};
use std::cmp::Ordering;
use crate::ecc::constants::SECP256K1_P;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    value: BigUint,
}

impl FieldElement {
    pub fn new(value: BigUint) -> Self {
        FieldElement { value: value % &*SECP256K1_P }
    }

    pub fn zero() -> Self { Self::new(BigUint::from(0u32)) }
    pub fn one() -> Self { Self::new(BigUint::from(1u32)) }

    // Convenience constructor for u64 values
    pub fn from_u64(num: u64) -> Self {
        Self::new(BigUint::from(num))
    }

    // Convenience constructor for hex strings
    pub fn from_hex(num_hex: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let value = BigUint::parse_bytes(num_hex.as_bytes(), 16).ok_or("Invalid hex string for num")?;
        Ok(Self::new(value))
    }

    // Convenience constructor for bytes (big-endian)
    pub fn from_bytes(num_bytes: &[u8]) -> Self {
        let value = BigUint::from_bytes_be(num_bytes);
        Self::new(value)
    }

    // Convert the field element's value to bytes (big-endian)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    // Convert the field element's value to bytes with fixed length (big-endian, zero-padded)
    pub fn to_bytes_fixed(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.value.to_bytes_be();
        match bytes.len().cmp(&len) {
            Ordering::Less => {
                let mut padded = vec![0u8; len - bytes.len()];
                padded.extend(bytes);
                padded
            }
            Ordering::Greater => {
                bytes.split_off(bytes.len() - len)
            }
            Ordering::Equal => bytes,
        }
    }

    pub fn inverse(&self) -> Option<Self> {
        if self.value == BigUint::from(0u32) {
            return None;
        }

        let (gcd, x) = extended_gcd_for_inverse(self.value.clone(), SECP256K1_P.clone());

        if gcd != BigUint::from(1u32) {
            return None;
        }

        Some(Self::new(x))
    }

    pub fn is_zero(&self) -> bool {
        self.value == BigUint::from(0u32)
    }

    pub fn num(&self) -> &BigUint {
        &self.value
    }

    pub fn value(&self) -> &BigUint {
        &self.value
    }

    pub fn prime(&self) -> &BigUint {
        &*SECP256K1_P
    }

    pub fn sqrt(&self) -> Self {
        let exp = (&*SECP256K1_P + BigUint::from(1u32)) / BigUint::from(4u32);
        let result = self.value.modpow(&exp, &*SECP256K1_P);
        Self::new(result)
    }

    pub fn pow_biguint(&self, exp: &BigUint) -> Self {
        let result = self.value.modpow(exp, &*SECP256K1_P);
        Self::new(result)
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

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FieldElement_{}", self.value.to_str_radix(16))
    }
}

// --- Borrowed operator impls ---

impl Add for &FieldElement {
    type Output = FieldElement;
    fn add(self, other: Self) -> FieldElement {
        let value = (&self.value + &other.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Sub for &FieldElement {
    type Output = FieldElement;
    fn sub(self, other: Self) -> FieldElement {
        let value = (&*SECP256K1_P + &self.value - &other.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;
    fn mul(self, other: Self) -> FieldElement {
        let value = (&self.value * &other.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Mul<u32> for &FieldElement {
    type Output = FieldElement;
    fn mul(self, scalar: u32) -> FieldElement {
        let value = (&self.value * BigUint::from(scalar)) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Div for &FieldElement {
    type Output = FieldElement;
    fn div(self, other: Self) -> FieldElement {
        let inv = other.inverse().expect("Division by zero");
        self * &inv
    }
}

// --- Owned operator impls (delegate to borrowed) ---

impl Add for FieldElement {
    type Output = FieldElement;
    fn add(self, other: Self) -> FieldElement { &self + &other }
}

impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;
    fn add(self, other: &FieldElement) -> FieldElement { &self + other }
}

impl Add<FieldElement> for &FieldElement {
    type Output = FieldElement;
    fn add(self, other: FieldElement) -> FieldElement { self + &other }
}

impl Sub for FieldElement {
    type Output = FieldElement;
    fn sub(self, other: Self) -> FieldElement { &self - &other }
}

impl Sub<&FieldElement> for FieldElement {
    type Output = FieldElement;
    fn sub(self, other: &FieldElement) -> FieldElement { &self - other }
}

impl Sub<FieldElement> for &FieldElement {
    type Output = FieldElement;
    fn sub(self, other: FieldElement) -> FieldElement { self - &other }
}

impl Mul for FieldElement {
    type Output = FieldElement;
    fn mul(self, other: Self) -> FieldElement { &self * &other }
}

impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;
    fn mul(self, other: &FieldElement) -> FieldElement { &self * other }
}

impl Mul<FieldElement> for &FieldElement {
    type Output = FieldElement;
    fn mul(self, other: FieldElement) -> FieldElement { self * &other }
}

impl Mul<u32> for FieldElement {
    type Output = FieldElement;
    fn mul(self, scalar: u32) -> FieldElement { &self * scalar }
}

impl Div for FieldElement {
    type Output = FieldElement;
    fn div(self, other: Self) -> FieldElement { &self / &other }
}

impl Div<&FieldElement> for FieldElement {
    type Output = FieldElement;
    fn div(self, other: &FieldElement) -> FieldElement { &self / other }
}

impl Div<FieldElement> for &FieldElement {
    type Output = FieldElement;
    fn div(self, other: FieldElement) -> FieldElement { self / &other }
}

pub trait Pow<T> {
    type Output;
    fn pow(self, exp: T) -> Self::Output;
}

impl Pow<&BigUint> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, exp: &BigUint) -> FieldElement {
        let value = self.value.modpow(exp, &*SECP256K1_P);
        FieldElement { value }
    }
}

impl Pow<BigUint> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, exp: BigUint) -> FieldElement {
        let value = self.value.modpow(&exp, &*SECP256K1_P);
        FieldElement { value }
    }
}

impl Pow<u32> for &FieldElement {
    type Output = FieldElement;

    fn pow(self, exp: u32) -> FieldElement {
        let exp = BigUint::from(exp);
        let value = self.value.modpow(&exp, &*SECP256K1_P);
        FieldElement { value }
    }
}
