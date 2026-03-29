
use num_bigint::BigUint;
use lazy_static::lazy_static;

// secp256k1 curve parameters
pub const SECP256K1_P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
pub const SECP256K1_N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
pub const SECP256K1_GX_HEX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
pub const SECP256K1_GY_HEX: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
pub const SECP256K1_A_HEX: &str = "0";
pub const SECP256K1_B_HEX: &str = "7";

lazy_static! {
    pub static ref SECP256K1_P: BigUint = BigUint::parse_bytes(SECP256K1_P_HEX.as_bytes(), 16).unwrap();
    pub static ref SECP256K1_N: BigUint = BigUint::parse_bytes(SECP256K1_N_HEX.as_bytes(), 16).unwrap();
    pub static ref SECP256K1_GX: BigUint = BigUint::parse_bytes(SECP256K1_GX_HEX.as_bytes(), 16).unwrap();
    pub static ref SECP256K1_GY: BigUint = BigUint::parse_bytes(SECP256K1_GY_HEX.as_bytes(), 16).unwrap();
    pub static ref SECP256K1_A: BigUint = BigUint::parse_bytes(SECP256K1_A_HEX.as_bytes(), 16).unwrap();
    pub static ref SECP256K1_B: BigUint = BigUint::parse_bytes(SECP256K1_B_HEX.as_bytes(), 16).unwrap();
}
