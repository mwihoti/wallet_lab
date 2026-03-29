/// src/ecc/util.rs

use sha2::{Sha256, Digest};
use rand::Rng;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}


pub fn secure_random_scalar() -> num_bigint::BigUint {
    use crate::ecc::constants::SECP256K1_N;
    loop {
        let bytes = secure_random_bytes(32);
        let candidate = num_bigint::BigUint::from_bytes_be(&bytes);
        if candidate < *SECP256K1_N && candidate > num_bigint::BigUint::from(0u32) {
            return candidate;
        }
    }
}
