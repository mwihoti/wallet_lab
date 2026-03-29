use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Performs HASH160 operation: RIPEMD160(SHA256(input))
/// This is commonly used in Bitcoin for creating addresses from public keys

/// # Returns
/// A 20-byte array containing the HASH160 result
pub fn hash160(input: &[u8]) -> [u8; 20] {
    // Write your implementation
    let sha256_digest: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    };

    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_digest);
    hasher.finalize().into()

}
