use sha2::{Sha256, Digest};


pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    };
    let mut hasher = Sha256::new();
    hasher.update(&first);
    hasher.finalize().into()
}