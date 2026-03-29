pub fn add(left: u64, right: u64) -> u64 {
    left + right
}
pub mod ecc {
    pub mod constants;
    pub mod util;
    pub mod field;
    pub mod scalar;
    pub mod curve;
    pub mod keys;
    pub mod ecdsa;
}
pub mod utils {
    pub mod hash160;
    pub mod hash256;
    pub mod base58;
    pub mod address_types;
    pub mod varint;
    pub mod bech32;
}
pub mod transaction {
    pub mod tx;
    pub mod tx_input;
    pub mod tx_output;

}
pub use ecc::util::{secure_random_bytes, sha256};
pub use utils::hash160::hash160;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
