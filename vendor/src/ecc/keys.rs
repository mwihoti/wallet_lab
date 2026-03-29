use super::scalar::Scalar;
use super::curve::Point;
use super::field::FieldElement;
use num_bigint::BigUint;
use crate::utils::address_types::AddressType;
use crate::utils::address_types::Network;
use crate::utils::base58;


#[derive(Debug, Clone)]
pub struct PrivateKey {
    scalar: Scalar,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey {
    point: Point,
}

impl PrivateKey {
    pub fn new() -> Self {
        // Write your implementation
        Self {
            scalar: Scalar::random(),
        }
    }
    
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }
    
    pub fn public_key(&self) -> PublicKey {
        // Write your implementation
        let generator = Point::generator();
        let point = generator.multiply(&self.scalar);
        PublicKey { point }
    }
    
    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }


    /// Convert private key to Wallet Import Format (WIF)
    /// WIF is a Base58Check encoded format for Bitcoin private keys
    /// compressed: if true, indicates the public key should be compressed
    pub fn to_wif(&self, network: Network, compressed: bool) -> String {
        // Write your implementation
        let mut payload = Vec::new();
        payload.push(network.wif_version());
        // add the 32
        payload.extend_from_slice(&self.scalar().as_bytes());
        if compressed {
            payload.push(0x01);
        }
       base58::encode_base58_check(&payload)
       
        
    }
  
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKey {
    pub fn point(&self) -> &Point {
        &self.point
    }

      pub fn to_sec(&self, compressed: bool) -> Vec<u8> {
        // Write your implementation
        // standard efficiency cryptography router
        if compressed {
            self.sec_compressed()
        } else {
            self.sec_uncompressed()
        }
    }
    
    fn sec_compressed(&self) -> Vec<u8> {
        let x = self.point.x().as_ref().unwrap();
        let y = self.point.y().as_ref().unwrap();

        let y_bytes = y.to_bytes_fixed(32);
        // If the last bit is 0, the number is even. If it's 1, the number is odd. 
        let prefix = if y_bytes[31] & 1 == 0 {
            0x02
        }  else {
            0x03
        };

        let mut result = vec![prefix];
        result.extend(x.to_bytes_fixed(32));
        result
    }

    fn sec_uncompressed(&self) -> Vec<u8> {
        let x = self.point.x().as_ref().unwrap();
        let y = self.point.y().as_ref().unwrap();

        let mut result = vec![0x04]; // add marker reading    
        result.extend(x.to_bytes_fixed(32));
        result.extend(y.to_bytes_fixed(32));
        result
    }

    // Parse a SEC format public key (compressed or uncompressed)
    /// Compressed format: 33 bytes [0x02/0x03, x_coordinate (32 bytes)]
    /// Uncompressed format: 65 bytes [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    pub fn parse(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        match sec_bytes.len() {
            65 => Self::parse_uncompressed(sec_bytes),
            33 => Self::parse_compressed(sec_bytes),
            _ => Err("Invalid SEC format: expected 33 bytes (compressed) or 65 bytes (uncompressed)"),
        }
    }

    fn parse_uncompressed(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        if sec_bytes[0] != 0x04 {
            return Err("Invalid uncompressed SEC: must start with 0x04");
        }

        let x = FieldElement::from_bytes(&sec_bytes[1..33]);
        let y = FieldElement::from_bytes(&sec_bytes[33..65]);

        let point = Point::new(Some(x), Some(y));
        Ok(PublicKey { point })
    }

    fn parse_compressed(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        if sec_bytes[0] != 0x02 && sec_bytes[0] != 0x03 {
            return Err("Invalid compressed SEC: must start with 0x02 or 0x03");
        }
        let is_even = sec_bytes[0] == 0x02;
        let x = FieldElement::from_bytes(&sec_bytes[1..33]);

        // y^2 = x^3 + 7
        let x_cubed = x.pow_biguint(&BigUint::from(3u32));
        let seven = FieldElement::new(BigUint::from(7u32));
        let y_squared = x_cubed + seven;
        // compute y = √(y²)
        let y = y_squared.sqrt();

        // sqrt() gives us one root - check if it's the right parity
        let y_bytes = y.to_bytes_fixed(32);
        let y_is_even = y_bytes[31] & 1 == 0;

        // if parity doesn't match, use other root: p - y
        let final_y = if y_is_even == is_even {
            y
        } else {
            let p = y.prime().clone();
            FieldElement::new(p - y.value())
        };

        let point = Point::new(Some(x), Some(final_y));
        Ok(PublicKey { point })
    }


    /// Generate a Bitcoin address of the specified type.
    pub fn address(&self, address_type: AddressType, network: Network) -> String {
        match address_type {
            AddressType::P2PKH => self.p2pkh_address(network),
            AddressType::P2SHP2WPKH => self.p2sh_p2wpkh_address(network),
            AddressType::P2WPKH => self.p2wpkh_address(network),
        }
    }

    /// Legacy P2PKH: base58check( version || hash160(pubkey) )
    pub fn p2pkh_address(&self, network: Network) -> String {
        let sec  = self.to_sec(true);
        let hash = crate::utils::hash160::hash160(&sec);
        let mut payload = Vec::with_capacity(21);
        payload.push(network.p2pkh_version());
        payload.extend_from_slice(&hash);
        crate::utils::base58::encode_base58_check(&payload)
    }

    /// Nested SegWit P2SH-P2WPKH: wrap a P2WPKH redeem script inside P2SH.
    ///
    /// redeem_script = OP_0 <20-byte-pubkey-hash>  (22 bytes)
    /// address       = base58check( p2sh_version || hash160(redeem_script) )
    pub fn p2sh_p2wpkh_address(&self, network: Network) -> String {
        let sec = self.to_sec(true);
        let pubkey_hash = crate::utils::hash160::hash160(&sec);

        // Build the 22-byte P2WPKH redeem script
        let mut redeem_script = Vec::with_capacity(22);
        redeem_script.push(0x00); // OP_0
        redeem_script.push(0x14); // push 20 bytes
        redeem_script.extend_from_slice(&pubkey_hash);

        // Hash the redeem script → 20-byte script hash
        let script_hash = crate::utils::hash160::hash160(&redeem_script);

        let mut payload = Vec::with_capacity(21);
        payload.push(network.p2sh_version());
        payload.extend_from_slice(&script_hash);
        crate::utils::base58::encode_base58_check(&payload)
    }

    /// Native SegWit P2WPKH: bech32( hrp, witness_version=0, hash160(pubkey) )
    pub fn p2wpkh_address(&self, network: Network) -> String {
        let sec = self.to_sec(true);
        let pubkey_hash = crate::utils::hash160::hash160(&sec);
        crate::utils::bech32::encode(network.bech32_hrp(), 0, &pubkey_hash)
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use crate::utils::address_types::{AddressType, Network};

    #[test]
    fn generate_and_view_my_keys() {
        // generate a random private key
        let private_key = PrivateKey::new();
        // derive the public key
        let public_key = private_key.public_key();

        // generate the bitcoin addresses
        let mainnet_address = public_key.p2pkh_address(Network::Mainnet);
        let testnet_address = public_key.p2pkh_address(Network::Testnet);

        // Get the public key in SEC formats

        let pubkey_compressed = public_key.to_sec(true);
        let pubkey_uncompressed = public_key.to_sec(false);

        // print them out!
              println!("\n=================================================");
              println!(" Secret Private Key (scalar): {:?}", private_key.scalar().value());
                     println!("\n=================================================");

                     println!("Public Key (Compressed): {}", hex::encode(&pubkey_compressed));
                     println!("Public Key (Uncompressed): {}", hex::encode(&pubkey_uncompressed));

                     println!("\n=================================================");
                     println!("Bitcoin Mainnet Address (P2PKH): {}", mainnet_address);
                     println!("Bitcoin Testnet Address (P2PKH): {}", testnet_address);
                     println!("\n=================================================");

            


    }
}