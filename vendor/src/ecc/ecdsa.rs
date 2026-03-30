use super::constants::SECP256K1_N;
use super::curve::Point;
use super::keys::{PrivateKey, PublicKey};
use super::scalar::Scalar;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

/// Generate deterministic k value according to RFC 6979
/// This ensures that the same message and private key always produce the same signature
fn deterministic_k(private_key: &PrivateKey, message_hash: &[u8]) -> Scalar {
    // Convert message hash to scalar
    let mut z = Scalar::new(BigUint::from_bytes_be(message_hash));

    // Get the secp256k1 order (n)
    let n = &*SECP256K1_N;

    // Adjust z if it's >= n (reduce modulo n)
    if z.value() >= n {
        z = Scalar::new(z.value() % n);
    }

    // Convert private key and z to 32-byte arrays
    let private_key_bytes = private_key.scalar().value().to_bytes_be();
    let mut private_key_32 = [0u8; 32];
    let start_idx = if private_key_bytes.len() < 32 {
        32 - private_key_bytes.len()
    } else {
        0
    };
    private_key_32[start_idx..]
        .copy_from_slice(&private_key_bytes[private_key_bytes.len().saturating_sub(32)..]);

    let z_bytes = z.value().to_bytes_be();
    let mut z_32 = [0u8; 32];
    let z_start_idx = if z_bytes.len() < 32 {
        32 - z_bytes.len()
    } else {
        0
    };
    z_32[z_start_idx..].copy_from_slice(&z_bytes[z_bytes.len().saturating_sub(32)..]);

    // Step 1: Initialize K and V
    let mut k = vec![0u8; 32];
    let mut v = vec![1u8; 32];

    // Step 2: First HMAC round with 0x00
    let mut data = Vec::new();
    data.extend_from_slice(&v);
    data.push(0x00);
    data.extend_from_slice(&private_key_32);
    data.extend_from_slice(&z_32);

    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&data);
    k = hmac.finalize().into_bytes().to_vec();

    // Update V
    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&v);
    v = hmac.finalize().into_bytes().to_vec();

    // Step 3: Second HMAC round with 0x01
    let mut data = Vec::new();
    data.extend_from_slice(&v);
    data.push(0x01);
    data.extend_from_slice(&private_key_32);
    data.extend_from_slice(&z_32);

    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&data);
    k = hmac.finalize().into_bytes().to_vec();

    // Update V
    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&v);
    v = hmac.finalize().into_bytes().to_vec();

    // Step 4: Generate candidate k values until we find a valid one
    loop {
        // Generate V
        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&v);
        v = hmac.finalize().into_bytes().to_vec();

        // Convert V to BigUint
        let candidate = BigUint::from_bytes_be(&v);

        // Check if candidate is in valid range [1, n-1]
        if candidate >= BigUint::from(1u32) && candidate < *n {
            return Scalar::new(candidate);
        }

        // Update K and V for next iteration
        let mut data = Vec::new();
        data.extend_from_slice(&v);
        data.push(0x00);

        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&data);
        k = hmac.finalize().into_bytes().to_vec();

        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&v);
        v = hmac.finalize().into_bytes().to_vec();
    }
}

/// ECDSA signature using deterministic k generation (RFC 6979)
/// This ensures that the same message and private key always produce the same signature
pub fn sign(private_key: &PrivateKey, message_hash: &[u8]) -> Signature {
    // Write your implementation
    let z = Scalar::new(BigUint::from_bytes_be(message_hash));
    let k = deterministic_k(private_key, message_hash);

    let generator = Point::generator();
    let r_point = &generator * k.value().clone();
    let r_x = r_point.x()
        .as_ref()
        .expect("K*G should not be infinity")
        .num()
        .clone();
    let r = Scalar::new(r_x);
    let k_inv = k.inverse().expect("k must have inverse");
    let r_times_secret = &r * private_key.scalar();
    let z_plus_r_times_secret = &z + &r_times_secret;
    let s = &k_inv * &z_plus_r_times_secret;

    // BIP-62 low-S normalization: if s > n/2, use n - s instead.
    // Bitcoin's mempool rejects signatures with high S values.
    let n = &*SECP256K1_N;
    let half_n = n / BigUint::from(2u32);
    let s = if s.value() > &half_n {
        Scalar::new(n - s.value())
    } else {
        s
    };

    Signature { r, s }
}

pub fn verify(public_key: &PublicKey, message_hash: &[u8], signature: &Signature) -> bool {
    // Write your implementation

    let zero = BigUint::from(0u32);
    if signature.r.value() == &zero || signature.s.value() == &zero {
        return false;
    }

    let z = Scalar::new(BigUint::from_bytes_be(message_hash));
    let s_inv = match signature.s.inverse() {
        Some(inv) => inv,
        None => return false,
    };

    let u1 = &z * &s_inv;
    let u2 = &signature.r * &s_inv;

    let generator = Point::generator();
    let u1_g = &generator * u1.value().clone();
    let u2_q = public_key.point() * u2.value().clone();
    let point = &u1_g + &u2_q;

    if point.is_infinity() {
        return false;
    }
    let point_x = point.x()
        .as_ref()
        .expect("point is not infinity")
        .num()
        .clone();

    let point_x_mod_n = Scalar::new(point_x);
    &point_x_mod_n == &signature.r
}

impl Signature {
    /// Encode the signature in Distinguished Encoding Rules (DER) format
    /// 
    /// DER format for ECDSA signatures:
    /// SEQUENCE {
    ///   r INTEGER,
    ///   s INTEGER
    /// }
    pub fn to_der(&self) -> Vec<u8> {
        // Write your implementation
        let r_bytes = self.encode_integer(&self.r);
        let s_bytes = self.encode_integer(&self.s);

        let content_length = r_bytes.len() + s_bytes.len();

        let mut result = vec![0x30];
        // sequence marker
        result.extend(Self::length_to_bytes(content_length));
       
        result.extend(r_bytes);
        result.extend(s_bytes);
        result

    }

    /// Parse a DER-encoded signature
    /// 
    /// Returns None if the DER encoding is invalid
    pub fn from_der(der_bytes: &[u8]) -> Option<Self> {
        // Write your implementation
        if der_bytes.len() < 2 || der_bytes[0] != 0x30 {
            return None;
        }
        let (total_length, len_size) = Self::decode_length(&der_bytes[1..])?;
        let content_start = 1 + len_size;

        if der_bytes.len()< content_start + total_length {
            return None;
        } 

        // Decode r
        let r_slice = &der_bytes[content_start..];
        let (r_value, r_consumed) = Self::decode_integer(r_slice)?;
        let s_slice = &r_slice[r_consumed..];
        let (s_value, _s_consumed) = Self::decode_integer(s_slice)?;
        if r_consumed + _s_consumed != total_length { return None; }
        Some(Signature {
            r: Scalar::new(r_value),
            s: Scalar::new(s_value),
        })
    }

    /// (Optional) helper methods

    /// Encode a scalar as a DER INTEGER
    fn encode_integer(&self, scalar: &Scalar) -> Vec<u8> {
        // Write your implementation
        let mut bytes = scalar.value().to_bytes_be();
        while bytes.len() > 1 && bytes[0] == 0x00 { bytes.remove(0);}
        // if high hit is set, add 0x00 to indicate positve
        if bytes[0] >= 0x80 {
            bytes.insert(0, 0x00);
        }

        let mut result = vec![0x02];

        result.extend(Self::length_to_bytes(bytes.len()));
        result.extend(bytes);
        result
    }

    /// Convert length to minimal byte representation
    fn length_to_bytes(length: usize) -> Vec<u8> {
        // Write your implementation
        if length < 0x80 {
        vec![length as u8]               // Short form: just the byte
    } else {
        let bytes = length.to_be_bytes();
        let bytes: Vec<u8> = bytes.into_iter().skip_while(|&b| b == 0).collect();
        let mut result = vec![0x80 | bytes.len() as u8];  // Long form marker
        result.extend(bytes);
        result
    }

    }

    /// Decode DER length field
    /// Returns (length, bytes_consumed)
    fn decode_length(bytes: &[u8]) -> Option<(usize, usize)> {
        // Write your implementation
          if bytes.is_empty() {
        return None;
    }
    if bytes[0] < 0x80 {
        // Short form
        Some((bytes[0] as usize, 1))
    } else {
        // Long form
        let num_bytes = (bytes[0] & 0x7F) as usize;
        if bytes.len() < 1 + num_bytes {
            return None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | bytes[1 + i] as usize;
        }
        Some((length, 1 + num_bytes))

    }}

    /// Decode DER INTEGER
    /// Returns (value, bytes_consumed)
    fn decode_integer(bytes: &[u8]) -> Option<(BigUint, usize)> {
        // Write your implementation
        if bytes.len() < 2 || bytes[0] != 0x02 {
            return None;
        }

        let (length, len_size) = Signature::decode_length(&bytes[1..])?;
        let start = 1 + len_size;
        let end = start + length;

        if bytes.len() < end {
            return None;
        }
        let int_bytes = &bytes[start..end];
        if int_bytes.len() > 1 && int_bytes[0] == 0x00 && int_bytes[1] < 0x80 {
            return None;
        }
        let value = BigUint::from_bytes_be(int_bytes);
        Some((value, end))
    }
}
