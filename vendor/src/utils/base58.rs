use crate::utils::hash256::hash256;
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encodes a byte array into Base58 format
/// Base58 is used in Bitcoin to encode addresses and other data
/// It uses an alphabet that excludes confusing characters (0, O, I, l)
pub fn encode_base58(input: &[u8]) -> String {
    // Write your implementation
    if input.is_empty() {
        return String::new();
    }

    // count leading zeros
    let mut zeros = 0;
    while zeros < input.len() && input[zeros] == 0 {
        zeros += 1;
    }
    let mut digits = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for digit in &mut digits {
            let res = {*digit as u32} * 256 + carry;
            *digit = (res % 58) as u8;
            carry = res / 58;
        }

        while carry > 0 {

            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    // build the string
    let mut result = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        result.push('1');
    }
    for digit in digits.iter().rev() {
        result.push(ALPHABET[*digit as usize] as char);

    }
    result

}

/// Decodes a Base58 encoded string back to bytes
/// Returns an error if the input contains invalid Base58 characters
pub fn decode_base58(input: &str) -> Result<Vec<u8>, &'static str> {
    // Write your implementation
    if input.is_empty() {
        return Ok(Vec::new());

    }
    let mut zeros = 0;

    let bytes = input.as_bytes();
    while zeros < bytes.len() && bytes[zeros] == b'1' {
        zeros += 1;
    } 
    // convert from base-58
    let mut decoded = Vec::with_capacity(input.len());
    for &byte in &bytes[zeros..] {
        let mut carry = match ALPHABET.iter().position(|&c| c == byte) {
            Some(idx) => idx as u32,
            None => return Err("Invalid character: not in Base58 alphabet"),
        };

        for b in &mut decoded {
            let res = (*b as u32) * 58 + carry;
            *b = (res % 256) as u8;
            carry = res / 256;
        }

        while carry > 0 {
            decoded.push((carry % 256) as u8);
            carry /= 256;
        }
    }

    let mut result = vec![0u8; zeros];
    result.extend(decoded.iter().rev());
    Ok(result)
}

/// Encodes a byte array into Base58Check format
/// Base58Check adds a 4-byte checksum to the data before encoding
/// This is used in Bitcoin for addresses, private keys, and other critical data
/// The checksum is the first 4 bytes of SHA256(SHA256(data))
pub fn encode_base58_check(input: &[u8]) -> String {
    // Write your implementation
    if input.is_empty() {
        return String::new();
    }
    let checksum = &hash256(input)[..4];
    let mut data = Vec::with_capacity(input.len() + 4);
    data.extend_from_slice(input);
    data.extend_from_slice(checksum);
    encode_base58(&data)

}

/// Decodes a Base58Check encoded string back to the original data
/// Base58Check includes a 4-byte checksum that is verified during decoding
/// Returns an error if the input is invalid or the checksum doesn't match
pub fn decode_base58_check(input: &str) -> Result<Vec<u8>, &'static str> {
    // Write your implementation
    let decoded = decode_base58(input)?;
    if decoded.is_empty() {
        return Ok(Vec::new());
    }
    if decoded.len() < 4 {
        return Err("Base58Check data too short: must be at least 4 bytes");
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected_checksum = &hash256(payload)[..4];
    if checksum != expected_checksum {
        return Err("Base58Check checksum verification failed");
    }
    Ok(payload.to_vec())
    
}
