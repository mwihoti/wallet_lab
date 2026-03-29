use std::io::{Read, Error};
/// Variable-length integer encoding and decoding functions
/// 
/// Varints encode integers from 0 to 2^64 - 1 using variable-length encoding:
/// - 0x00 to 0xFC: stored as single byte
/// - 0xFD: followed by 2-byte little-endian value (253 to 65535)
/// - 0xFE: followed by 4-byte little-endian value (65536 to 4294967295)
/// - 0xFF: followed by 8-byte little-endian value (4294967296 to 18446744073709551615)
/// Encode a u64 value as a varint
pub fn encode_varint(value: u64) -> Vec<u8> {
    // Write your implementation
    if value < 0xFd {
        vec![value as u8]
    }

    else if value <= 0xFFFF {
        let mut buf = vec![0xFD];

        buf.extend_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value <= 0xFFFFFFFF {
        let mut buf = vec![0xFE];
        buf.extend_from_slice(&(value as u32).to_le_bytes());
        buf
    }
    else {
        let mut buf = vec![0xFF];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    
    }
}

/// Reads a varint from a reader
pub fn decode_varint<R: Read>(reader: &mut R) -> Result<u64, Error> {
    // Write your implementation

    let mut prefix = [0u8; 1];

    reader.read_exact(&mut prefix)?;
    match prefix[0] {
        0..=0xFC => Ok(prefix[0] as u64),

        0xFD => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            let val = u16::from_le_bytes(buf) as u64;

            if val < 0xFD {
                return Err(Error::new(std::io::ErrorKind::InvalidData, "non-canonical varint"));
                
            }
           Ok(val)
        }

        0xFE => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            let val = u32::from_le_bytes(buf) as u64;

            if val <= 0xFFFF {
                return Err(Error::new(std::io::ErrorKind::InvalidData, "non-canonical varint"));
            }
            Ok(val)
        }

        0xFF => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            let val = u64::from_le_bytes(buf);
            if val <= 0xFFFFFFFF {
                return Err(Error::new(std::io::ErrorKind::InvalidData, "non-cannonical varint"));
            }
            Ok(val)
        }
    }
}

/// Get the encoded length of a varint for a given value
pub fn varint_length(value: u64) -> usize {
    // Write your implementation
    if value < 0xFD {
        1
    } else if value <= 0xFFFF {
        3 // 1 marker byte  + 2 data bytes

    } else if value <= 0xFFFFFFFF {
        5
    } else {
        9 // 1 marker byte + 8 data bytes
    }
}