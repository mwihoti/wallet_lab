use bitcoin_dojo::utils::varint::{decode_varint, encode_varint, varint_length};
use std::io::Cursor;

#[test]
fn test_encode_single_byte() {
    assert_eq!(encode_varint(0), vec![0x00]);
    assert_eq!(encode_varint(252), vec![0xFC]);
}

#[test]
fn test_encode_two_byte() {
    assert_eq!(encode_varint(253), vec![0xFD, 0xFD, 0x00]);
    assert_eq!(encode_varint(255), vec![0xFD, 0xFF, 0x00]);
    assert_eq!(encode_varint(65535), vec![0xFD, 0xFF, 0xFF]);
}

#[test]
fn test_encode_four_byte() {
    assert_eq!(encode_varint(65536), vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(
        encode_varint(4294967295),
        vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]
    );
}

#[test]
fn test_encode_eight_byte() {
    assert_eq!(
        encode_varint(4294967296),
        vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        encode_varint(18446744073709551615),
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
}

#[test]
fn test_decode_single_byte() {
    let mut cursor = Cursor::new(&[0x00]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 0);
    let mut cursor = Cursor::new(&[0xFC]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 252);
}

#[test]
fn test_decode_two_byte() {
    let mut cursor = Cursor::new(&[0xFD, 0xFD, 0x00]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 253);
    let mut cursor = Cursor::new(&[0xFD, 0xFF, 0x00]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 255);
    let mut cursor = Cursor::new(&[0xFD, 0xFF, 0xFF]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 65535);
}

#[test]
fn test_decode_four_byte() {
    let mut cursor = Cursor::new(&[0xFE, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 65536);
    let mut cursor = Cursor::new(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 4294967295);
}

#[test]
fn test_decode_eight_byte() {
    let mut cursor = Cursor::new(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 4294967296);
    let mut cursor = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(decode_varint(&mut cursor).unwrap(), 18446744073709551615);
}

#[test]
fn test_decode_errors() {
    // Empty slice
    let mut cursor = Cursor::new(&[]);
    assert!(decode_varint(&mut cursor).is_err());

    // Insufficient bytes for 2-byte varint
    let mut cursor = Cursor::new(&[0xFD]);
    assert!(decode_varint(&mut cursor).is_err());
    let mut cursor = Cursor::new(&[0xFD, 0x01]);
    assert!(decode_varint(&mut cursor).is_err());

    // Insufficient bytes for 4-byte varint
    let mut cursor = Cursor::new(&[0xFE]);
    assert!(decode_varint(&mut cursor).is_err());
    let mut cursor = Cursor::new(&[0xFE, 0x01, 0x02, 0x03]);
    assert!(decode_varint(&mut cursor).is_err());

    // Insufficient bytes for 8-byte varint
    let mut cursor = Cursor::new(&[0xFF]);
    assert!(decode_varint(&mut cursor).is_err());
    let mut cursor = Cursor::new(&[0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    assert!(decode_varint(&mut cursor).is_err());
}

#[test]
fn test_non_canonical_encoding() {
    // Value 252 encoded as 2-byte (should be single byte)
    let mut cursor = Cursor::new(&[0xFD, 0xFC, 0x00]);
    assert!(decode_varint(&mut cursor).is_err());

    // Value 65535 encoded as 4-byte (should be 2-byte)
    let mut cursor = Cursor::new(&[0xFE, 0xFF, 0xFF, 0x00, 0x00]);
    assert!(decode_varint(&mut cursor).is_err());

    // Value 4294967295 encoded as 8-byte (should be 4-byte)
    let mut cursor = Cursor::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    assert!(decode_varint(&mut cursor).is_err());
}

#[test]
fn test_varint_length() {
    assert_eq!(varint_length(0), 1);
    assert_eq!(varint_length(252), 1);
    assert_eq!(varint_length(253), 3);
    assert_eq!(varint_length(65535), 3);
    assert_eq!(varint_length(65536), 5);
    assert_eq!(varint_length(4294967295), 5);
    assert_eq!(varint_length(4294967296), 9);
    assert_eq!(varint_length(18446744073709551615), 9);
}

#[test]
fn test_encode_decode_roundtrip() {
    let test_values = vec![
        0,
        1,
        252,
        253,
        254,
        255,
        256,
        65535,
        65536,
        4294967295,
        4294967296,
        18446744073709551615,
    ];

    for value in test_values {
        let encoded = encode_varint(value);
        let mut cursor = Cursor::new(&encoded);
        let decoded = decode_varint(&mut cursor).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(cursor.position() as usize, encoded.len());
        assert_eq!(cursor.position() as usize, varint_length(value));
    }
}
