//! Bech32 encoding/decoding for native SegWit addresses (BIP 173).

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5 {
            if (b >> i) & 1 != 0 {
                chk ^= GEN[i];
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for b in hrp.bytes() { out.push(b >> 5); }
    out.push(0);
    for b in hrp.bytes() { out.push(b & 31); }
    out
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut v = hrp_expand(hrp);
    v.extend_from_slice(data);
    v.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&v) ^ 1;
    let mut cs = [0u8; 6];
    for i in 0..6 {
        cs[i] = ((pm >> (5 * (5 - i))) & 31) as u8;
    }
    cs
}

/// Convert between bit widths (e.g. 8-bit bytes → 5-bit groups).
fn convertbits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    let maxv = (1u32 << to) - 1;
    for &value in data {
        let v = value as u32;
        if v >> from != 0 { return None; }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

fn charset_rev(c: char) -> Option<u8> {
    CHARSET.iter().position(|&b| b as char == c).map(|i| i as u8)
}

/// Bech32-encode a witness program.
///
/// - `hrp`: human-readable part ("bc" mainnet, "tb" testnet)
/// - `witness_version`: 0 for P2WPKH / P2WSH
/// - `program`: the witness program (20 bytes for P2WPKH)
pub fn encode(hrp: &str, witness_version: u8, program: &[u8]) -> String {
    let mut data = vec![witness_version];
    data.extend(convertbits(program, 8, 5, true).unwrap());
    let checksum = create_checksum(hrp, &data);
    let mut out = format!("{}1", hrp);
    for b in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[*b as usize] as char);
    }
    out
}

/// Decode a bech32 address.
///
/// Returns `(witness_version, program_bytes)` or `None` on any error.
pub fn decode(hrp: &str, addr: &str) -> Option<(u8, Vec<u8>)> {
    let lower = addr.to_lowercase();
    let sep = lower.rfind('1')?;
    if sep < 1 || sep + 7 > lower.len() { return None; }
    if &lower[..sep] != hrp { return None; }

    let values: Option<Vec<u8>> = lower[sep + 1..].chars().map(charset_rev).collect();
    let values = values?;

    // Verify checksum
    let mut v = hrp_expand(hrp);
    v.extend_from_slice(&values);
    if polymod(&v) != 1 { return None; }

    let (version, data) = (values[0], &values[1..values.len() - 6]);
    let program = convertbits(data, 5, 8, false)?;
    Some((version, program))
}
