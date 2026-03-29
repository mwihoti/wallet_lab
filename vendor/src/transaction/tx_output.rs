use std::io::Read;
use crate::utils::varint::decode_varint;
use crate::utils::varint::encode_varint;

#[derive(Clone, Debug, PartialEq)]
pub struct TxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8> // Store the script_pubkey as a Vec<u8> for now, we will parse it in a later track
}

impl TxOutput {
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Write your implementation
        let mut amount_bytes = [0u8; 8];
        reader.read_exact(&mut amount_bytes)?;
        let amount = u64::from_le_bytes(amount_bytes);

        let script_len = decode_varint(&mut reader)?;
        let mut script_pubkey = vec![0u8; script_len as usize];
        reader.read_exact(&mut script_pubkey)?;
        Ok(Self {
            amount,
            script_pubkey,
        })
    }

     pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // serialize amount (8bytes, little-endian)
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        // serialize script_pubkey length
        bytes.extend(encode_varint(self.script_pubkey.len() as u64));
        // serialize script_pubkey bytes
        bytes.extend(&self.script_pubkey);
        bytes
    }
}