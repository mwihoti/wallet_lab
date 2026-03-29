use std::io::Read;
use crate::utils::varint::{encode_varint, decode_varint};
#[derive(Clone, Debug, PartialEq)]

pub struct TxInput {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32
}

impl TxInput {
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // parse prev_tx_id (32 bytes)
        let mut prev_tx_id = [0u8; 32];
        reader.read_exact(&mut prev_tx_id)?;
        // parse prev_index (4 bytes, little-endian)
        let mut index_bytes = [0u8; 4];
        reader.read_exact(&mut index_bytes)?;
        let prev_index = u32::from_le_bytes(index_bytes);

        // parse script_sig length 
        let script_len = decode_varint(&mut reader)?;
        let mut script_sig = vec![0u8; script_len as usize];
        reader.read_exact(&mut script_sig)?;
        // parse sequence ( 4 bytes, little-endian)
        let mut sequence_bytes = [0u8; 4];
        reader.read_exact(&mut sequence_bytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);

        Ok(Self {
            prev_tx_id,
            prev_index,
            script_sig,
            sequence
        })
            
        
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // serialize prev_tx_id
        bytes.extend_from_slice(&self.prev_tx_id);
        // serialize prev_index
        bytes.extend_from_slice(&self.prev_index.to_le_bytes());
        bytes.extend(encode_varint(self.script_sig.len() as u64));
        // serialize script_sig length
        bytes.extend(&self.script_sig);
        // serialize sequence 
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes        
    }

}