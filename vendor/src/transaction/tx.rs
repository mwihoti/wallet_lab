use std::io::Read;
use super::tx_input::TxInput;
use crate::utils::varint::{decode_varint, encode_varint};
use super::tx_output::TxOutput;
use crate::utils::hash256::hash256;
#[derive(Clone, Debug, PartialEq)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxInput>,
    pub tx_outs: Vec<TxOutput>,
    pub locktime: u32,
}

impl Tx {
    pub fn new(version: u32, tx_ins: Vec<TxInput>, tx_outs: Vec<TxOutput>, locktime: u32 ) -> Self {
        Self {
            version,
            tx_ins,
            tx_outs,
            locktime,
        }
    }

    // Parse the first 4 bytes of a transaction and interpret them as a little-endian 32-bit integer.
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Write your implementation
        // create a 4 byte buffer
        let mut version_bytes = [0u8; 4];

        // read exactly 4 bytes from the reader in to the buffer
        reader.read_exact(&mut version_bytes)?;

        // interpret the 4 bytes as 32-bit little-endian integer
        let version = u32::from_le_bytes(version_bytes);
        let num_inputs = decode_varint(&mut reader)?;

        let mut tx_ins = Vec::new();
        for _ in 0..num_inputs {
            tx_ins.push(TxInput::parse(&mut reader)?);
        }
        let num_outputs = decode_varint(&mut reader)?;
        let mut tx_outs = Vec::new();
        for _ in 0..num_outputs {
            tx_outs.push(TxOutput::parse(&mut reader)?);
        }

        // parse locktime (4 bytes, little-endian)
        
        let mut locktime_bytes = [0u8; 4];
        reader.read_exact(&mut locktime_bytes)?;
        let locktime = u32::from_le_bytes(locktime_bytes);

        Ok(Self::new(version, tx_ins, tx_outs, locktime))

    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // serialize version
        bytes.extend_from_slice(&self.version.to_le_bytes());
        // Input count + Each input
        bytes.extend(encode_varint(self.tx_ins.len() as u64));
        for tx_in in &self.tx_ins {
            bytes.extend(tx_in.serialize());
        }
        // outputs count + each output
        bytes.extend(encode_varint(self.tx_outs.len() as u64));
        for tx_out in &self.tx_outs {
            bytes.extend(tx_out.serialize());
        }
        // serialize locktime
        bytes.extend_from_slice(&self.locktime.to_le_bytes());
        bytes
    }
     pub fn id(&self) -> String { // little endian
        // Write your implementation
        let hash_bytes = self.hash();
        hex::encode(hash_bytes)
    }

    fn hash(&self) -> Vec<u8> {
        // Write your implementation
        let serialized = self.serialize();
        hash256(&serialized).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn print_tx_version() {
        let raw_tx_bytes = vec![
            0x01, 0x00, 0x00, 0x00, // Version 1
            0x00,                   // 0 inputs
            0x00,                   // 0 outputs
            0x00, 0x00, 0x00, 0x00  // Locktime 0
        ];
        
        let cursor = Cursor::new(raw_tx_bytes);
        let result = Tx::parse(cursor).unwrap();
        println!("\n=================================================");
        println!("Successfully parsed FULL Transaction!");
        println!("Transaction ID: {}", result.id()); // NEW: Show the ID!
        println!("Version: {}", result.version);
        println!("Inputs: {}", result.tx_ins.len());
        println!("Outputs: {}", result.tx_outs.len());
        println!("Locktime: {}", result.locktime);
        println!("=================================================\n");
    }

}
