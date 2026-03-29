#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressType {
    /// Legacy Pay-to-Public-Key-Hash (mainnet: 1..., testnet: m/n...)
    P2PKH,
    /// Nested SegWit: P2SH wrapping P2WPKH (mainnet: 3..., testnet: 2...)
    P2SHP2WPKH,
    /// Native SegWit: Pay-to-Witness-Public-Key-Hash, bech32 (mainnet: bc1q..., testnet: tb1q...)
    P2WPKH,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    /// Version byte for P2PKH addresses (base58check prefix)
    pub fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Regtest => 0x6F,
        }
    }

    /// Version byte for P2SH addresses (base58check prefix)
    pub fn p2sh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Regtest => 0xC4,
        }
    }

    /// Version byte for WIF private keys
    pub fn wif_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet | Network::Regtest => 0xEF,
        }
    }

    /// Human-readable part for bech32 native SegWit addresses
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Regtest => "tb",
        }
    }
}
