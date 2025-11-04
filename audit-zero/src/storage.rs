use crate::{AzError, Result};
use ark_bn254::Fr;
use ark_std::collections::HashMap;

// min = storage key: 24 (ledgers) + 20 root version + 20 branch + 20 (leaf) = 84bit
// const EMPTY_KEY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#[inline]
pub fn index_key(ledger: u32) -> [u8; 16] {
    let mut empty = [0u8; 16];
    empty[0..4].copy_from_slice(&ledger.to_le_bytes());
    empty[0] = 1u8;
    empty
}

#[inline]
pub fn version_key(ledger: u32) -> [u8; 16] {
    let mut empty = [0u8; 16];
    empty[0..4].copy_from_slice(&ledger.to_le_bytes());
    empty[0] = 2u8;
    empty
}

#[inline]
pub fn root_key(ledger: u32, version: u32) -> [u8; 16] {
    let mut empty = [0u8; 16];
    empty[0..4].copy_from_slice(&ledger.to_le_bytes());
    empty[4..8].copy_from_slice(&version.to_le_bytes());
    empty
}

#[inline]
pub fn branch_key(ledger: u32, branch: u32) -> [u8; 16] {
    let mut empty = [0u8; 16];
    empty[0..4].copy_from_slice(&ledger.to_le_bytes());
    empty[8..12].copy_from_slice(&branch.to_le_bytes());
    empty
}

#[inline]
pub fn leaf_key(ledger: u32, index: u32) -> [u8; 16] {
    let mut empty = [0u8; 16];
    empty[0..4].copy_from_slice(&ledger.to_le_bytes());
    empty[12..16].copy_from_slice(&index.to_le_bytes());
    empty
}

/// Main Merkle Tree Storage
pub trait Storage {
    /// get stored commitment
    fn get(&self, key: &[u8]) -> Result<Fr>;

    /// add new merkle tree commitment
    fn set(&mut self, key: [u8; 16], value: Fr) -> Result<()>;
}

/// Memory storage for the Merkle Tree
#[derive(Default)]
pub struct MemoryStorage {
    values: HashMap<[u8; 16], Fr>,
}

impl Storage for MemoryStorage {
    fn get(&self, key: &[u8]) -> Result<Fr> {
        self.values
            .get(key)
            .cloned()
            .ok_or(AzError::MerkleTreeStorageMissing)
    }

    fn set(&mut self, key: [u8; 16], value: Fr) -> Result<()> {
        self.values.insert(key, value);
        Ok(())
    }
}
