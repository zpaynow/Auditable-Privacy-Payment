/// Main Result
pub type Result<T> = core::result::Result<T, AzError>;

/// Main error types in audit zero
#[derive(Debug)]
pub enum AzError {
    MerkleTreeStorageMissing,
    MerkleTreeStorageError,
    MerkleTreeProof,
}
