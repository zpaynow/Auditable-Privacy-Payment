use crate::{
    AzError, Keypair, PublicKey, Result,
    audit_poseidon::{audit_decrypt_field_elements, audit_encrypt_field_elements},
    memo::{hybrid_decrypt, hybrid_encrypt},
    poseidon::{poseidon_hash, poseidon_merge_hash},
    storage::*,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{
    UniformRand, Zero,
    collections::HashMap,
    rand::{CryptoRng, Rng},
};

pub type Asset = u64;

pub type Amount = u128;

pub type Commitment = Fr;

pub type Nullifier = Fr;

pub type Blind = Fr;

/// Pack asset (u64) and amount (u128) into a single field element
/// Layout: [asset (64 bits) || amount (128 bits)] = 192 bits total < 254 bits (Fr)
pub fn pack_asset_amount(asset: Asset, amount: Amount) -> Fr {
    // Compute: asset * 2^128 + amount
    let asset_fr = Fr::from(asset);
    let amount_fr = Fr::from(amount);
    let shift = Fr::from(2u128).pow([128]); // 2^128

    asset_fr * shift + amount_fr
}

/// Unpack asset (u64) and amount (u128) from a single field element
pub fn unpack_asset_amount(packed: Fr) -> (Asset, Amount) {
    let packed_bigint = packed.into_bigint();

    // Extract lower 128 bits for amount
    // BigInt is little-endian, so first two u64 limbs contain the lower 128 bits
    let amount_low = packed_bigint.as_ref()[0];
    let amount_high = packed_bigint.as_ref()[1];
    let amount = (amount_high as u128) << 64 | (amount_low as u128);

    // Extract upper bits for asset by computing: asset = (packed - amount) / 2^128
    let amount_fr = Fr::from(amount);
    let remainder = packed - amount_fr;
    let shift = Fr::from(2u128).pow([128]); // 2^128
    let asset_fr = remainder / shift;

    // Convert to u64
    let asset = asset_fr.into_bigint().as_ref()[0] as u64;

    (asset, amount)
}

#[derive(Clone)]
pub struct OpenCommitment {
    /// asset id
    pub asset: Asset,
    /// amount
    pub amount: Amount,
    /// owner public key
    pub owner: PublicKey,
    /// blind
    pub blind: Blind,
}

impl OpenCommitment {
    pub fn generate<R: CryptoRng + Rng>(
        prng: &mut R,
        asset: Asset,
        amount: Amount,
        owner: PublicKey,
    ) -> Self {
        let blind = Fr::rand(prng);
        Self {
            asset,
            amount,
            owner,
            blind,
        }
    }

    pub fn commit(&self) -> Commitment {
        let inputs = [
            Fr::from(self.asset),
            Fr::from(self.amount),
            self.blind,
            self.owner.x,
            self.owner.y,
        ];

        poseidon_hash(&inputs)
    }

    pub fn nullify(&self, keypair: &Keypair) -> Nullifier {
        poseidon_hash(&[self.commit(), keypair.secret_to_fq()])
    }

    pub fn freeze(&self) -> Nullifier {
        poseidon_hash(&[self.commit(), self.owner.x])
    }

    /// encrypt the memo for receiver
    pub fn memo_encrypt<R: CryptoRng + Rng>(&self, prng: &mut R) -> Result<Vec<u8>> {
        let mut ptext = vec![];
        ptext.extend(self.asset.to_le_bytes());
        ptext.extend(self.amount.to_le_bytes());
        ptext.extend(self.blind.into_bigint().to_bytes_le());

        hybrid_encrypt(prng, &self.owner, &ptext)
    }

    /// decrypt the memo by receiver
    pub fn memo_decrypt(keypair: &Keypair, comm: &Commitment, bytes: &[u8]) -> Result<Self> {
        let ptext = hybrid_decrypt(keypair, bytes)?;
        if ptext.len() < 56 {
            return Err(AzError::Decryption);
        }

        let mut asset_bytes = [0u8; 8];
        asset_bytes.copy_from_slice(&ptext[..8]);
        let asset = Asset::from_le_bytes(asset_bytes);

        let mut amount_bytes = [0u8; 16];
        amount_bytes.copy_from_slice(&ptext[8..24]);
        let amount = Amount::from_le_bytes(amount_bytes);

        let blind = Blind::from_le_bytes_mod_order(&ptext[24..56]);

        let open_comm = OpenCommitment {
            asset,
            amount,
            blind,
            owner: keypair.public,
        };

        if &open_comm.commit() != comm {
            return Err(AzError::Decryption);
        }

        Ok(open_comm)
    }

    /// Encrypt audit data using field-element-based encryption (circuit-compatible)
    ///
    /// Returns: (ciphertext_bytes, ephemeral_secret_fr)
    /// Ciphertext format: ephemeral_pk (64 bytes) || ciphertexts (3 × 32 bytes = 96 bytes)
    /// Field elements: [asset_amount_packed, owner_x, owner_y]
    pub fn audit_encrypt<R: CryptoRng + Rng>(
        &self,
        prng: &mut R,
        auditor: &PublicKey,
    ) -> Result<(Vec<u8>, Fr)> {
        // Pack asset and amount into single field element (192 bits < 254 bits)
        let asset_amount_packed = pack_asset_amount(self.asset, self.amount);
        let owner_x_fr = self.owner.x;
        let owner_y_fr = self.owner.y;

        let field_elements = vec![asset_amount_packed, owner_x_fr, owner_y_fr];

        audit_encrypt_field_elements(prng, auditor, &field_elements)
    }

    /// Decrypt audit data using field-element-based decryption (circuit-compatible)
    pub fn audit_decrypt(auditor: &Keypair, _comm: &Commitment, bytes: &[u8]) -> Result<Self> {
        // Decrypt field elements: [asset_amount_packed, owner_x, owner_y]
        let field_elements = audit_decrypt_field_elements(auditor, bytes)?;

        if field_elements.len() != 3 {
            return Err(AzError::Decryption);
        }

        let asset_amount_packed = field_elements[0];
        let owner_x = field_elements[1];
        let owner_y = field_elements[2];

        // Unpack asset and amount from single field element
        let (asset, amount) = unpack_asset_amount(asset_amount_packed);

        let open_comm = OpenCommitment {
            asset,
            amount,
            blind: Fr::zero(),
            owner: PublicKey {
                x: owner_x,
                y: owner_y,
            },
        };

        Ok(open_comm)
    }
}

// 2^20 = 1048576, parallel max version 2^20 = 1048576, max ledgers 2^24 = 16777216
// 20 + 20 + 24 = 64, so u64 is enough for represent: ledger index, left index, root version
pub const TREE_DEPTH: usize = 20;
const ROOT_AS_PARENT: u32 = 2097150; // 2^20 + 2^19 + 2^18 + ..2^1

/// MerkleTree is a 3-ary merkle tree
pub struct MerkleTree<S: Storage> {
    ledger: u32,
    current_root: Fr,
    current_version: u32,
    current_index: u32,
    storage: S,
    cache: HashMap<[u8; 16], Fr>,
}

/// PersistentMerkleTree Proof.
#[derive(Clone)]
pub struct MTProof {
    /// proof nodes, from lower(leaf) to upper.
    pub nodes: Vec<MTNode>,
    /// current ledger
    pub ledger: u32,
    /// current root.
    pub root: Fr,
    /// current root version.
    pub version: u32,
    /// leaf's uid.
    pub index: u32,
}

impl MTProof {
    /// check the merkle proof is right
    pub fn verify(&self) -> bool {
        for (i, node) in self.nodes.iter().enumerate() {
            let parent = poseidon_merge_hash(node.left, node.right);
            if i < TREE_DEPTH - 1 {
                if self.nodes[i + 1].left != parent && self.nodes[i + 1].right != parent {
                    return false;
                }
            } else {
                return self.root == parent;
            }
        }

        false
    }
}

/// PersistentMerkleTree Proof Node, 3-ary merkle tree,
/// so every leaf has two siblings and own position.
#[derive(Clone, Debug)]
pub struct MTNode {
    /// left.
    pub left: Fr,
    /// right.
    pub right: Fr,
}

impl<S: Storage> MerkleTree<S> {
    #[inline]
    fn fetch_comm(&self, key: &[u8]) -> Fr {
        if let Some(comm) = self.cache.get(key) {
            *comm
        } else {
            self.storage.get(key).unwrap_or(Fr::zero())
        }
    }

    /// Generates a new MerkleTree by ledger index
    pub fn new(ledger: u32, storage: S) -> Result<MerkleTree<S>> {
        let current_version = storage
            .get(&version_key(ledger))
            .map(simple_fr_to_u32)
            .unwrap_or(0);
        let current_index = storage
            .get(&index_key(ledger))
            .map(simple_fr_to_u32)
            .unwrap_or(0);
        let current_root = storage
            .get(&root_key(ledger, current_version))
            .unwrap_or(Fr::zero());

        Ok(MerkleTree {
            ledger,
            current_version,
            current_index,
            current_root,
            storage,
            cache: HashMap::new(),
        })
    }

    /// add a new leaf and return the leaf uid.
    pub fn add_leaf(&mut self, leaf: Fr) -> Result<u32> {
        // 0. use next index as the leaf index
        let current_index = self.current_index;

        // 1. generate leaf and branches index
        let keys = get_path_keys(current_index);

        // 2. save leaf firstly
        self.cache
            .insert(leaf_key(self.ledger, current_index), leaf);

        // 3. calc the leaf hash
        let (leaf1_index, leaf2_index, parent_index) = keys.first().unwrap(); // safe unwrap
        let leaf1 = self.fetch_comm(&leaf_key(self.ledger, *leaf1_index));
        let leaf2 = self.fetch_comm(&leaf_key(self.ledger, *leaf2_index));

        self.cache
            .insert(leaf_key(self.ledger, *leaf1_index), leaf1);
        self.cache
            .insert(leaf_key(self.ledger, *leaf2_index), leaf2);

        let parent = poseidon_merge_hash(leaf1, leaf2);
        self.cache
            .insert(branch_key(self.ledger, *parent_index), parent);

        // 3. update all branches
        for (left_index, right_index, parent_index) in &keys[1..] {
            let left = self.fetch_comm(&branch_key(self.ledger, *left_index));
            let right = self.fetch_comm(&branch_key(self.ledger, *right_index));
            self.cache
                .insert(branch_key(self.ledger, *left_index), left);
            self.cache
                .insert(branch_key(self.ledger, *right_index), right);

            let parent = poseidon_merge_hash(left, right);
            if *parent_index == ROOT_AS_PARENT {
                self.current_root = parent;
            } else {
                self.cache
                    .insert(branch_key(self.ledger, *parent_index), parent);
            }
        }

        self.current_index += 1;
        Ok(current_index)
    }

    /// commit to store and add the tree version.
    pub fn commit(&mut self) -> Result<u32> {
        for (key, value) in self.cache.drain() {
            self.storage.set(key, value)?;
        }

        self.current_version += 1;
        self.storage.set(
            root_key(self.ledger, self.current_version),
            self.current_root,
        )?;

        self.storage
            .set(index_key(self.ledger), simple_u32_to_fr(self.current_index))?;
        self.storage.set(
            version_key(self.ledger),
            simple_u32_to_fr(self.current_version),
        )?;

        Ok(self.current_version)
    }

    /// get leaf hash by index
    pub fn get_leaf(&self, index: u32) -> Result<Fr> {
        let key = leaf_key(self.ledger, index);
        if let Some(comm) = self.cache.get(&key) {
            Ok(*comm)
        } else {
            self.storage.get(&key)
        }
    }

    /// get tree current root
    pub fn get_root(&self) -> Result<Fr> {
        Ok(self.current_root)
    }

    /// get tree root by version.
    pub fn get_root_with_version(&self, version: u32) -> Result<Fr> {
        if version == 0 {
            return Ok(Fr::zero());
        }

        self.storage.get(&root_key(self.ledger, version))
    }

    /// get the tree version
    pub fn get_version(&self) -> u32 {
        self.current_version
    }

    /// get the number of entries
    pub fn get_count(&self) -> u32 {
        self.current_index
    }

    /// generate leaf's merkle proof by index.
    pub fn generate_proof(&self, index: u32) -> Result<MTProof> {
        let keys = get_path_keys(index);

        let mut nodes: Vec<MTNode> = vec![];

        let (leaf1_index, leaf2_index, _) = keys.first().unwrap(); // safe unwrap
        let left = self
            .storage
            .get(&leaf_key(self.ledger, *leaf1_index))
            .unwrap_or(Fr::zero());
        let right = self
            .storage
            .get(&leaf_key(self.ledger, *leaf2_index))
            .unwrap_or(Fr::zero());
        nodes.push(MTNode { left, right });

        for (left_index, right_index, _) in &keys[1..] {
            let left = self.storage.get(&branch_key(self.ledger, *left_index))?;
            let right = self.storage.get(&branch_key(self.ledger, *right_index))?;
            nodes.push(MTNode { left, right });
        }

        let root = self.get_root_with_version(self.current_version)?;

        Ok(MTProof {
            nodes,
            ledger: self.ledger,
            root,
            version: self.current_version,
            index,
        })
    }
}

fn get_path_keys(mut index: u32) -> Vec<(u32, u32, u32)> {
    let mut keys = vec![];

    let mut parent_acc_pow = 0;
    for i in 0..TREE_DEPTH {
        let current = index + parent_acc_pow;
        let parent_index = index >> 1;
        parent_acc_pow += 1 << (20 - i);
        let parent = parent_index + parent_acc_pow;

        if index & 1 == 0 {
            keys.push((current, current + 1, parent));
        } else {
            keys.push((current - 1, current, parent));
        }
        index = parent_index;
    }
    keys
}

fn simple_fr_to_u32(f: Fr) -> u32 {
    let bigint = f.into_bigint();
    bigint.as_ref()[0] as u32
}

fn simple_u32_to_fr(i: u32) -> Fr {
    Fr::from(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_merkle_tree() {
        let rng = &mut ChaCha20Rng::from_seed([1u8; 32]);

        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        for _ in 0..10 {
            merkle.add_leaf(Fr::rand(rng)).unwrap();
        }
        merkle.commit().unwrap();

        let proof1 = merkle.generate_proof(0).unwrap();
        assert!(proof1.verify());

        let proof2 = merkle.generate_proof(5).unwrap();
        assert!(proof2.verify());

        let proof3 = merkle.generate_proof(9).unwrap();
        assert!(proof3.verify());
    }

    #[test]
    fn test_pack_unpack_asset_amount() {
        // Test edge cases
        let test_cases = vec![
            (0u64, 0u128),
            (1u64, 1u128),
            (u64::MAX, 0u128),
            (0u64, u128::MAX),
            (u64::MAX, u128::MAX),
            (12345u64, 67890u128),
            (1u64, 1_000_000_000_000_000u128), // 1 quadrillion
        ];

        for (asset, amount) in test_cases {
            let packed = pack_asset_amount(asset, amount);
            let (unpacked_asset, unpacked_amount) = unpack_asset_amount(packed);

            assert_eq!(
                asset, unpacked_asset,
                "Asset mismatch for ({}, {})",
                asset, amount
            );
            assert_eq!(
                amount, unpacked_amount,
                "Amount mismatch for ({}, {})",
                asset, amount
            );
        }
    }

    #[test]
    fn test_memo() {
        let rng = &mut ChaCha20Rng::from_seed([2u8; 32]);

        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;

        let open_comm = OpenCommitment::generate(rng, asset, amount, keypair.public);
        let comm = open_comm.commit();
        let memo = open_comm.memo_encrypt(rng).unwrap();

        let open_comm2 = OpenCommitment::memo_decrypt(&keypair, &comm, &memo).unwrap();
        assert_eq!(open_comm.asset, open_comm2.asset);
        assert_eq!(open_comm.amount, open_comm2.amount);
        assert_eq!(open_comm.blind, open_comm2.blind);
    }

    #[test]
    fn test_audit() {
        let rng = &mut ChaCha20Rng::from_seed([2u8; 32]);

        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;

        let auditor = Keypair::generate(rng);

        let open_comm = OpenCommitment::generate(rng, asset, amount, keypair.public);
        let comm = open_comm.commit();
        let (memo, _) = open_comm.audit_encrypt(rng, &auditor.public).unwrap();

        let open_comm2 = OpenCommitment::audit_decrypt(&auditor, &comm, &memo).unwrap();
        assert_eq!(open_comm.asset, open_comm2.asset);
        assert_eq!(open_comm.amount, open_comm2.amount);
        assert_eq!(open_comm.owner, open_comm2.owner);
    }
}
