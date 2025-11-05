use crate::{
    Keypair, PublicKey, Result,
    poseidon::{poseidon_hash, poseidon_merge_hash},
    storage::*,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{Zero, collections::HashMap};

pub type Asset = u64;

pub type Amount = u128;

pub type Commitment = Fr;

pub type Nullifier = Fr;

pub type Blind = Fr;

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
    /// memo for owner
    pub memo: Option<OpenMemo>,
    /// audit for auditor
    pub audit: Option<OpenAudit>,
}

impl OpenCommitment {
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
        let comm = self.commit();

        let bytes = keypair.secret.into_bigint().to_bytes_le();
        let sk = Fr::from_le_bytes_mod_order(&bytes); // TODO splite two

        let inputs = [
            comm,
            Fr::from(self.asset),
            Fr::from(self.amount),
            keypair.public.x,
            keypair.public.y,
            sk,
        ];

        poseidon_hash(&inputs)
    }
}

#[derive(Clone)]
pub struct OpenMemo {
    pub asset: Asset,
    pub amount: Amount,
}

#[derive(Clone)]
pub struct OpenAudit {
    pub asset: Asset,
    // TODO only show the amount range
    pub amount: Amount,
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
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_merkle_tree() {
        let rng = &mut test_rng();
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
}
