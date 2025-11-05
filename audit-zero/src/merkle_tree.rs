use crate::{TREE_DEPTH, poseidon::poseidon_merge_hash_gadget};
use ark_bn254::Fr;
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;

/// Circuit gadget for verifying Merkle tree membership proof
/// Given a leaf commitment and a Merkle proof, verify that the leaf is in the tree
pub fn merkle_proof_gadget(
    leaf: &FpVar<Fr>,
    proof_nodes_left: &[FpVar<Fr>],
    proof_nodes_right: &[FpVar<Fr>],
    expected_root: &FpVar<Fr>,
) -> Result<Boolean<Fr>, SynthesisError> {
    assert_eq!(proof_nodes_left.len(), TREE_DEPTH);
    assert_eq!(proof_nodes_right.len(), TREE_DEPTH);

    // Start with the leaf
    let mut current_hash = leaf.clone();

    // Traverse from leaf to root
    for i in 0..TREE_DEPTH {
        // Compute parent hash: Poseidon(left, right)
        let parent = poseidon_merge_hash_gadget(&proof_nodes_left[i], &proof_nodes_right[i])?;

        // Check if current_hash is either left or right child
        let is_left = current_hash.is_eq(&proof_nodes_left[i])?;
        let is_right = current_hash.is_eq(&proof_nodes_right[i])?;

        // At least one must be true (is_left OR is_right)
        // We enforce this by checking: NOT(NOT is_left AND NOT is_right)
        // Using bitwise operations: a OR b = NOT(NOT a AND NOT b)
        let not_left = !is_left;
        let not_right = !is_right;
        let both_false = &not_left & &not_right;
        let is_valid_child = !both_false;

        // Enforce that current_hash must be one of the children
        is_valid_child.enforce_equal(&Boolean::TRUE)?;

        // Move to parent for next iteration
        current_hash = parent;
    }

    // Verify the final computed root matches the expected root
    current_hash.is_eq(expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::structs::MerkleTree;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_merkle_proof_gadget() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a merkle tree and add some leaves
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        let mut leaves = vec![];
        for _ in 0..10 {
            let leaf = Fr::rand(rng);
            leaves.push(leaf);
            merkle.add_leaf(leaf).unwrap();
        }
        merkle.commit().unwrap();

        // Get proof for leaf at index 5
        let proof = merkle.generate_proof(5).unwrap();
        assert!(proof.verify());

        // Circuit verification
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaves[5])).unwrap();
        let root_var = FpVar::new_witness(cs.clone(), || Ok(proof.root)).unwrap();

        let mut left_nodes = vec![];
        let mut right_nodes = vec![];

        for node in &proof.nodes {
            left_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.left)).unwrap());
            right_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.right)).unwrap());
        }

        let result = merkle_proof_gadget(&leaf_var, &left_nodes, &right_nodes, &root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert!(result.value().unwrap());
    }
}
