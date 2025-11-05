use crate::{AzError, Keypair, MTNode, MTProof, OpenCommitment, TREE_DEPTH};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};

pub use crate::utxo::{Utxo, UtxoCircuit, UtxoInput, UtxoOutput};

/// Groth16 proving key
pub type ProvingKey = ark_groth16::ProvingKey<Bn254>;

/// Groth16 verification key
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;

/// Groth16 proof
pub type Proof = ark_groth16::Proof<Bn254>;

/// Setup the Groth16 proving and verification keys for a circuit with given shape
/// num_inputs: number of input UTXOs
/// num_outputs: number of output UTXOs
pub fn setup<R: Rng + CryptoRng>(
    num_inputs: usize,
    num_outputs: usize,
    rng: &mut R,
) -> crate::Result<(ProvingKey, VerifyingKey)> {
    // Create a dummy circuit for setup matching the desired shape
    // The circuit needs witness data for constraint generation
    let keypair = Keypair::generate(rng);

    let mut inputs = vec![];
    for _ in 0..num_inputs {
        let blind = Fr::rand(rng);
        let commitment = OpenCommitment {
            asset: 0,
            amount: 0,
            owner: keypair.public.clone(),
            blind,
            memo: None,
            audit: None,
        };

        let mut nodes = vec![];
        for _ in 0..TREE_DEPTH {
            nodes.push(MTNode {
                left: Fr::from(0u64),
                right: Fr::from(0u64),
            });
        }

        let merkle_proof = MTProof {
            nodes,
            ledger: 0,
            root: Fr::from(0u64),
            version: 0,
            index: 0,
        };

        inputs.push(UtxoInput {
            commitment,
            merkle_proof,
        });
    }

    let mut outputs = vec![];
    for _ in 0..num_outputs {
        let blind = Fr::rand(rng);
        let commitment = OpenCommitment {
            asset: 0,
            amount: 0,
            owner: keypair.public.clone(),
            blind,
            memo: None,
            audit: None,
        };

        outputs.push(UtxoOutput { commitment });
    }

    let dummy_circuit = UtxoCircuit {
        keypair,
        inputs,
        outputs,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|_e| AzError::Groth16Setup)?;

    Ok((pk, vk))
}

/// Generate a Groth16 proof for a UTXO transaction
pub fn prove<R: Rng + CryptoRng>(
    pk: &ProvingKey,
    circuit: UtxoCircuit,
    rng: &mut R,
) -> crate::Result<Proof> {
    Groth16::<Bn254>::prove(pk, circuit, rng).map_err(|_| AzError::Groth16Prove)
}

/// Verify a Groth16 proof for a UTXO transaction
pub fn verify(vk: &VerifyingKey, utxo: &Utxo, proof: &Proof) -> crate::Result<()> {
    let mut publics = utxo.nullifiers.clone();
    publics.extend(&utxo.commitments);
    publics.push(utxo.merkle_root);

    let res = Groth16::<Bn254>::verify(vk, &publics, proof).map_err(|_| AzError::Groth16Verify)?;

    if res {
        Ok(())
    } else {
        Err(AzError::Groth16Verify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryStorage, MerkleTree};
    use ark_std::{UniformRand, rand::SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_groth16_prove_verify() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let mut comm_inputs = vec![];
        for _ in 0..3 {
            let input_blind = Fr::rand(rng);
            let input_comm = OpenCommitment {
                asset: 1,
                amount: 100,
                owner: keypair.public,
                blind: input_blind,
                memo: None,
                audit: None,
            };

            // Add to merkle tree
            let index = merkle.add_leaf(input_comm.commit()).unwrap();
            comm_inputs.push((index, input_comm));
        }
        merkle.commit().unwrap();
        let merkle_root = merkle.get_root().unwrap();

        let mut inputs = vec![];
        for (index, commitment) in comm_inputs {
            let merkle_proof = merkle.generate_proof(index).unwrap();
            inputs.push(UtxoInput {
                commitment,
                merkle_proof,
            });
        }

        // Create output UTXO
        let mut outputs = vec![];
        for _ in 0..3 {
            let output_blind = Fr::rand(rng);
            let commitment = OpenCommitment {
                asset: 1,
                amount: 100,
                owner: keypair.public,
                blind: output_blind,
                memo: None,
                audit: None,
            };
            outputs.push(UtxoOutput { commitment });
        }

        // Setup with 3 input and 3 output
        let (pk, vk) = setup(3, 3, rng).unwrap();

        // Create circuit
        let circuit = UtxoCircuit {
            keypair,
            inputs,
            outputs,
        };
        let utxo = circuit.publics();
        assert_eq!(utxo.merkle_root, merkle_root);

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();
    }
}
