use crate::{AzError, Keypair, MTNode, MTProof, OpenCommitment, TREE_DEPTH};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{CryptoRng, Rng};

pub use crate::utxo::{AuditCircuit, Utxo, UtxoCircuit, UtxoInput, UtxoOutput};

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
    is_audit: bool,
    rng: &mut R,
) -> crate::Result<(ProvingKey, VerifyingKey)> {
    // Create a dummy circuit for setup matching the desired shape
    // The circuit needs witness data for constraint generation
    let keypair = Keypair::generate(rng);

    let mut inputs = vec![];
    for _ in 0..num_inputs {
        let commitment = OpenCommitment::generate(rng, 0, 0, keypair.public);

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
        let commitment = OpenCommitment::generate(rng, 0, 0, keypair.public);

        outputs.push(UtxoOutput { commitment });
    }

    let audit = if is_audit {
        // Field-element encryption format: ephemeral_pk (32 bytes) + ciphertexts (4 × 32 bytes)
        // 4 field elements: [asset_amount_packed, owner_x, owner_y, nullifier]
        // asset and amount are packed together: asset * 2^128 + amount
        let memos = vec![vec![0u8; 160]; num_outputs]; // 32 + 4*32 = 160 bytes
        let shares = vec![Fr::from(0u64); num_outputs];
        Some(AuditCircuit {
            auditor: keypair.public,
            memos,
            shares,
        })
    } else {
        None
    };

    let dummy_circuit = UtxoCircuit {
        keypair,
        inputs,
        outputs,
        audit,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng).unwrap();
    // .map_err(|_e| AzError::Groth16Setup)?;

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

    if let Some(audit) = &utxo.audit {
        publics.push(audit.auditor.x);
        publics.push(audit.auditor.y);

        for memo_bytes in &audit.memos {
            for bytes in memo_bytes[32..].chunks(32) {
                // skip first pk
                let ct = Fr::deserialize_compressed(bytes).map_err(|_| AzError::Groth16Verify)?;
                publics.push(ct);
            }
        }
    }

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
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_different_cs_size() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);
        // 2-1: cs_size: 34743, public_inputs: 4, pk: 7 MB - vk: 392 B merge outputs
        // 1-2: cs_size: 21162, public_inputs: 4, pk: 4 MB - vk: 392 B pay no gas
        // 1-3: cs_size: 23104, public_inputs: 5, pk: 4 MB - vk: 424 B pay with gas
        // 2-3: cs_size: 38627, public_inputs: 6, pk: 7 MB - vk: 456 B multiple usages
        for (i, o) in [(2, 1), (1, 2), (1, 3), (2, 3)] {
            let (pk, vk) = setup(i, o, false, rng).unwrap();
            let mut pk_bytes = vec![];
            pk.serialize_compressed(&mut pk_bytes).unwrap();
            let mut vk_bytes = vec![];
            vk.serialize_compressed(&mut vk_bytes).unwrap();

            // The constraint system size can be determined from the a_query length
            // a_query contains elements for all constraints and witnesses
            let cs_size = pk.a_query.len();
            let num_public_inputs = pk.vk.gamma_abc_g1.len() - 1;

            println!(
                "{i}-{o}: cs_size: {}, public_inputs: {}, pk: {} MB - vk: {} B",
                cs_size,
                num_public_inputs,
                pk_bytes.len() / 1024 / 1024,
                vk_bytes.len()
            );

            let (pk1, vk1) = setup(i, o, true, rng).unwrap();
            let mut pk1_bytes = vec![];
            pk1.serialize_compressed(&mut pk1_bytes).unwrap();
            let mut vk1_bytes = vec![];
            vk1.serialize_compressed(&mut vk1_bytes).unwrap();

            // The constraint system size can be determined from the a_query length
            // a_query contains elements for all constraints and witnesses
            let cs1_size = pk1.a_query.len();
            let num1_public_inputs = pk1.vk.gamma_abc_g1.len() - 1;

            println!(
                "Aduit: {i}-{o}: cs_size: {}, public_inputs: {}, pk: {} MB - vk: {} B",
                cs1_size,
                num1_public_inputs,
                pk1_bytes.len() / 1024 / 1024,
                vk1_bytes.len()
            );
        }
    }

    #[test]
    fn test_groth16_prove_verify() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount1 = 300;
        let amount2 = 200;

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let mut comm_inputs = vec![];
        for _ in 0..2 {
            let input_comm = OpenCommitment::generate(rng, asset, amount1, keypair.public);

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
            let commitment = OpenCommitment::generate(rng, asset, amount2, keypair.public);
            outputs.push(UtxoOutput { commitment });
        }

        // Setup with 3 input and 3 output
        let (pk, vk) = setup(2, 3, false, rng).unwrap();

        // Create circuit
        let circuit = UtxoCircuit {
            keypair,
            inputs,
            outputs,
            audit: None,
        };
        let utxo = circuit.publics();
        assert_eq!(utxo.merkle_root, merkle_root);

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();
    }

    #[test]
    fn test_groth16_prove_verify_with_audit() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount1 = 300;
        let amount2 = 200;
        let auditor = Keypair::generate(rng);

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let mut comm_inputs = vec![];
        for _ in 0..2 {
            let input_comm = OpenCommitment::generate(rng, asset, amount1, keypair.public);

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
        let mut audit_memos = vec![];
        let mut audit_shares = vec![];
        for _ in 0..3 {
            let commitment = OpenCommitment::generate(rng, asset, amount2, keypair.public);
            let (memo, share) = commitment
                .audit_encrypt(rng, &keypair, &auditor.public)
                .unwrap();
            outputs.push(UtxoOutput { commitment });
            audit_memos.push(memo);
            audit_shares.push(share);
        }

        // Setup with 2 input and 3 output
        let (pk, vk) = setup(2, 3, true, rng).unwrap();

        // Create circuit
        let circuit = UtxoCircuit {
            keypair,
            inputs,
            outputs,
            audit: Some(AuditCircuit {
                auditor: auditor.public,
                memos: audit_memos,
                shares: audit_shares,
            }),
        };
        let utxo = circuit.publics();
        assert_eq!(utxo.merkle_root, merkle_root);

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();
    }
}
