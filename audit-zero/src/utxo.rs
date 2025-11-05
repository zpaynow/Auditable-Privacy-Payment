use crate::commitment::commitment_gadget;
use crate::merkle_tree::merkle_proof_gadget;
use crate::nullifier::nullifier_gadget;
use crate::{Keypair, OpenCommitment, structs::MTProof};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// UTXO transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct UtxoCircuit {
    // Private inputs (witness)
    pub keypair: Option<Keypair>,
    pub inputs: Vec<UtxoInput>,
    pub outputs: Vec<UtxoOutput>,

    // Public inputs
    pub nullifiers: Vec<Fr>,
    pub output_commitments: Vec<Fr>,
    pub merkle_root: Fr,
}

/// Input UTXO being spent
#[derive(Clone)]
pub struct UtxoInput {
    pub commitment: OpenCommitment,
    pub merkle_proof: MTProof,
}

/// Output UTXO being created
#[derive(Clone)]
pub struct UtxoOutput {
    pub commitment: OpenCommitment,
}

impl ConstraintSynthesizer<Fr> for UtxoCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let nullifiers_vars: Vec<FpVar<Fr>> = self
            .nullifiers
            .iter()
            .map(|n| FpVar::new_input(cs.clone(), || Ok(*n)))
            .collect::<Result<_, _>>()?;

        let output_commitment_vars: Vec<FpVar<Fr>> = self
            .output_commitments
            .iter()
            .map(|c| FpVar::new_input(cs.clone(), || Ok(*c)))
            .collect::<Result<_, _>>()?;

        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;

        // Allocate private witness data
        let keypair = self
            .keypair
            .as_ref()
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Convert secret key to Fr for circuit
        let sk_bytes = keypair.secret.0.into_bigint().to_bytes_le();
        let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);

        let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk_fr))?;
        let pk_x_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.0.x))?;
        let pk_y_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.0.y))?;

        // Track asset balances
        let mut asset_balances: std::collections::HashMap<u64, (FpVar<Fr>, FpVar<Fr>)> =
            std::collections::HashMap::new();

        // Process inputs
        for (i, input) in self.inputs.iter().enumerate() {
            let comm = &input.commitment;
            let proof = &input.merkle_proof;

            // 1. Allocate input commitment fields
            let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.asset)))?;
            let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.amount)))?;
            let blind_var = FpVar::new_witness(cs.clone(), || Ok(comm.blind))?;
            let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.0.x))?;
            let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.0.y))?;

            // 2. Verify commitment correctness
            let computed_commitment = commitment_gadget(
                &asset_var,
                &amount_var,
                &blind_var,
                &owner_x_var,
                &owner_y_var,
            )?;

            // 3. Verify ownership (owner must be the keypair)
            owner_x_var.enforce_equal(&pk_x_var)?;
            owner_y_var.enforce_equal(&pk_y_var)?;

            // 4. Compute and verify nullifier
            let index_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(proof.index)))?;
            let computed_nullifier = nullifier_gadget(
                &asset_var,
                &amount_var,
                &index_var,
                &pk_x_var,
                &pk_y_var,
                &sk_var,
            )?;

            // Verify nullifier matches public input
            computed_nullifier.enforce_equal(&nullifiers_vars[i])?;

            // 5. Verify Merkle tree membership
            let commitment_hash = comm.commit();
            let leaf_var = FpVar::new_witness(cs.clone(), || Ok(commitment_hash))?;

            // The leaf should match the computed commitment
            leaf_var.enforce_equal(&computed_commitment)?;

            let mut left_nodes = vec![];
            let mut right_nodes = vec![];
            for node in &proof.nodes {
                left_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.left))?);
                right_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.right))?);
            }

            let merkle_valid =
                merkle_proof_gadget(&leaf_var, &left_nodes, &right_nodes, &merkle_root_var)?;
            merkle_valid.enforce_equal(&Boolean::TRUE)?;

            // 6. Track input amounts by asset
            let entry = asset_balances.entry(comm.asset).or_insert((
                FpVar::constant(Fr::from(0u64)),
                FpVar::constant(Fr::from(0u64)),
            ));
            entry.0 = &entry.0 + &amount_var; // Add to input total
        }

        // Process outputs
        for (i, output) in self.outputs.iter().enumerate() {
            let comm = &output.commitment;

            // 1. Allocate output commitment fields
            let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.asset)))?;
            let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.amount)))?;
            let blind_var = FpVar::new_witness(cs.clone(), || Ok(comm.blind))?;
            let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.0.x))?;
            let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.0.y))?;

            // 2. Compute commitment
            let computed_commitment = commitment_gadget(
                &asset_var,
                &amount_var,
                &blind_var,
                &owner_x_var,
                &owner_y_var,
            )?;

            // 3. Verify commitment matches public output
            computed_commitment.enforce_equal(&output_commitment_vars[i])?;

            // 4. Track output amounts by asset
            let entry = asset_balances.entry(comm.asset).or_insert((
                FpVar::constant(Fr::from(0u64)),
                FpVar::constant(Fr::from(0u64)),
            ));
            entry.1 = &entry.1 + &amount_var; // Add to output total
        }

        // 7. Verify balance: for each asset, inputs == outputs
        for (_asset, (input_total, output_total)) in asset_balances.iter() {
            input_total.enforce_equal(output_total)?;
        }

        Ok(())
    }
}

/// Groth16 proving key
pub type ProvingKey = ark_groth16::ProvingKey<Bn254>;

/// Groth16 verification key
pub type VerifyingKey = ark_groth16::VerifyingKey<Bn254>;

/// Groth16 proof
pub type Proof = ark_groth16::Proof<Bn254>;

/// Setup the Groth16 proving and verification keys for a circuit with given shape
/// num_inputs: number of input UTXOs
/// num_outputs: number of output UTXOs
pub fn setup<R: ark_std::rand::Rng + ark_std::rand::CryptoRng>(
    num_inputs: usize,
    num_outputs: usize,
    rng: &mut R,
) -> Result<(ProvingKey, VerifyingKey), Box<dyn std::error::Error>> {
    // Create a dummy circuit for setup matching the desired shape
    // The circuit needs witness data for constraint generation
    use crate::{PublicKey, SecretKey, structs::MTNode};
    use ark_ed_on_bn254::{EdwardsAffine, Fr as EdFr};
    use ark_std::UniformRand;

    let sk = EdFr::rand(rng);
    let pk_point = EdwardsAffine::rand(rng);
    let keypair = Keypair {
        public: PublicKey(pk_point),
        secret: SecretKey(sk),
    };

    let mut inputs = vec![];
    let mut nullifiers = vec![];
    for _ in 0..num_inputs {
        let blind = Fr::rand(rng);
        let comm = OpenCommitment {
            asset: 0,
            amount: 0,
            owner: keypair.public.clone(),
            blind,
            memo: None,
            audit: None,
            leaf: None,
        };

        let mut nodes = vec![];
        for _ in 0..crate::structs::TREE_DEPTH {
            nodes.push(MTNode {
                left: Fr::from(0u64),
                right: Fr::from(0u64),
            });
        }

        let proof = crate::structs::MTProof {
            nodes,
            ledger: 0,
            root: Fr::from(0u64),
            version: 0,
            index: 0,
        };

        let mut comm_with_proof = comm.clone();
        comm_with_proof.leaf = Some(proof.clone());

        inputs.push(UtxoInput {
            commitment: comm_with_proof.clone(),
            merkle_proof: proof,
        });

        nullifiers.push(comm_with_proof.nullify(&keypair));
    }

    let mut outputs = vec![];
    let mut output_commitments = vec![];
    for _ in 0..num_outputs {
        let blind = Fr::rand(rng);
        let comm = OpenCommitment {
            asset: 0,
            amount: 0,
            owner: keypair.public.clone(),
            blind,
            memo: None,
            audit: None,
            leaf: None,
        };
        outputs.push(UtxoOutput {
            commitment: comm.clone(),
        });
        output_commitments.push(comm.commit());
    }

    let dummy_circuit = UtxoCircuit {
        keypair: Some(keypair),
        inputs,
        outputs,
        nullifiers,
        output_commitments,
        merkle_root: Fr::from(0u64),
    };

    let (pk, vk) = ark_groth16::Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok((pk, vk))
}

/// Generate a Groth16 proof for a UTXO transaction
pub fn prove<R: ark_std::rand::Rng + ark_std::rand::CryptoRng>(
    pk: &ProvingKey,
    circuit: UtxoCircuit,
    rng: &mut R,
) -> Result<Proof, Box<dyn std::error::Error>> {
    ark_groth16::Groth16::<Bn254>::prove(pk, circuit, rng)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Verify a Groth16 proof for a UTXO transaction
pub fn verify(
    vk: &VerifyingKey,
    public_inputs: &[Fr],
    proof: &Proof,
) -> Result<bool, Box<dyn std::error::Error>> {
    ark_groth16::Groth16::<Bn254>::verify(vk, public_inputs, proof)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use crate::{PublicKey, SecretKey, structs::MerkleTree};
    use ark_ed_on_bn254::EdwardsAffine;
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_utxo_circuit_basic() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);

        // Create keypair
        let sk = ark_ed_on_bn254::Fr::rand(rng);
        let pk_point = EdwardsAffine::rand(rng);
        let keypair = Keypair {
            public: PublicKey(pk_point),
            secret: SecretKey(sk),
        };

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let input_blind = Fr::rand(rng);
        let input_comm = OpenCommitment {
            asset: 1,
            amount: 100,
            owner: keypair.public.clone(),
            blind: input_blind,
            memo: None,
            audit: None,
            leaf: None,
        };

        // Add to merkle tree
        let commitment_hash = input_comm.commit();
        let index = merkle.add_leaf(commitment_hash).unwrap();
        merkle.commit().unwrap();
        let proof = merkle.generate_proof(index).unwrap();

        let mut input_with_proof = input_comm.clone();
        input_with_proof.leaf = Some(proof.clone());

        // Create output UTXO (same amount, different blind)
        let output_blind = Fr::rand(rng);
        let output_comm = OpenCommitment {
            asset: 1,
            amount: 100,
            owner: keypair.public.clone(),
            blind: output_blind,
            memo: None,
            audit: None,
            leaf: None,
        };

        // Compute nullifier and output commitment
        let nullifier = input_with_proof.nullify(&keypair);
        let output_commitment = output_comm.commit();

        // Create circuit
        let circuit = UtxoCircuit {
            keypair: Some(keypair),
            inputs: vec![UtxoInput {
                commitment: input_with_proof,
                merkle_proof: proof,
            }],
            outputs: vec![UtxoOutput {
                commitment: output_comm,
            }],
            nullifiers: vec![nullifier],
            output_commitments: vec![output_commitment],
            merkle_root: merkle.get_root().unwrap(),
        };

        // Test constraint satisfaction
        use ark_relations::r1cs::ConstraintSystem;
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("Circuit has {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_groth16_prove_verify() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        // Create keypair
        let sk = ark_ed_on_bn254::Fr::rand(rng);
        let pk_point = EdwardsAffine::rand(rng);
        let keypair = Keypair {
            public: PublicKey(pk_point),
            secret: SecretKey(sk),
        };

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let input_blind = Fr::rand(rng);
        let input_comm = OpenCommitment {
            asset: 1,
            amount: 100,
            owner: keypair.public.clone(),
            blind: input_blind,
            memo: None,
            audit: None,
            leaf: None,
        };

        // Add to merkle tree
        let commitment_hash = input_comm.commit();
        let index = merkle.add_leaf(commitment_hash).unwrap();
        merkle.commit().unwrap();
        let proof_merkle = merkle.generate_proof(index).unwrap();

        let mut input_with_proof = input_comm.clone();
        input_with_proof.leaf = Some(proof_merkle.clone());

        // Create output UTXO
        let output_blind = Fr::rand(rng);
        let output_comm = OpenCommitment {
            asset: 1,
            amount: 100,
            owner: keypair.public.clone(),
            blind: output_blind,
            memo: None,
            audit: None,
            leaf: None,
        };

        // Compute public inputs
        let nullifier = input_with_proof.nullify(&keypair);
        let output_commitment = output_comm.commit();
        let merkle_root = merkle.get_root().unwrap();

        // Setup with 1 input and 1 output
        let (pk, vk) = setup(1, 1, rng).unwrap();

        // Create circuit
        let circuit = UtxoCircuit {
            keypair: Some(keypair),
            inputs: vec![UtxoInput {
                commitment: input_with_proof,
                merkle_proof: proof_merkle,
            }],
            outputs: vec![UtxoOutput {
                commitment: output_comm,
            }],
            nullifiers: vec![nullifier],
            output_commitments: vec![output_commitment],
            merkle_root,
        };

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        let public_inputs = vec![nullifier, output_commitment, merkle_root];
        let valid = verify(&vk, &public_inputs, &proof).unwrap();
        assert!(valid);
    }
}
