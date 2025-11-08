use crate::{
    Keypair, MTProof, OpenCommitment, PublicKey, audit_gadget::audit_encrypt_gadget,
    commitment::commitment_gadget, keys::keypair_gadget, merkle_tree::merkle_proof_gadget,
    nullifier::nullifier_gadget,
};
use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_std::{
    collections::HashMap,
    rand::{CryptoRng, Rng},
};

/// UTXO transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct UtxoCircuit {
    pub keypair: Keypair,
    pub inputs: Vec<UtxoInput>,
    pub outputs: Vec<UtxoOutput>,
    pub audit: Option<AuditCircuit>,
}

/// Audit memo encryption circuit
#[derive(Clone)]
pub struct AuditCircuit {
    pub auditor: PublicKey,
    pub memos: Vec<Vec<u8>>,
    pub shares: Vec<Fr>,
}

/// UTXO public inputs
#[derive(Clone, Debug)]
pub struct Utxo {
    pub nullifiers: Vec<Fr>,
    pub commitments: Vec<Fr>,
    pub memos: Vec<Vec<u8>>,
    pub merkle_version: u32,
    pub merkle_root: Fr,
    pub audit: Option<Audit>,
}

/// UTXO public inputs
#[derive(Clone, Debug)]
pub struct Audit {
    pub auditor: PublicKey,
    pub memos: Vec<Vec<u8>>,
}

impl UtxoCircuit {
    /// generate public used utxo
    pub fn utxo<R: CryptoRng + Rng>(&self, prng: &mut R) -> crate::Result<Utxo> {
        assert!(!self.inputs.is_empty());

        let nullifiers = self
            .inputs
            .iter()
            .map(|input| input.commitment.nullify(&self.keypair))
            .collect();
        let commitments = self
            .outputs
            .iter()
            .map(|output| output.commitment.commit())
            .collect();

        let mut memos = vec![];
        for output in self.outputs.iter() {
            memos.push(output.commitment.memo_encrypt(prng)?);
        }

        let merkle_version = self.inputs[0].merkle_proof.version;
        let merkle_root = self.inputs[0].merkle_proof.root;

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memos: audit.memos.clone(),
            })
        } else {
            None
        };

        Ok(Utxo {
            nullifiers,
            commitments,
            memos,
            merkle_version,
            merkle_root,
            audit,
        })
    }

    /// generate public inputs
    pub(crate) fn publics(&self) -> Utxo {
        assert!(!self.inputs.is_empty());

        let nullifiers = self
            .inputs
            .iter()
            .map(|input| input.commitment.nullify(&self.keypair))
            .collect();
        let commitments = self
            .outputs
            .iter()
            .map(|output| output.commitment.commit())
            .collect();

        let merkle_version = self.inputs[0].merkle_proof.version;
        let merkle_root = self.inputs[0].merkle_proof.root;

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memos: audit.memos.clone(),
            })
        } else {
            None
        };

        Utxo {
            nullifiers,
            commitments,
            merkle_root,
            merkle_version,
            audit,
            memos: vec![],
        }
    }
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
        let utxo = self.publics();

        // Allocate public inputs
        let nullifiers_vars: Vec<FpVar<Fr>> = utxo
            .nullifiers
            .iter()
            .map(|n| FpVar::new_input(cs.clone(), || Ok(*n)))
            .collect::<Result<_, _>>()?;

        let commitments_vars: Vec<FpVar<Fr>> = utxo
            .commitments
            .iter()
            .map(|c| FpVar::new_input(cs.clone(), || Ok(*c)))
            .collect::<Result<_, _>>()?;

        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(utxo.merkle_root))?;

        // Allocate private witness data
        let sk_fr = self.keypair.secret_to_fq();
        let sk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sk_fr))?;

        // Public key coordinates in their native Fq field for keypair proof
        let pk_x_fq_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.keypair.public.x))?;
        let pk_y_fq_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.keypair.public.y))?;

        // Prove keypair relationship: pk = sk * G
        keypair_gadget(&sk_var, &pk_x_fq_var, &pk_y_fq_var)?;

        // Track asset balances
        let mut asset_balances: HashMap<u64, (FpVar<Fr>, FpVar<Fr>)> = HashMap::new();

        // Process inputs
        for (i, input) in self.inputs.iter().enumerate() {
            let comm = &input.commitment;
            let proof = &input.merkle_proof;

            // 1. Allocate input commitment fields
            let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.asset)))?;
            let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.amount)))?;
            let blind_var = FpVar::new_witness(cs.clone(), || Ok(comm.blind))?;

            // 2. Verify commitment correctness
            let computed_commitment = commitment_gadget(
                &asset_var,
                &amount_var,
                &blind_var,
                &pk_x_fq_var,
                &pk_y_fq_var,
            )?;

            // 3. Compute and verify nullifier
            let computed_nullifier = nullifier_gadget(&computed_commitment, &sk_var)?;

            // Verify nullifier matches public input
            computed_nullifier.enforce_equal(&nullifiers_vars[i])?;

            // Verify Merkle tree membership
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
        let mut audit_used = Vec::new();
        for (i, output) in self.outputs.iter().enumerate() {
            let comm = &output.commitment;

            // 1. Allocate output commitment fields
            let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.asset)))?;
            let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm.amount)))?;
            let blind_var = FpVar::new_witness(cs.clone(), || Ok(comm.blind))?;
            let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.x))?;
            let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(comm.owner.y))?;

            // 2. Compute commitment
            let computed_commitment = commitment_gadget(
                &asset_var,
                &amount_var,
                &blind_var,
                &owner_x_var,
                &owner_y_var,
            )?;

            // 3. Verify commitment matches public output
            computed_commitment.enforce_equal(&commitments_vars[i])?;

            // 4. Track output amounts by asset
            let entry = asset_balances.entry(comm.asset).or_insert((
                FpVar::constant(Fr::from(0u64)),
                FpVar::constant(Fr::from(0u64)),
            ));
            entry.1 = &entry.1 + &amount_var; // Add to output total

            audit_used.push((
                asset_var,
                amount_var,
                owner_x_var,
                owner_y_var,
                computed_commitment,
            ));
        }

        // 7. Verify balance: for each asset, inputs == outputs
        for (_asset, (input_total, output_total)) in asset_balances.iter() {
            input_total.enforce_equal(output_total)?;
        }

        // 8. Prove audit encryption correctness (if audit is enabled)
        if let Some(audit) = &self.audit {
            // Allocate auditor public key as witness
            let auditor_pk_x_var = FpVar::new_input(cs.clone(), || Ok(audit.auditor.x))?;
            let auditor_pk_y_var = FpVar::new_input(cs.clone(), || Ok(audit.auditor.y))?;

            // Prove encryption for each output
            for (i, output) in self.outputs.iter().enumerate() {
                let memo_bytes = &audit.memos[i];
                let (asset_var, amount_var, owner_x_var, owner_y_var, _comm_var) = &audit_used[i];

                // Get the ephemeral secret for this output
                let ephemeral_secret = audit.shares[i];
                let ephemeral_sk_var = FpVar::new_witness(cs.clone(), || Ok(ephemeral_secret))?;

                // Public key coordinates in their native Fq field for keypair proof
                let ephemeral_pk_x = Fr::deserialize_compressed(&memo_bytes[..32])
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                let ephemeral_pk_y = Fr::deserialize_compressed(&memo_bytes[32..64])
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                let ephemeral_pk_x_var =
                    FpVar::<Fr>::new_witness(cs.clone(), || Ok(ephemeral_pk_x))?;
                let ephemeral_pk_y_var =
                    FpVar::<Fr>::new_witness(cs.clone(), || Ok(ephemeral_pk_y))?;

                // Prove keypair relationship: pk = sk * G
                keypair_gadget(&ephemeral_sk_var, &ephemeral_pk_x_var, &ephemeral_pk_y_var)?;

                // Compute nullifier for this output
                // FIXME let nullifier_var = nullifier_gadget(&comm_var, &sk_var)?;

                let nullifier = output.commitment.nullify(&self.keypair);
                let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(nullifier))?;

                // Extract ciphertexts from memo bytes
                // Format: ephemeral_pk (64 bytes) || ciphertexts (4 × 32 bytes)
                // 4 field elements: [asset_amount_packed, owner_x, owner_y, nullifier]
                let mut expected_ciphertexts = Vec::new();
                for bytes in memo_bytes[64..].chunks(32) {
                    // skip pk
                    let ct = Fr::deserialize_compressed(bytes)
                        .map_err(|_| SynthesisError::Unsatisfiable)?;
                    let ct_var = FpVar::new_input(cs.clone(), || Ok(ct))?;
                    expected_ciphertexts.push(ct_var);
                }

                // Prove encryption correctness
                audit_encrypt_gadget(
                    &ephemeral_sk_var,
                    &auditor_pk_x_var,
                    &auditor_pk_y_var,
                    &asset_var,
                    &amount_var,
                    &owner_x_var,
                    &owner_y_var,
                    &nullifier_var,
                    &expected_ciphertexts,
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryStorage, MerkleTree};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_utxo_circuit() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let input_comm = OpenCommitment::generate(rng, asset, amount, keypair.public);

        // Add to merkle tree
        let commitment_hash = input_comm.commit();
        let index = merkle.add_leaf(commitment_hash).unwrap();
        merkle.commit().unwrap();
        let merkle_proof = merkle.generate_proof(index).unwrap();

        // Create output UTXO (same amount, different blind)
        let output_comm = OpenCommitment::generate(rng, asset, amount, keypair.public);

        // Create circuit
        let circuit = UtxoCircuit {
            keypair: keypair,
            inputs: vec![UtxoInput {
                commitment: input_comm,
                merkle_proof,
            }],
            outputs: vec![UtxoOutput {
                commitment: output_comm,
            }],
            audit: None,
        };

        // Test constraint satisfaction
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("Circuit has {} constraints", cs.num_constraints());
    }
}
