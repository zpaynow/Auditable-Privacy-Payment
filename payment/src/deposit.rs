use crate::{
    Amount, Asset, AzError, Commitment, Keypair, OpenCommitment, PublicKey,
    audit_gadget::audit_encrypt_gadget,
    commitment::commitment_gadget,
    keys::keypair_gadget,
    transfer::{Proof, ProvingKey, VerifyingKey},
};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{CryptoRng, Rng};

/// Deposit transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct DepositCircuit {
    pub keypair: Keypair,
    pub asset: Asset,
    pub amount: Amount,
    pub output: OpenCommitment,
    pub audit: Option<AuditCircuit>,
}

/// Audit memo encryption circuit
#[derive(Clone)]
pub struct AuditCircuit {
    pub auditor: PublicKey,
    pub memo: Vec<u8>,
    pub share: Fr,
}

/// Deposit public struct
#[derive(Clone, Debug)]
pub struct Deposit {
    pub asset: Asset,
    pub amount: Amount,
    pub commitment: Commitment,
    pub memo: Vec<u8>,
    pub audit: Option<Audit>,
}

/// Deposit public inputs
#[derive(Clone, Debug)]
pub struct Audit {
    pub auditor: PublicKey,
    pub memo: Vec<u8>,
}

impl DepositCircuit {
    /// generate public used deposit
    pub fn deposit<R: CryptoRng + Rng>(&self, prng: &mut R) -> crate::Result<Deposit> {
        let commitment = self.output.commit();
        let memo = self.output.memo_encrypt(prng)?;

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memo: audit.memo.clone(),
            })
        } else {
            None
        };

        Ok(Deposit {
            asset: self.asset,
            amount: self.amount,
            commitment,
            memo,
            audit,
        })
    }

    /// generate public inputs
    pub(crate) fn publics(&self) -> Deposit {
        let commitment = self.output.commit();

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memo: audit.memo.clone(),
            })
        } else {
            None
        };

        Deposit {
            asset: self.asset,
            amount: self.amount,
            commitment,
            memo: vec![],
            audit,
        }
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let utxo = self.publics();

        // Allocate public inputs
        let asset_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(utxo.asset)))?;
        let amount_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(utxo.amount)))?;
        let commitment_var = FpVar::new_input(cs.clone(), || Ok(utxo.commitment))?;

        // Process output
        let blind_var = FpVar::new_witness(cs.clone(), || Ok(self.output.blind))?;
        let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(self.output.owner.x))?;
        let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(self.output.owner.y))?;

        // Compute commitment
        let computed_commitment = commitment_gadget(
            &asset_var,
            &amount_var,
            &blind_var,
            &owner_x_var,
            &owner_y_var,
        )?;

        // Verify commitment matches public output
        computed_commitment.enforce_equal(&commitment_var)?;

        // Prove audit encryption correctness (if audit is enabled)
        if let Some(audit) = &self.audit {
            // Allocate auditor public key as witness
            let auditor_pk_x_var = FpVar::new_input(cs.clone(), || Ok(audit.auditor.x))?;
            let auditor_pk_y_var = FpVar::new_input(cs.clone(), || Ok(audit.auditor.y))?;

            // Prove encryption for output
            let comm = &self.output;
            let memo_bytes = &audit.memo;
            let ephemeral_secret = audit.share;

            // Get the ephemeral secret for this output
            let ephemeral_sk_var = FpVar::new_witness(cs.clone(), || Ok(ephemeral_secret))?;

            // Public key coordinates in their native Fq field for keypair proof
            let ephemeral_pk_x = Fr::deserialize_compressed(&memo_bytes[..32])
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            let ephemeral_pk_y = Fr::deserialize_compressed(&memo_bytes[32..64])
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            let ephemeral_pk_x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(ephemeral_pk_x))?;
            let ephemeral_pk_y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(ephemeral_pk_y))?;

            // Prove keypair relationship: pk = sk * G
            keypair_gadget(&ephemeral_sk_var, &ephemeral_pk_x_var, &ephemeral_pk_y_var)?;

            // Compute nullifier for this output
            let nullifier = comm.nullify(&self.keypair);
            let nullifier_var = FpVar::new_witness(cs.clone(), || Ok(nullifier))?;

            // Extract ciphertexts from memo bytes
            // Format: ephemeral_pk (64 bytes) || ciphertexts (4 × 32 bytes)
            // 4 field elements: [asset_amount_packed, owner_x, owner_y, nullifier]
            let mut expected_ciphertexts = Vec::new();
            for bytes in memo_bytes[64..].chunks(32) {
                // skip pk
                let ct =
                    Fr::deserialize_compressed(bytes).map_err(|_| SynthesisError::Unsatisfiable)?;
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

        Ok(())
    }
}

/// Setup the Groth16 proving and verification keys for a circuit with given shape
/// num_inputs: number of input UTXOs
/// num_outputs: number of output UTXOs
pub fn setup<R: Rng + CryptoRng>(
    is_audit: bool,
    rng: &mut R,
) -> crate::Result<(ProvingKey, VerifyingKey)> {
    // Create a dummy circuit for setup matching the desired shape
    // The circuit needs witness data for constraint generation
    let keypair = Keypair::generate(rng);

    let output = OpenCommitment::generate(rng, 0, 0, keypair.public);

    let audit = if is_audit {
        // Field-element encryption format: ephemeral_pk (64 bytes) + ciphertexts (4 × 32 bytes)
        // 4 field elements: [asset_amount_packed, owner_x, owner_y, nullifier]
        // asset and amount are packed together: asset * 2^128 + amount
        Some(AuditCircuit {
            auditor: keypair.public,
            memo: vec![0u8; 192],
            share: Fr::from(0u64),
        })
    } else {
        None
    };

    let dummy_circuit = DepositCircuit {
        keypair,
        asset: 1,
        amount: 1,
        output,
        audit,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|_e| AzError::Groth16Setup)?;

    Ok((pk, vk))
}

/// Generate a Groth16 proof for a deposit transaction
pub fn prove<R: Rng + CryptoRng>(
    pk: &ProvingKey,
    circuit: DepositCircuit,
    rng: &mut R,
) -> crate::Result<Proof> {
    Groth16::<Bn254>::prove(pk, circuit, rng).map_err(|_| AzError::Groth16Prove)
}

/// Verify a Groth16 proof for a withdraw transaction
pub fn verify(vk: &VerifyingKey, utxo: &Deposit, proof: &Proof) -> crate::Result<()> {
    let mut publics = Vec::new();

    publics.push(Fr::from(utxo.asset));
    publics.push(Fr::from(utxo.amount));
    publics.push(utxo.commitment);

    if let Some(audit) = &utxo.audit {
        publics.push(audit.auditor.x);
        publics.push(audit.auditor.y);

        for bytes in audit.memo[64..].chunks(32) {
            // skip first pk
            let ct = Fr::deserialize_compressed(bytes).map_err(|_| AzError::Groth16Verify)?;
            publics.push(ct);
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
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_deposit_prove_verify() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;

        let output = OpenCommitment::generate(rng, asset, amount, keypair.public);

        // Setup
        let (pk, vk) = setup(false, rng).unwrap();
        let mut pk_bytes = vec![];
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let cs_size = pk.a_query.len();
        let num_public_inputs = pk.vk.gamma_abc_g1.len() - 1;

        println!(
            "N-A deposit: cs_size: {}, public_inputs: {}, pk: {} MB - vk: {} B",
            cs_size,
            num_public_inputs,
            pk_bytes.len() / 1024 / 1024,
            vk_bytes.len()
        );

        // Create circuit
        let circuit = DepositCircuit {
            keypair,
            asset,
            amount,
            output,
            audit: None,
        };
        let utxo = circuit.publics();

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();
    }

    #[test]
    fn test_deposit_prove_verify_with_audit() {
        let rng = &mut ChaCha20Rng::from_seed([2u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;
        let auditor = Keypair::generate(rng);

        // Create output
        let output = OpenCommitment::generate(rng, asset, amount, keypair.public);
        let (memo, share) = output
            .audit_encrypt(rng, &keypair, &auditor.public)
            .unwrap();

        // Setup with audit
        let (pk, vk) = setup(true, rng).unwrap();
        let mut pk_bytes = vec![];
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let cs_size = pk.a_query.len();
        let num_public_inputs = pk.vk.gamma_abc_g1.len() - 1;

        println!(
            "Y-A deposit: cs_size: {}, public_inputs: {}, pk: {} MB - vk: {} B",
            cs_size,
            num_public_inputs,
            pk_bytes.len() / 1024 / 1024,
            vk_bytes.len()
        );

        // Create circuit
        let circuit = DepositCircuit {
            keypair,
            asset,
            amount,
            output,
            audit: Some(AuditCircuit {
                auditor: auditor.public,
                memo,
                share,
            }),
        };
        let utxo = circuit.publics();

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();
    }
}
