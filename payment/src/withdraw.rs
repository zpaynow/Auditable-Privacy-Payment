use crate::{
    Amount, Asset, AzError, Keypair, MTNode, MTProof, Nullifier, OpenCommitment, TREE_DEPTH,
    commitment::commitment_gadget,
    keys::keypair_gadget,
    merkle_tree::merkle_proof_gadget,
    nullifier::nullifier_gadget,
    transfer::{Proof, ProvingKey, VerifyingKey},
};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{CryptoRng, Rng};

/// Withdraw transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct WithdrawCircuit {
    pub keypair: Keypair,
    pub asset: Asset,
    pub amount: Amount,
    /// recipient of the withdrawn funds (e.g. an EVM address encoded as a field element)
    pub recipient: Fr,
    /// fee paid to the relayer/aggregator out of `amount`
    pub fee: Amount,
    /// EVM address that must submit the transaction (`msg.sender`) and receives `fee`;
    /// bound into the proof so nobody else can front-run the relayer and take the fee
    pub relayer: Fr,
    pub input: OpenCommitment,
    pub merkle_proof: MTProof,
}

/// Withdraw public input
#[derive(Clone, Debug)]
pub struct Withdraw {
    pub asset: Asset,
    pub amount: Amount,
    pub recipient: Fr,
    pub fee: Amount,
    /// relayer address as a field element (see `WithdrawCircuit::relayer`)
    pub relayer: Fr,
    pub nullifier: Nullifier,
    pub freezer: Nullifier,
    pub merkle_version: u32,
    pub merkle_root: Fr,
}

impl Withdraw {
    /// Public inputs in the exact order the circuit allocates them:
    /// `[asset, amount, nullifier, freezer, root, recipient, fee, relayer]`.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.asset),
            Fr::from(self.amount),
            self.nullifier,
            self.freezer,
            self.merkle_root,
            self.recipient,
            Fr::from(self.fee),
            self.relayer,
        ]
    }
}

impl WithdrawCircuit {
    /// generate public inputs/withdraw
    pub fn withdraw(&self) -> Withdraw {
        let nullifier = self.input.nullify(&self.keypair);
        let freezer = self.input.freeze();

        Withdraw {
            nullifier,
            freezer,
            asset: self.asset,
            amount: self.amount,
            recipient: self.recipient,
            fee: self.fee,
            relayer: self.relayer,
            merkle_version: self.merkle_proof.version,
            merkle_root: self.merkle_proof.root,
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let utxo = self.withdraw();

        // Allocate public inputs
        let asset_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(utxo.asset)))?;
        let amount_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(utxo.amount)))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(utxo.nullifier))?;
        let freezer_var = FpVar::new_input(cs.clone(), || Ok(utxo.freezer))?;
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(utxo.merkle_root))?;
        let recipient_var = FpVar::new_input(cs.clone(), || Ok(utxo.recipient))?;
        let fee_var = FpVar::new_input(cs.clone(), || Ok(Fr::from(utxo.fee)))?;
        let relayer_var = FpVar::new_input(cs.clone(), || Ok(utxo.relayer))?;

        // Bind recipient, fee and relayer to the proof. Groth16 does not bind a public input
        // that appears in no constraint, so tie each one to a witness copy.
        let recipient_w = FpVar::new_witness(cs.clone(), || Ok(utxo.recipient))?;
        recipient_var.enforce_equal(&recipient_w)?;
        let fee_w = FpVar::new_witness(cs.clone(), || Ok(Fr::from(utxo.fee)))?;
        fee_var.enforce_equal(&fee_w)?;
        let relayer_w = FpVar::new_witness(cs.clone(), || Ok(utxo.relayer))?;
        relayer_var.enforce_equal(&relayer_w)?;

        // Allocate private witness data
        let sk_fr = self.keypair.secret_to_fq();
        let sk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sk_fr))?;

        // Public key coordinates in their native Fq field for keypair proof
        let pk_x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.keypair.public.x))?;
        let pk_y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.keypair.public.y))?;

        // Prove keypair relationship: pk = sk * G
        keypair_gadget(&sk_var, &pk_x_var, &pk_y_var)?;

        // Allocate input commitment fields
        let blind_var = FpVar::new_witness(cs.clone(), || Ok(self.input.blind))?;

        // Verify commitment correctness
        let computed_commitment =
            commitment_gadget(&asset_var, &amount_var, &blind_var, &pk_x_var, &pk_y_var)?;

        // Compute and verify nullifier/freezer
        let computed_nullifier = nullifier_gadget(&computed_commitment, &sk_var)?;
        let computed_freezer = nullifier_gadget(&computed_commitment, &pk_x_var)?;

        // Verify nullifier matches public input
        computed_nullifier.enforce_equal(&nullifier_var)?;
        computed_freezer.enforce_equal(&freezer_var)?;

        // Verify Merkle tree membership
        let commitment_hash = self.input.commit();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(commitment_hash))?;

        // The leaf should match the computed commitment
        leaf_var.enforce_equal(&computed_commitment)?;

        let mut left_nodes = vec![];
        let mut right_nodes = vec![];
        for node in &self.merkle_proof.nodes {
            left_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.left))?);
            right_nodes.push(FpVar::new_witness(cs.clone(), || Ok(node.right))?);
        }

        let merkle_valid =
            merkle_proof_gadget(&leaf_var, &left_nodes, &right_nodes, &merkle_root_var)?;
        merkle_valid.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

/// Setup the Groth16 proving and verification keys for a circuit with given shape
/// num_inputs: number of input UTXOs
/// num_outputs: number of output UTXOs
pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> crate::Result<(ProvingKey, VerifyingKey)> {
    // Create a dummy circuit for setup matching the desired shape
    // The circuit needs witness data for constraint generation
    let keypair = Keypair::generate(rng);

    let input = OpenCommitment::generate(rng, 0, 0, keypair.public);

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

    let dummy_circuit = WithdrawCircuit {
        keypair,
        asset: 1,
        amount: 1,
        recipient: Fr::from(0u64),
        fee: 0,
        relayer: Fr::from(0u64),
        input,
        merkle_proof,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)
        .map_err(|_e| AzError::Groth16Setup)?;

    Ok((pk, vk))
}

/// Generate a Groth16 proof for a UTXO transaction
pub fn prove<R: Rng + CryptoRng>(
    pk: &ProvingKey,
    circuit: WithdrawCircuit,
    rng: &mut R,
) -> crate::Result<Proof> {
    Groth16::<Bn254>::prove(pk, circuit, rng).map_err(|_| AzError::Groth16Prove)
}

/// Verify a Groth16 proof for a UTXO transaction
pub fn verify(vk: &VerifyingKey, utxo: &Withdraw, proof: &Proof) -> crate::Result<()> {
    let publics = utxo.public_inputs();

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
    fn test_withdraw_prove_verify() {
        let rng = &mut ChaCha20Rng::from_seed([3u8; 32]);

        // Create keypair
        let keypair = Keypair::generate(rng);
        let asset = 1;
        let amount = 100;

        // Create a merkle tree
        let storage = MemoryStorage::default();
        let mut merkle = MerkleTree::new(0, storage).unwrap();

        // Create input UTXO
        let input = OpenCommitment::generate(rng, asset, amount, keypair.public);

        // Add to merkle tree
        let index = merkle.add_leaf(input.commit()).unwrap();
        merkle.commit().unwrap();

        let merkle_root = merkle.get_root().unwrap();
        let merkle_proof = merkle.generate_proof(index).unwrap();

        // Setup
        let (pk, vk) = setup(rng).unwrap();
        let mut pk_bytes = vec![];
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        let cs_size = pk.a_query.len();
        let num_public_inputs = pk.vk.gamma_abc_g1.len() - 1;

        println!(
            "withdraw: cs_size: {}, public_inputs: {}, pk: {} MB - vk: {} B",
            cs_size,
            num_public_inputs,
            pk_bytes.len() / 1024 / 1024,
            vk_bytes.len()
        );

        // Create circuit
        let recipient = Fr::from(0xdead_beefu64);
        let circuit = WithdrawCircuit {
            keypair,
            asset,
            amount,
            recipient,
            fee: 3,
            relayer: Fr::from(0x5e1a_u64),
            input,
            merkle_proof,
        };

        let utxo = circuit.withdraw();
        assert_eq!(utxo.merkle_root, merkle_root);

        // Prove
        let proof = prove(&pk, circuit, rng).unwrap();

        // Verify
        verify(&vk, &utxo, &proof).unwrap();

        // A different recipient or fee must not verify (front-running protection)
        let mut stolen = utxo.clone();
        stolen.recipient = Fr::from(0xbad_u64);
        assert!(verify(&vk, &stolen, &proof).is_err());

        let mut refee = utxo.clone();
        refee.fee = 4;
        assert!(verify(&vk, &refee, &proof).is_err());

        let mut stolen_fee = utxo.clone();
        stolen_fee.relayer = Fr::from(0xbad_u64);
        assert!(verify(&vk, &stolen_fee, &proof).is_err());
    }
}
