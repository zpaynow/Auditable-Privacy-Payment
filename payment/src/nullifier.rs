use crate::poseidon::poseidon_hash_gadget;
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Circuit gadget for computing nullifier/freezer
/// Nullifier = Poseidon(comm, sk)
pub fn nullifier_gadget(comm: &FpVar<Fr>, sk: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(&[comm.clone(), sk.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, OpenCommitment};
    use ark_ff::PrimeField;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_nullifier_gadget() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let keypair = Keypair::generate(rng);

        // Create test data
        let asset = 1u64;
        let amount = 100u128;

        let open_comm = OpenCommitment::generate(rng, asset, amount, keypair.public);
        let comm = open_comm.commit();

        // Compute native nullifier
        let expected = open_comm.nullify(&keypair);

        // Circuit computation
        let sk_int = keypair.secret.into_bigint();
        let sk_fr = Fr::from_bigint(sk_int).unwrap();

        let comm_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm))).unwrap();
        let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        let result = nullifier_gadget(&comm_var, &sk_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);
    }
}
