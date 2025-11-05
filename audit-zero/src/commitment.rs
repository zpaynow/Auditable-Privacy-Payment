use crate::poseidon::poseidon_hash_gadget;
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Circuit gadget for computing commitment
/// Commitment = Poseidon(asset, amount, blind, owner.x, owner.y)
pub fn commitment_gadget(
    asset: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    blind: &FpVar<Fr>,
    owner_x: &FpVar<Fr>,
    owner_y: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inputs = vec![
        asset.clone(),
        amount.clone(),
        blind.clone(),
        owner_x.clone(),
        owner_y.clone(),
    ];

    poseidon_hash_gadget(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, OpenCommitment};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{UniformRand, rand::SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_commitment_gadget() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test data
        let asset = 1u64;
        let amount = 100u128;
        let blind = Fr::rand(rng);

        // Create a random point for owner
        let keypair = Keypair::generate(rng);

        // Compute native commitment
        let open_comm = OpenCommitment {
            asset,
            amount,
            blind,
            owner: keypair.public,
            memo: None,
            audit: None,
        };
        let expected = open_comm.commit();

        // Circuit computation
        let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(asset))).unwrap();
        let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(amount))).unwrap();
        let blind_var = FpVar::new_witness(cs.clone(), || Ok(blind)).unwrap();
        let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.x)).unwrap();
        let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.y)).unwrap();

        let result = commitment_gadget(
            &asset_var,
            &amount_var,
            &blind_var,
            &owner_x_var,
            &owner_y_var,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);
    }
}
