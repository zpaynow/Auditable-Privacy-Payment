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
    use crate::{Blind, OpenCommitment, PublicKey};
    use ark_ed_on_bn254::{EdwardsAffine, Fr as EdFr};
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_commitment_gadget() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test data
        let asset = 1u64;
        let amount = 100u128;
        let blind = Fr::rand(rng);

        // Create a random point for owner
        let owner_point = EdwardsAffine::rand(rng);
        let owner = PublicKey(owner_point);

        // Compute native commitment
        let open_comm = OpenCommitment {
            asset,
            amount,
            blind,
            owner: owner.clone(),
            memo: None,
            audit: None,
            leaf: None,
        };
        let expected = open_comm.commit();

        // Circuit computation
        let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(asset))).unwrap();
        let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(amount))).unwrap();
        let blind_var = FpVar::new_witness(cs.clone(), || Ok(blind)).unwrap();
        let owner_x_var = FpVar::new_witness(cs.clone(), || Ok(owner.0.x)).unwrap();
        let owner_y_var = FpVar::new_witness(cs.clone(), || Ok(owner.0.y)).unwrap();

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
