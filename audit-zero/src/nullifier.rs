use crate::poseidon::poseidon_hash_gadget;
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Circuit gadget for computing nullifier
/// Nullifier = Poseidon(asset, amount, index, pk.x, pk.y, sk)
pub fn nullifier_gadget(
    comm: &FpVar<Fr>,
    asset: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    pk_x: &FpVar<Fr>,
    pk_y: &FpVar<Fr>,
    sk: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inputs = vec![
        comm.clone(),
        asset.clone(),
        amount.clone(),
        pk_x.clone(),
        pk_y.clone(),
        sk.clone(),
    ];

    poseidon_hash_gadget(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, OpenCommitment};
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{UniformRand, rand::SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_nullifier_gadget() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test data
        let asset = 1u64;
        let amount = 100u128;

        let keypair = Keypair::generate(rng);
        let open_comm = OpenCommitment {
            asset,
            amount,
            blind: Fr::rand(rng),
            owner: keypair.public.clone(),
            memo: None,
            audit: None,
        };
        let comm = open_comm.commit();

        // Compute native nullifier
        let expected = open_comm.nullify(&keypair);

        // Circuit computation
        let sk_bytes = keypair.secret.into_bigint().to_bytes_le();
        let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);

        let comm_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(comm))).unwrap();
        let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(asset))).unwrap();
        let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(amount))).unwrap();
        let pk_x_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.x)).unwrap();
        let pk_y_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.y)).unwrap();
        let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        let result = nullifier_gadget(
            &comm_var,
            &asset_var,
            &amount_var,
            &pk_x_var,
            &pk_y_var,
            &sk_var,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);
    }
}
