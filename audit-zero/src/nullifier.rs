use crate::poseidon::poseidon_hash_gadget;
use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Circuit gadget for computing nullifier
/// Nullifier = Poseidon(asset, amount, index, pk.x, pk.y, sk)
pub fn nullifier_gadget(
    asset: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    index: &FpVar<Fr>,
    pk_x: &FpVar<Fr>,
    pk_y: &FpVar<Fr>,
    sk: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inputs = vec![
        asset.clone(),
        amount.clone(),
        index.clone(),
        pk_x.clone(),
        pk_y.clone(),
        sk.clone(),
    ];

    poseidon_hash_gadget(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, OpenCommitment, PublicKey, SecretKey, structs::MTProof};
    use ark_ed_on_bn254::{EdwardsAffine, Fr as EdFr};
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_nullifier_gadget() {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test data
        let asset = 1u64;
        let amount = 100u128;
        let index = 42u32;

        let sk = EdFr::rand(rng);
        let pk_point = EdwardsAffine::rand(rng);
        let keypair = Keypair {
            public: PublicKey(pk_point),
            secret: SecretKey(sk),
        };

        // Create mock merkle proof
        let mock_proof = MTProof {
            nodes: vec![],
            ledger: 0,
            root: Fr::from(0u64),
            version: 1,
            index,
        };

        let open_comm = OpenCommitment {
            asset,
            amount,
            blind: Fr::rand(rng),
            owner: keypair.public.clone(),
            memo: None,
            audit: None,
            leaf: Some(mock_proof),
        };

        // Compute native nullifier
        let expected = open_comm.nullify(&keypair);

        // Circuit computation
        let sk_bytes = sk.into_bigint().to_bytes_le();
        let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);

        let asset_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(asset))).unwrap();
        let amount_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(amount))).unwrap();
        let index_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(index))).unwrap();
        let pk_x_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.0.x)).unwrap();
        let pk_y_var = FpVar::new_witness(cs.clone(), || Ok(keypair.public.0.y)).unwrap();
        let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        let result = nullifier_gadget(
            &asset_var,
            &amount_var,
            &index_var,
            &pk_x_var,
            &pk_y_var,
            &sk_var,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);
    }
}
