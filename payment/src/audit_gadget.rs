use crate::poseidon::poseidon_hash_gadget;
use ark_bn254::Fr;
use ark_ed_on_bn254::EdwardsConfig;
use ark_ff::Field;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::twisted_edwards::AffineVar},
};
use ark_relations::r1cs::SynthesisError;

/// Circuit type for Edwards curve points (Baby JubJub)
type EdwardsVar = AffineVar<EdwardsConfig, FpVar<Fr>>;

/// Proves ECDH shared secret computation: shared = auditor_pk * ephemeral_sk
///
/// Returns (shared_x, shared_y)
///
/// # Constraints
/// - Scalar multiplication: ~2500-3000 constraints
pub fn ecdh_gadget(
    ephemeral_sk: &FpVar<Fr>,
    auditor_pk_x: &FpVar<Fr>,
    auditor_pk_y: &FpVar<Fr>,
) -> Result<(FpVar<Fr>, FpVar<Fr>), SynthesisError> {
    // 1. Reconstruct auditor public key point
    let auditor_pk = EdwardsVar::new(auditor_pk_x.clone(), auditor_pk_y.clone());

    // 2. Convert ephemeral secret key to bits for scalar multiplication
    let sk_bits = ephemeral_sk.to_bits_le()?;

    // 3. Compute shared secret: shared = auditor_pk * ephemeral_sk
    let shared = auditor_pk.scalar_mul_le(sk_bits.iter())?;

    // 4. Return coordinates
    Ok((shared.x, shared.y))
}

/// Derives encryption key from shared secret using Poseidon
///
/// key = Poseidon(shared_x, shared_y)
///
/// # Constraints
/// - Poseidon hash: ~150-200 constraints
pub fn derive_key_gadget(
    shared_x: &FpVar<Fr>,
    shared_y: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(&[shared_x.clone(), shared_y.clone()])
}

/// Pack asset (u64) and amount (u128) into a single field element
/// Layout: [asset (64 bits) || amount (128 bits)] = 192 bits total
///
/// # Constraints
/// - Bit decomposition: ~192 constraints
/// - Reconstruction: ~1 constraint
/// - Total: ~193 constraints
pub fn pack_asset_amount_gadget(
    asset: &FpVar<Fr>,
    amount: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let cs = asset.cs();

    // Compute: packed = asset * 2^128 + amount
    let shift_constant = FpVar::new_constant(cs, Fr::from(2u128).pow([128]))?;
    let packed = asset * &shift_constant + amount;

    Ok(packed)
}

/// Packs field elements from inputs (asset_amount_packed, owner, nullifier)
///
/// # Constraints
/// - Negligible (just organization of existing variables)
pub fn pack_audit_plaintext_gadget(
    asset_amount_packed: &FpVar<Fr>,
    owner_x: &FpVar<Fr>,
    owner_y: &FpVar<Fr>,
    nullifier: &FpVar<Fr>,
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    // For audit, we encrypt: asset_amount_packed (1 Fr) | owner (2 Fr) | nullifier (1 Fr)
    // Total: 4 field elements
    Ok(vec![
        asset_amount_packed.clone(),
        owner_x.clone(),
        owner_y.clone(),
        nullifier.clone(),
    ])
}

/// Poseidon stream cipher: generates keystream and encrypts
///
/// ciphertext[i] = plaintext[i] + Poseidon(key, nonce, i)
///
/// # Constraints
/// - Poseidon hash per block: ~150-200 constraints
/// - For 5 blocks: ~750-1000 constraints
pub fn poseidon_stream_cipher_gadget(
    key: &FpVar<Fr>,
    nonce: &FpVar<Fr>,
    plaintexts: &[FpVar<Fr>],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    let cs = key.cs();
    let mut ciphertexts = Vec::with_capacity(plaintexts.len());

    for (i, plaintext) in plaintexts.iter().enumerate() {
        // Generate keystream: Poseidon(key, nonce, i)
        let counter = FpVar::new_constant(cs.clone(), Fr::from(i as u64))?;
        let keystream = poseidon_hash_gadget(&[key.clone(), nonce.clone(), counter])?;

        // Encrypt: ciphertext = plaintext + keystream
        let ciphertext = plaintext + &keystream;
        ciphertexts.push(ciphertext);
    }

    Ok(ciphertexts)
}

/// Full audit encryption proof gadget
///
/// Proves that the ciphertext is correctly encrypted using Poseidon-based encryption:
/// 1. ECDH: shared = auditor_pk * ephemeral_sk
/// 2. Key derivation: key = Poseidon(shared_x, shared_y)
/// 3. Pack asset+amount: asset_amount = asset * 2^128 + amount
/// 4. Pack plaintext: [asset_amount, owner_x, owner_y, nullifier]
/// 5. Encrypt: ciphertext[i] = plaintext[i] + Poseidon(key, 0, i)
///
/// # Arguments
/// * `ephemeral_sk` - Ephemeral secret key (witness)
/// * `auditor_pk_x` - Auditor public key X coordinate (public or witness)
/// * `auditor_pk_y` - Auditor public key Y coordinate (public or witness)
/// * `asset` - Asset ID (witness)
/// * `amount` - Amount (witness)
/// * `owner_x` - Owner public key X (witness)
/// * `owner_y` - Owner public key Y (witness)
/// * `nullifier` - Nullifier (witness, already proven elsewhere)
/// * `expected_ciphertexts` - Expected ciphertext field elements to verify against (4 elements)
///
/// # Constraints
/// - ECDH: ~2500-3000 constraints
/// - Key derivation: ~150-200 constraints
/// - Asset+amount packing: ~1 constraint
/// - Stream cipher (4 blocks): ~600-800 constraints
/// - Equality checks: ~4 constraints
/// - **Total: ~3300-4000 constraints per output** (savings from 4 vs 5 blocks!)
pub fn audit_encrypt_gadget(
    ephemeral_sk: &FpVar<Fr>,
    auditor_pk_x: &FpVar<Fr>,
    auditor_pk_y: &FpVar<Fr>,
    asset: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    owner_x: &FpVar<Fr>,
    owner_y: &FpVar<Fr>,
    nullifier: &FpVar<Fr>,
    expected_ciphertexts: &[FpVar<Fr>],
) -> Result<(), SynthesisError> {
    let cs = ephemeral_sk.cs();

    // 1. ECDH: Compute shared secret
    let (shared_x, shared_y) = ecdh_gadget(ephemeral_sk, auditor_pk_x, auditor_pk_y)?;

    // 2. Derive encryption key
    let key = derive_key_gadget(&shared_x, &shared_y)?;

    // 3. Pack asset and amount into single field element
    let asset_amount_packed = pack_asset_amount_gadget(asset, amount)?;

    // 4. Pack plaintext into field elements (4 elements now)
    let plaintexts =
        pack_audit_plaintext_gadget(&asset_amount_packed, owner_x, owner_y, nullifier)?;

    // 5. Encrypt using Poseidon stream cipher
    let nonce = FpVar::new_constant(cs, Fr::from(0u64))?;
    let computed_ciphertexts = poseidon_stream_cipher_gadget(&key, &nonce, &plaintexts)?;

    // 6. Verify ciphertexts match expected values
    if computed_ciphertexts.len() != expected_ciphertexts.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    for (computed, expected) in computed_ciphertexts.iter().zip(expected_ciphertexts.iter()) {
        computed.enforce_equal(expected)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, poseidon::poseidon_hash};
    use ark_ec::CurveGroup;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ecdh_gadget() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        let ephemeral_keypair = Keypair::generate(rng);
        let auditor_keypair = Keypair::generate(rng);

        // Native computation
        let shared_native = auditor_keypair.public * ephemeral_keypair.secret;
        let shared_affine = shared_native.into_affine();

        // Circuit computation
        let ephemeral_sk_var =
            FpVar::new_witness(cs.clone(), || Ok(ephemeral_keypair.secret_to_fq())).unwrap();
        let auditor_pk_x_var =
            FpVar::new_witness(cs.clone(), || Ok(auditor_keypair.public.x)).unwrap();
        let auditor_pk_y_var =
            FpVar::new_witness(cs.clone(), || Ok(auditor_keypair.public.y)).unwrap();

        let (shared_x, shared_y) =
            ecdh_gadget(&ephemeral_sk_var, &auditor_pk_x_var, &auditor_pk_y_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(shared_x.value().unwrap(), shared_affine.x);
        assert_eq!(shared_y.value().unwrap(), shared_affine.y);
    }

    #[test]
    fn test_key_derivation_gadget() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let shared_x = Fr::from(123u64);
        let shared_y = Fr::from(456u64);

        // Native computation
        let key_native = poseidon_hash(&[shared_x, shared_y]);

        // Circuit computation
        let shared_x_var = FpVar::new_witness(cs.clone(), || Ok(shared_x)).unwrap();
        let shared_y_var = FpVar::new_witness(cs.clone(), || Ok(shared_y)).unwrap();

        let key_var = derive_key_gadget(&shared_x_var, &shared_y_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(key_var.value().unwrap(), key_native);
    }

    #[test]
    fn test_stream_cipher_gadget() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let key = Fr::from(789u64);
        let nonce = Fr::from(0u64);
        let plaintexts = vec![Fr::from(100u64), Fr::from(200u64), Fr::from(300u64)];

        // Native computation
        let mut ciphertexts_native = Vec::new();
        for (i, pt) in plaintexts.iter().enumerate() {
            let keystream = poseidon_hash(&[key, nonce, Fr::from(i as u64)]);
            ciphertexts_native.push(*pt + keystream);
        }

        // Circuit computation
        let key_var = FpVar::new_witness(cs.clone(), || Ok(key)).unwrap();
        let nonce_var = FpVar::new_witness(cs.clone(), || Ok(nonce)).unwrap();
        let plaintext_vars: Vec<_> = plaintexts
            .iter()
            .map(|pt| FpVar::new_witness(cs.clone(), || Ok(*pt)).unwrap())
            .collect();

        let ciphertext_vars =
            poseidon_stream_cipher_gadget(&key_var, &nonce_var, &plaintext_vars).unwrap();

        assert!(cs.is_satisfied().unwrap());
        for (computed, expected) in ciphertext_vars.iter().zip(ciphertexts_native.iter()) {
            assert_eq!(computed.value().unwrap(), *expected);
        }
    }
}
