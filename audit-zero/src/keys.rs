use crate::{AzError, Result};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fr};
use ark_ff::Field;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};

/// BabyJubjub: PublicKey to receive the amount
pub type PublicKey = EdwardsAffine;

/// BabyJubjub: SecretKey to spent the output
pub type SecretKey = Fr;

/// Main keypair
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey, // TODO add zeroize
}

impl Keypair {
    /// generate an random keypair
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Keypair {
        let secret = Fr::rand(rng);
        Self::from_secret(secret)
    }

    pub fn from_seed(seed: &[u8]) -> Result<Keypair> {
        let secret = Fr::from_random_bytes(seed).ok_or(AzError::KeypairInvalidSeed)?;
        Ok(Self::from_secret(secret))
    }

    pub fn from_secret(secret: Fr) -> Keypair {
        let public = (EdwardsAffine::generator() * secret).into_affine();

        Keypair { secret, public }
    }
}
