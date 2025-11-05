use ark_ed_on_bn254::{EdwardsAffine, Fr};

/// BabyJubjub: PublicKey to receive the amount
#[derive(Clone)]
pub struct PublicKey(pub EdwardsAffine);

/// BabyJubjub: SecretKey to spent the output
#[derive(Clone)]
pub struct SecretKey(pub Fr);

/// Main keypair
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}
