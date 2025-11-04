use ark_bn254::{Fr, G1Projective};

/// PublicKey to receive the amount
pub struct PublicKey(pub G1Projective);

/// SecretKey to spent the output
pub struct SecretKey(pub Fr);

/// Main keypair
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}
