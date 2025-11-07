use crate::{AzError, Keypair, PublicKey, Result, SecretKey};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use ark_ed_on_bn254::{EdwardsAffine, Fq};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};
use sha2::{Digest, Sha256};

/// Hybrid encryption
pub fn audit_encrypt<R: CryptoRng + Rng>(
    prng: &mut R,
    pk: &PublicKey,
    ptext: &[u8],
) -> Result<(Vec<u8>, Fq)> {
    let secret = SecretKey::rand(prng);
    let share_keypair = Keypair::from_secret(secret);
    let dh = *pk * share_keypair.secret;

    let mut bytes = vec![];
    share_keypair
        .public
        .serialize_compressed(&mut bytes)
        .map_err(|_| AzError::Encryption)?;

    let mut dh_bytes = vec![];
    dh.serialize_compressed(&mut dh_bytes)
        .map_err(|_| AzError::Encryption)?;

    let mut hasher = Sha256::new();
    hasher.update(&dh_bytes);

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());

    let gcm = {
        let res = Aes256Gcm::new_from_slice(key.as_slice());

        if res.is_err() {
            return Err(AzError::Encryption);
        }

        res.unwrap()
    };

    let mut ctext = {
        let res = gcm.encrypt(&[0u8; 12].into(), ptext);

        if res.is_err() {
            return Err(AzError::Encryption);
        }

        res.unwrap()
    };

    bytes.append(&mut ctext);
    Ok((bytes, share_keypair.secret_to_fq()))
}

/// Hybrid decryption
pub fn audit_decrypt(keypair: &Keypair, ctext: &[u8]) -> Result<Vec<u8>> {
    let share_len = keypair.public.compressed_size();
    if ctext.len() < share_len {
        return Err(AzError::Decryption);
    }

    let share = EdwardsAffine::deserialize_compressed(&ctext[..share_len])
        .map_err(|_| AzError::Decryption)?;
    let dh = share * keypair.secret;

    let mut dh_bytes = vec![];
    dh.serialize_compressed(&mut dh_bytes)
        .map_err(|_| AzError::Encryption)?;

    let mut hasher = Sha256::new();
    hasher.update(&dh_bytes);

    let mut key = [0u8; 32];
    key.copy_from_slice(&hasher.finalize());

    let gcm = {
        let res = Aes256Gcm::new_from_slice(key.as_slice());

        if res.is_err() {
            return Err(AzError::Decryption);
        }

        res.unwrap()
    };

    let res = {
        let res = gcm.decrypt(&[0u8; 12].into(), &ctext[share_len..]);

        if res.is_err() {
            return Err(AzError::Decryption);
        }

        res.unwrap()
    };

    Ok(res)
}
