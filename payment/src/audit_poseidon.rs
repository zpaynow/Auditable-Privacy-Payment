use crate::{AzError, Keypair, PublicKey, Result, SecretKey, poseidon::poseidon_hash};
use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::EdwardsAffine;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};

/// Poseidon-based hybrid encryption for audit (SNARK-friendly) - byte-based version
///
/// This uses ECDH + Poseidon hash for key derivation + Poseidon stream cipher
/// This is the byte-packing version, kept for tests. Production uses field-element version.
///
/// Returns: (ciphertext_bytes, ephemeral_secret_as_Fr)
#[allow(dead_code)]
pub fn audit_encrypt_poseidon<R: CryptoRng + Rng>(
    prng: &mut R,
    auditor_pk: &PublicKey,
    ptext: &[u8],
) -> Result<(Vec<u8>, Fr)> {
    // 1. Generate ephemeral keypair for ECDH
    let ephemeral_secret = SecretKey::rand(prng);
    let ephemeral_keypair = Keypair::from_secret(ephemeral_secret);

    // 2. Compute shared secret: shared = auditor_pk * ephemeral_sk
    let shared = *auditor_pk * ephemeral_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive encryption key using Poseidon: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Pack plaintext bytes into field elements
    // Each Fr can hold up to 31 bytes (to stay within field modulus)
    let plaintexts = pack_bytes_to_field_elements(ptext)?;

    // 5. Encrypt using Poseidon stream cipher
    // ciphertext[i] = plaintext[i] + Poseidon(key, nonce=0, i)
    let mut ciphertexts = Vec::with_capacity(plaintexts.len());
    for (i, plaintext) in plaintexts.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let ciphertext = *plaintext + keystream;
        ciphertexts.push(ciphertext);
    }

    // 6. Serialize: ephemeral_pk || ciphertexts
    let mut bytes = vec![];

    // Serialize ephemeral public key (compressed: 32 bytes)
    ephemeral_keypair
        .public
        .serialize_compressed(&mut bytes)
        .map_err(|_| AzError::Encryption)?;

    // Serialize ciphertexts (32 bytes each)
    for ct in &ciphertexts {
        ct.serialize_compressed(&mut bytes)
            .map_err(|_| AzError::Encryption)?;
    }

    // Convert ephemeral secret to Fr for circuit proof
    let ephemeral_secret_fr = ephemeral_keypair.secret_to_fq();

    Ok((bytes, ephemeral_secret_fr))
}

/// Poseidon-based hybrid encryption for field elements (aligned with circuit)
///
/// This version encrypts field elements directly, matching the circuit gadget.
/// Encrypts: [asset, amount, owner_x, owner_y, nullifier] (5 field elements)
///
/// Returns: (ciphertext_bytes, ephemeral_secret_as_Fr)
pub fn audit_encrypt_field_elements<R: CryptoRng + Rng>(
    prng: &mut R,
    auditor_pk: &PublicKey,
    field_elements: &[Fr],
) -> Result<(Vec<u8>, Fr)> {
    // 1. Generate ephemeral keypair for ECDH
    let ephemeral_secret = SecretKey::rand(prng);
    let ephemeral_keypair = Keypair::from_secret(ephemeral_secret);

    // 2. Compute shared secret: shared = auditor_pk * ephemeral_sk
    let shared = *auditor_pk * ephemeral_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive encryption key using Poseidon: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Encrypt using Poseidon stream cipher
    // ciphertext[i] = plaintext[i] + Poseidon(key, nonce=0, i)
    let mut ciphertexts = Vec::with_capacity(field_elements.len());
    for (i, plaintext) in field_elements.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let ciphertext = *plaintext + keystream;
        ciphertexts.push(ciphertext);
    }

    // 5. Serialize: ephemeral_pk || ciphertexts
    let mut bytes = vec![];

    // Serialize ephemeral public key (compressed: 32 bytes)
    ephemeral_keypair
        .public
        .serialize_compressed(&mut bytes)
        .map_err(|_| AzError::Encryption)?;

    // Serialize ciphertexts (32 bytes each)
    for ct in &ciphertexts {
        ct.serialize_compressed(&mut bytes)
            .map_err(|_| AzError::Encryption)?;
    }

    // Convert ephemeral secret to Fr for circuit proof
    let ephemeral_secret_fr = ephemeral_keypair.secret_to_fq();

    Ok((bytes, ephemeral_secret_fr))
}

/// Decrypts field element ciphertext
///
/// Returns the decrypted field elements
pub fn audit_decrypt_field_elements(auditor_keypair: &Keypair, ctext: &[u8]) -> Result<Vec<Fr>> {
    // 1. Deserialize ephemeral public key (32 bytes compressed)
    let pk_size = auditor_keypair.public.compressed_size();
    if ctext.len() < pk_size {
        return Err(AzError::Decryption);
    }

    let ephemeral_pk = EdwardsAffine::deserialize_compressed(&ctext[..pk_size])
        .map_err(|_| AzError::Decryption)?;

    // 2. Compute shared secret: shared = ephemeral_pk * auditor_sk
    let shared = ephemeral_pk * auditor_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive decryption key: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Deserialize ciphertexts (32 bytes each)
    let remaining = &ctext[pk_size..];
    if remaining.len() % 32 != 0 {
        return Err(AzError::Decryption);
    }

    let num_blocks = remaining.len() / 32;
    let mut ciphertexts = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        let start = i * 32;
        let end = start + 32;
        let ct =
            Fr::deserialize_compressed(&remaining[start..end]).map_err(|_| AzError::Decryption)?;
        ciphertexts.push(ct);
    }

    // 5. Decrypt using Poseidon stream cipher
    // plaintext[i] = ciphertext[i] - Poseidon(key, nonce=0, i)
    let mut plaintexts = Vec::with_capacity(ciphertexts.len());
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let plaintext = *ciphertext - keystream;
        plaintexts.push(plaintext);
    }

    Ok(plaintexts)
}

/// Poseidon-based hybrid decryption - byte-based version
///
/// This is the byte-unpacking version, kept for tests. Production uses field-element version.
#[allow(dead_code)]
pub fn audit_decrypt_poseidon(auditor_keypair: &Keypair, ctext: &[u8]) -> Result<Vec<u8>> {
    // 1. Deserialize ephemeral public key (32 bytes compressed)
    let pk_size = auditor_keypair.public.compressed_size();
    if ctext.len() < pk_size {
        return Err(AzError::Decryption);
    }

    let ephemeral_pk = EdwardsAffine::deserialize_compressed(&ctext[..pk_size])
        .map_err(|_| AzError::Decryption)?;

    // 2. Compute shared secret: shared = ephemeral_pk * auditor_sk
    let shared = ephemeral_pk * auditor_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive decryption key: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Deserialize ciphertexts (32 bytes each)
    let remaining = &ctext[pk_size..];
    if remaining.len() % 32 != 0 {
        return Err(AzError::Decryption);
    }

    let num_blocks = remaining.len() / 32;
    let mut ciphertexts = Vec::with_capacity(num_blocks);

    for i in 0..num_blocks {
        let start = i * 32;
        let end = start + 32;
        let ct =
            Fr::deserialize_compressed(&remaining[start..end]).map_err(|_| AzError::Decryption)?;
        ciphertexts.push(ct);
    }

    // 5. Decrypt using Poseidon stream cipher
    // plaintext[i] = ciphertext[i] - Poseidon(key, nonce=0, i)
    let mut plaintexts = Vec::with_capacity(ciphertexts.len());
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let plaintext = *ciphertext - keystream;
        plaintexts.push(plaintext);
    }

    // 6. Unpack field elements back to bytes
    unpack_field_elements_to_bytes(&plaintexts)
}

/// Pack bytes into field elements (31 bytes per element to stay safe)
#[allow(dead_code)]
fn pack_bytes_to_field_elements(bytes: &[u8]) -> Result<Vec<Fr>> {
    const BYTES_PER_ELEMENT: usize = 31;

    let num_elements = (bytes.len() + BYTES_PER_ELEMENT - 1) / BYTES_PER_ELEMENT;
    let mut elements = Vec::with_capacity(num_elements);

    for i in 0..num_elements {
        let start = i * BYTES_PER_ELEMENT;
        let end = std::cmp::min(start + BYTES_PER_ELEMENT, bytes.len());
        let chunk = &bytes[start..end];

        // Pad with the chunk length as the last byte for proper unpacking
        let mut padded = [0u8; 32];
        padded[..chunk.len()].copy_from_slice(chunk);
        padded[31] = chunk.len() as u8; // Store length in last byte

        let element = Fr::from_le_bytes_mod_order(&padded);
        elements.push(element);
    }

    Ok(elements)
}

/// Unpack field elements back to bytes
#[allow(dead_code)]
fn unpack_field_elements_to_bytes(elements: &[Fr]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();

    for element in elements {
        let element_bytes = element.into_bigint().to_bytes_le();

        // Last byte contains the actual data length
        if element_bytes.len() < 32 {
            return Err(AzError::Decryption);
        }

        let length = element_bytes[31] as usize;
        if length > 31 {
            return Err(AzError::Decryption);
        }

        bytes.extend_from_slice(&element_bytes[..length]);
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_pack_unpack() {
        let data = b"Hello World! This is a test message.";
        let elements = pack_bytes_to_field_elements(data).unwrap();
        let unpacked = unpack_field_elements_to_bytes(&elements).unwrap();
        assert_eq!(data.to_vec(), unpacked);
    }

    #[test]
    fn test_audit_encrypt_decrypt_poseidon() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);

        // Generate auditor keypair
        let auditor = Keypair::generate(rng);

        // Test data
        let plaintext = b"asset: 1, amount: 100, owner: 0x123...";

        // Encrypt
        let (ciphertext, _ephemeral_secret) =
            audit_encrypt_poseidon(rng, &auditor.public, plaintext).unwrap();

        // Decrypt
        let decrypted = audit_decrypt_poseidon(&auditor, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_audit_encrypt_decrypt_long_message() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);

        let auditor = Keypair::generate(rng);

        // Long message that requires multiple field elements
        let plaintext = vec![0x42u8; 120]; // 120 bytes = 4 field elements

        let (ciphertext, _) = audit_encrypt_poseidon(rng, &auditor.public, &plaintext).unwrap();

        let decrypted = audit_decrypt_poseidon(&auditor, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_keys_fail() {
        let rng = &mut ChaCha20Rng::from_seed([44u8; 32]);

        let auditor1 = Keypair::generate(rng);
        let auditor2 = Keypair::generate(rng);

        let plaintext = b"secret message";

        let (ciphertext, _) = audit_encrypt_poseidon(rng, &auditor1.public, plaintext).unwrap();

        // Try to decrypt with wrong key
        let decrypted = audit_decrypt_poseidon(&auditor2, &ciphertext).unwrap();

        // Should produce garbage, not the original plaintext
        assert_ne!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_field_element_encrypt_decrypt() {
        let rng = &mut ChaCha20Rng::from_seed([45u8; 32]);

        let auditor = Keypair::generate(rng);

        // Test field elements: [asset, amount, owner_x, owner_y, nullifier]
        let field_elements = vec![
            Fr::from(1u64),      // asset
            Fr::from(100u64),    // amount
            Fr::from(123456u64), // owner_x (simplified)
            Fr::from(789012u64), // owner_y (simplified)
            Fr::from(999999u64), // nullifier (simplified)
        ];

        let (ciphertext, _ephemeral_secret) =
            audit_encrypt_field_elements(rng, &auditor.public, &field_elements).unwrap();

        // Verify ciphertext size: 32 (ephemeral_pk) + 5*32 (ciphertexts) = 192 bytes
        assert_eq!(ciphertext.len(), 192);

        let decrypted = audit_decrypt_field_elements(&auditor, &ciphertext).unwrap();

        assert_eq!(field_elements, decrypted);
    }

    #[test]
    fn test_field_element_different_keys_fail() {
        let rng = &mut ChaCha20Rng::from_seed([46u8; 32]);

        let auditor1 = Keypair::generate(rng);
        let auditor2 = Keypair::generate(rng);

        let field_elements = vec![Fr::from(1u64), Fr::from(100u64), Fr::from(123u64)];

        let (ciphertext, _) =
            audit_encrypt_field_elements(rng, &auditor1.public, &field_elements).unwrap();

        // Try to decrypt with wrong key
        let decrypted = audit_decrypt_field_elements(&auditor2, &ciphertext).unwrap();

        // Should produce garbage, not the original field elements
        assert_ne!(field_elements, decrypted);
    }
}
