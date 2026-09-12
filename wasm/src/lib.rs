use wasm_bindgen::prelude::*;
use app_payment::{
    Keypair, OpenCommitment, MTProof, MTNode, TREE_DEPTH, deposit, transfer, withdraw
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_ed_on_bn254::EdwardsAffine;

// =============================================================================
// Keypair Operations
// =============================================================================

#[wasm_bindgen]
pub struct WasmKeypair {
    inner: Keypair,
}

#[wasm_bindgen]
impl WasmKeypair {
    /// Derive a keypair deterministically from any non-empty seed
    /// (e.g. the bytes of a wallet signature). Hash-to-scalar, never fails.
    #[wasm_bindgen(constructor)]
    pub fn from_seed(seed: &[u8]) -> std::result::Result<WasmKeypair, JsValue> {
        let keypair = Keypair::from_seed(seed)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate keypair: {:?}", e)))?;
        Ok(WasmKeypair { inner: keypair })
    }

    /// Restore a keypair from its 32-byte secret (as returned by `secret_key`).
    #[wasm_bindgen]
    pub fn from_secret(secret: &[u8]) -> std::result::Result<WasmKeypair, JsValue> {
        let keypair = Keypair::from_secret_bytes(secret)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret: {:?}", e)))?;
        Ok(WasmKeypair { inner: keypair })
    }

    /// Generate a random keypair from a random seed
    #[wasm_bindgen]
    pub fn random(seed: &[u8]) -> std::result::Result<WasmKeypair, JsValue> {
        if seed.len() != 32 {
            return Err(JsValue::from_str("Random seed must be 32 bytes"));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        let mut rng = ChaCha20Rng::from_seed(seed_array);

        let keypair = Keypair::generate(&mut rng);
        Ok(WasmKeypair { inner: keypair })
    }

    /// Export public key as bytes (compressed, 32 bytes for x + 32 bytes for y)
    #[wasm_bindgen]
    pub fn public_key(&self) -> std::result::Result<Vec<u8>, JsValue> {
        let mut bytes = Vec::new();
        self.inner.public.x.serialize_compressed(&mut bytes)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;
        self.inner.public.y.serialize_compressed(&mut bytes)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;
        Ok(bytes)
    }

    /// Export secret key as bytes (compressed, 32 bytes)
    #[wasm_bindgen]
    pub fn secret_key(&self) -> std::result::Result<Vec<u8>, JsValue> {
        let mut bytes = Vec::new();
        self.inner.secret.serialize_compressed(&mut bytes)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {:?}", e)))?;
        Ok(bytes)
    }
}

// =============================================================================
// Deposit Operations
// =============================================================================

/// Setup deposit circuit (returns proving key and verifying key as bytes)
#[wasm_bindgen]
pub fn deposit_setup(is_audit: bool, seed: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    let (pk, vk) = deposit::setup(is_audit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Setup failed: {:?}", e)))?;

    let mut result = Vec::new();

    // Serialize proving key
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("PK serialization error: {:?}", e)))?;

    // Serialize verifying key
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("VK serialization error: {:?}", e)))?;

    // Pack: [pk_len (4 bytes) | pk_bytes | vk_bytes]
    result.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&pk_bytes);
    result.extend_from_slice(&vk_bytes);

    Ok(result)
}

/// Generate deposit proof
/// Parameters:
/// - pk_bytes: proving key bytes
/// - asset: asset id (u64)
/// - amount: amount (u128, as two u64s: low, high)
/// - owner_pk: owner public key bytes (64 bytes)
/// - blind: blind factor bytes (32 bytes)
/// - auditor_pk: optional auditor public key (64 bytes), empty if not audited
/// - audit_memo: optional audit memo bytes, empty if not audited
/// - audit_share: optional audit share bytes (32 bytes), empty if not audited
/// - seed: random seed (32 bytes)
#[wasm_bindgen]
pub fn deposit_prove(
    pk_bytes: &[u8],
    asset: u64,
    amount_low: u64,
    amount_high: u64,
    owner_pk: &[u8],
    blind: &[u8],
    auditor_pk: &[u8],
    audit_memo: &[u8],
    audit_share: &[u8],
    seed: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {

    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }
    if owner_pk.len() != 64 {
        return Err(JsValue::from_str("Owner public key must be 64 bytes"));
    }
    if blind.len() != 32 {
        return Err(JsValue::from_str("Blind must be 32 bytes"));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    // Deserialize proving key
    let pk = transfer::ProvingKey::deserialize_compressed(pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("PK deserialization error: {:?}", e)))?;

    // Parse amount from two u64s
    let amount: u128 = ((amount_high as u128) << 64) | (amount_low as u128);

    // Parse owner public key
    let owner_x = Fr::deserialize_compressed(&owner_pk[..32])
        .map_err(|e| JsValue::from_str(&format!("Owner x deserialization error: {:?}", e)))?;
    let owner_y = Fr::deserialize_compressed(&owner_pk[32..])
        .map_err(|e| JsValue::from_str(&format!("Owner y deserialization error: {:?}", e)))?;
    let owner = EdwardsAffine::new_unchecked(owner_x, owner_y);

    // Parse blind
    let blind_fr = Fr::deserialize_compressed(blind)
        .map_err(|e| JsValue::from_str(&format!("Blind deserialization error: {:?}", e)))?;

    let output = OpenCommitment {
        asset,
        amount,
        owner,
        blind: blind_fr,
    };

    // Handle audit if provided
    let audit = if !auditor_pk.is_empty() {
        if auditor_pk.len() != 64 {
            return Err(JsValue::from_str("Auditor public key must be 64 bytes"));
        }
        if audit_share.len() != 32 {
            return Err(JsValue::from_str("Audit share must be 32 bytes"));
        }

        let auditor_x = Fr::deserialize_compressed(&auditor_pk[..32])
            .map_err(|e| JsValue::from_str(&format!("Auditor x deserialization error: {:?}", e)))?;
        let auditor_y = Fr::deserialize_compressed(&auditor_pk[32..])
            .map_err(|e| JsValue::from_str(&format!("Auditor y deserialization error: {:?}", e)))?;
        let auditor = EdwardsAffine::new_unchecked(auditor_x, auditor_y);

        let share = Fr::deserialize_compressed(audit_share)
            .map_err(|e| JsValue::from_str(&format!("Share deserialization error: {:?}", e)))?;

        Some(deposit::AuditCircuit {
            auditor,
            memo: audit_memo.to_vec(),
            share,
        })
    } else {
        None
    };

    let circuit = deposit::DepositCircuit {
        asset,
        amount,
        output,
        audit,
    };

    let proof = deposit::prove(&pk, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {:?}", e)))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Proof serialization error: {:?}", e)))?;

    Ok(proof_bytes)
}

/// Verify deposit proof
/// Returns commitment bytes (32 bytes) on success
#[wasm_bindgen]
pub fn deposit_verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    asset: u64,
    amount_low: u64,
    amount_high: u64,
    commitment: &[u8],
    auditor_pk: &[u8],
    audit_memo: &[u8],
) -> std::result::Result<bool, JsValue> {

    if commitment.len() != 32 {
        return Err(JsValue::from_str("Commitment must be 32 bytes"));
    }

    let vk = transfer::VerifyingKey::deserialize_compressed(vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("VK deserialization error: {:?}", e)))?;

    let proof = transfer::Proof::deserialize_compressed(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Proof deserialization error: {:?}", e)))?;

    let amount: u128 = ((amount_high as u128) << 64) | (amount_low as u128);

    let commitment_fr = Fr::deserialize_compressed(commitment)
        .map_err(|e| JsValue::from_str(&format!("Commitment deserialization error: {:?}", e)))?;

    let audit = if !auditor_pk.is_empty() {
        if auditor_pk.len() != 64 {
            return Err(JsValue::from_str("Auditor public key must be 64 bytes"));
        }

        let auditor_x = Fr::deserialize_compressed(&auditor_pk[..32])
            .map_err(|e| JsValue::from_str(&format!("Auditor x deserialization error: {:?}", e)))?;
        let auditor_y = Fr::deserialize_compressed(&auditor_pk[32..])
            .map_err(|e| JsValue::from_str(&format!("Auditor y deserialization error: {:?}", e)))?;
        let auditor = EdwardsAffine::new_unchecked(auditor_x, auditor_y);

        Some(deposit::Audit {
            auditor,
            memo: audit_memo.to_vec(),
        })
    } else {
        None
    };

    let deposit = deposit::Deposit {
        asset,
        amount,
        commitment: commitment_fr,
        memo: vec![],
        audit,
    };

    deposit::verify(&vk, &deposit, &proof)
        .map(|_| true)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {:?}", e)))
}

// =============================================================================
// Transfer Operations
// =============================================================================

/// Setup transfer circuit
#[wasm_bindgen]
pub fn transfer_setup(
    num_inputs: usize,
    num_outputs: usize,
    is_audit: bool,
    seed: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    let (pk, vk) = transfer::setup(num_inputs, num_outputs, is_audit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Setup failed: {:?}", e)))?;

    let mut result = Vec::new();

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("PK serialization error: {:?}", e)))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("VK serialization error: {:?}", e)))?;

    result.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&pk_bytes);
    result.extend_from_slice(&vk_bytes);

    Ok(result)
}

// =============================================================================
// Withdraw Operations
// =============================================================================

/// Setup withdraw circuit
#[wasm_bindgen]
pub fn withdraw_setup(seed: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    let (pk, vk) = withdraw::setup(&mut rng)
        .map_err(|e| JsValue::from_str(&format!("Setup failed: {:?}", e)))?;

    let mut result = Vec::new();

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("PK serialization error: {:?}", e)))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("VK serialization error: {:?}", e)))?;

    result.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&pk_bytes);
    result.extend_from_slice(&vk_bytes);

    Ok(result)
}

/// Generate withdraw proof
/// merkle_nodes: flat array of [left, right, left, right, ...] for TREE_DEPTH nodes (32 bytes each)
/// recipient: 20-byte EVM address (big-endian), bound into the proof
/// fee: amount paid to the relayer out of `amount` (u128 as two u64s)
#[wasm_bindgen]
pub fn withdraw_prove(
    pk_bytes: &[u8],
    keypair_secret: &[u8],
    asset: u64,
    amount_low: u64,
    amount_high: u64,
    recipient: &[u8],
    fee_low: u64,
    fee_high: u64,
    input_asset: u64,
    input_amount_low: u64,
    input_amount_high: u64,
    input_owner_pk: &[u8],
    input_blind: &[u8],
    merkle_nodes: &[u8],
    merkle_ledger: u32,
    merkle_root: &[u8],
    merkle_version: u32,
    merkle_index: u32,
    seed: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {

    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }
    if keypair_secret.len() != 32 {
        return Err(JsValue::from_str("Keypair secret must be 32 bytes"));
    }
    if input_owner_pk.len() != 64 {
        return Err(JsValue::from_str("Input owner public key must be 64 bytes"));
    }
    if input_blind.len() != 32 {
        return Err(JsValue::from_str("Input blind must be 32 bytes"));
    }
    if merkle_root.len() != 32 {
        return Err(JsValue::from_str("Merkle root must be 32 bytes"));
    }
    if merkle_nodes.len() != TREE_DEPTH * 2 * 32 {
        return Err(JsValue::from_str(&format!("Merkle nodes must be {} bytes (TREE_DEPTH * 2 * 32)", TREE_DEPTH * 2 * 32)));
    }
    let recipient_fr = address_to_fr(recipient)?;
    let fee: u128 = ((fee_high as u128) << 64) | (fee_low as u128);

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    let keypair = Keypair::from_secret_bytes(keypair_secret)
        .map_err(|e| JsValue::from_str(&format!("Invalid keypair secret: {:?}", e)))?;

    let pk = transfer::ProvingKey::deserialize_compressed(pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("PK deserialization error: {:?}", e)))?;

    let amount: u128 = ((amount_high as u128) << 64) | (amount_low as u128);
    let input_amount: u128 = ((input_amount_high as u128) << 64) | (input_amount_low as u128);

    let input_owner_x = Fr::deserialize_compressed(&input_owner_pk[..32])
        .map_err(|e| JsValue::from_str(&format!("Input owner x deserialization error: {:?}", e)))?;
    let input_owner_y = Fr::deserialize_compressed(&input_owner_pk[32..])
        .map_err(|e| JsValue::from_str(&format!("Input owner y deserialization error: {:?}", e)))?;
    let input_owner = EdwardsAffine::new_unchecked(input_owner_x, input_owner_y);

    let input_blind_fr = Fr::deserialize_compressed(input_blind)
        .map_err(|e| JsValue::from_str(&format!("Input blind deserialization error: {:?}", e)))?;

    let input = OpenCommitment {
        asset: input_asset,
        amount: input_amount,
        owner: input_owner,
        blind: input_blind_fr,
    };

    // Parse merkle proof nodes
    let mut nodes = Vec::new();
    for i in 0..TREE_DEPTH {
        let offset = i * 2 * 32;
        let left = Fr::deserialize_compressed(&merkle_nodes[offset..offset + 32])
            .map_err(|e| JsValue::from_str(&format!("Left node deserialization error: {:?}", e)))?;
        let right = Fr::deserialize_compressed(&merkle_nodes[offset + 32..offset + 64])
            .map_err(|e| JsValue::from_str(&format!("Right node deserialization error: {:?}", e)))?;
        nodes.push(MTNode { left, right });
    }

    let root_fr = Fr::deserialize_compressed(merkle_root)
        .map_err(|e| JsValue::from_str(&format!("Merkle root deserialization error: {:?}", e)))?;

    let merkle_proof = MTProof {
        nodes,
        ledger: merkle_ledger,
        root: root_fr,
        version: merkle_version,
        index: merkle_index,
    };

    let circuit = withdraw::WithdrawCircuit {
        keypair,
        asset,
        amount,
        recipient: recipient_fr,
        fee,
        input,
        merkle_proof,
    };

    let proof = withdraw::prove(&pk, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {:?}", e)))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Proof serialization error: {:?}", e)))?;

    Ok(proof_bytes)
}

/// Verify withdraw proof
#[wasm_bindgen]
pub fn withdraw_verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    asset: u64,
    amount_low: u64,
    amount_high: u64,
    recipient: &[u8],
    fee_low: u64,
    fee_high: u64,
    nullifier: &[u8],
    freezer: &[u8],
    merkle_root: &[u8],
    merkle_version: u32,
) -> std::result::Result<bool, JsValue> {

    if nullifier.len() != 32 {
        return Err(JsValue::from_str("Nullifier must be 32 bytes"));
    }
    if freezer.len() != 32 {
        return Err(JsValue::from_str("Freezer must be 32 bytes"));
    }
    if merkle_root.len() != 32 {
        return Err(JsValue::from_str("Merkle root must be 32 bytes"));
    }

    let vk = transfer::VerifyingKey::deserialize_compressed(vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("VK deserialization error: {:?}", e)))?;

    let proof = transfer::Proof::deserialize_compressed(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Proof deserialization error: {:?}", e)))?;

    let amount: u128 = ((amount_high as u128) << 64) | (amount_low as u128);
    let recipient_fr = address_to_fr(recipient)?;
    let fee: u128 = ((fee_high as u128) << 64) | (fee_low as u128);

    let nullifier_fr = Fr::deserialize_compressed(nullifier)
        .map_err(|e| JsValue::from_str(&format!("Nullifier deserialization error: {:?}", e)))?;
    let freezer_fr = Fr::deserialize_compressed(freezer)
        .map_err(|e| JsValue::from_str(&format!("Freezer deserialization error: {:?}", e)))?;
    let merkle_root_fr = Fr::deserialize_compressed(merkle_root)
        .map_err(|e| JsValue::from_str(&format!("Merkle root deserialization error: {:?}", e)))?;

    let withdraw = withdraw::Withdraw {
        asset,
        amount,
        recipient: recipient_fr,
        fee,
        nullifier: nullifier_fr,
        freezer: freezer_fr,
        merkle_version,
        merkle_root: merkle_root_fr,
    };

    withdraw::verify(&vk, &withdraw, &proof)
        .map(|_| true)
        .map_err(|e| JsValue::from_str(&format!("Verification failed: {:?}", e)))
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Interpret a 20-byte big-endian EVM address as a field element (matches `uint256(uint160(addr))`).
fn address_to_fr(addr: &[u8]) -> std::result::Result<Fr, JsValue> {
    if addr.len() != 20 {
        return Err(JsValue::from_str("Recipient must be a 20-byte address"));
    }
    Ok(Fr::from_be_bytes_mod_order(addr))
}

/// Compute commitment from components
#[wasm_bindgen]
pub fn compute_commitment(
    asset: u64,
    amount_low: u64,
    amount_high: u64,
    owner_pk: &[u8],
    blind: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {

    if owner_pk.len() != 64 {
        return Err(JsValue::from_str("Owner public key must be 64 bytes"));
    }
    if blind.len() != 32 {
        return Err(JsValue::from_str("Blind must be 32 bytes"));
    }

    let amount: u128 = ((amount_high as u128) << 64) | (amount_low as u128);

    let owner_x = Fr::deserialize_compressed(&owner_pk[..32])
        .map_err(|e| JsValue::from_str(&format!("Owner x deserialization error: {:?}", e)))?;
    let owner_y = Fr::deserialize_compressed(&owner_pk[32..])
        .map_err(|e| JsValue::from_str(&format!("Owner y deserialization error: {:?}", e)))?;
    let owner = EdwardsAffine::new_unchecked(owner_x, owner_y);

    let blind_fr = Fr::deserialize_compressed(blind)
        .map_err(|e| JsValue::from_str(&format!("Blind deserialization error: {:?}", e)))?;

    let open_comm = OpenCommitment {
        asset,
        amount,
        owner,
        blind: blind_fr,
    };

    let commitment = open_comm.commit();

    let mut commitment_bytes = Vec::new();
    commitment.serialize_compressed(&mut commitment_bytes)
        .map_err(|e| JsValue::from_str(&format!("Commitment serialization error: {:?}", e)))?;

    Ok(commitment_bytes)
}

/// Generate random bytes for blind factor
#[wasm_bindgen]
pub fn generate_random_blind(seed: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    use ark_std::UniformRand;

    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_array);

    let blind = Fr::rand(&mut rng);

    let mut blind_bytes = Vec::new();
    blind.serialize_compressed(&mut blind_bytes)
        .map_err(|e| JsValue::from_str(&format!("Blind serialization error: {:?}", e)))?;

    Ok(blind_bytes)
}

// =============================================================================
// Helpers shared by the extended API
// =============================================================================

use app_payment::{MemoryStorage, MerkleTree, evm};
use serde::Serialize;

fn js_err<E: core::fmt::Debug>(ctx: &str) -> impl Fn(E) -> JsValue + '_ {
    move |e| JsValue::from_str(&format!("{ctx}: {e:?}"))
}

fn parse_pk(bytes: &[u8]) -> std::result::Result<EdwardsAffine, JsValue> {
    if bytes.len() != 64 {
        return Err(JsValue::from_str("Public key must be 64 bytes (x || y)"));
    }
    let x = Fr::deserialize_compressed(&bytes[..32]).map_err(js_err("pk.x"))?;
    let y = Fr::deserialize_compressed(&bytes[32..]).map_err(js_err("pk.y"))?;
    let p = EdwardsAffine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(JsValue::from_str("Public key is not a valid BabyJubJub point"));
    }
    Ok(p)
}

fn parse_fr(bytes: &[u8], what: &str) -> std::result::Result<Fr, JsValue> {
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!("{what} must be 32 bytes")));
    }
    Fr::deserialize_compressed(bytes).map_err(js_err(what))
}

fn fr_bytes(f: &Fr) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    f.serialize_compressed(&mut v).expect("fr serialize");
    v
}

fn u128_of(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | (lo as u128)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse a serialized Merkle proof blob:
/// nodes (TREE_DEPTH * 64) || root (32) || version (4 LE) || index (4 LE) || ledger (4 LE)
const MT_PROOF_LEN: usize = TREE_DEPTH * 64 + 32 + 12;

fn parse_mt_proof(bytes: &[u8]) -> std::result::Result<MTProof, JsValue> {
    if bytes.len() != MT_PROOF_LEN {
        return Err(JsValue::from_str(&format!("Merkle proof blob must be {MT_PROOF_LEN} bytes")));
    }
    let mut nodes = Vec::with_capacity(TREE_DEPTH);
    for i in 0..TREE_DEPTH {
        let o = i * 64;
        nodes.push(MTNode {
            left: parse_fr(&bytes[o..o + 32], "merkle node")?,
            right: parse_fr(&bytes[o + 32..o + 64], "merkle node")?,
        });
    }
    let o = TREE_DEPTH * 64;
    let root = parse_fr(&bytes[o..o + 32], "merkle root")?;
    let u32_at = |p: usize| u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
    Ok(MTProof {
        nodes,
        root,
        version: u32_at(o + 32),
        index: u32_at(o + 36),
        ledger: u32_at(o + 40),
    })
}

fn serialize_mt_proof(p: &MTProof) -> Vec<u8> {
    p.to_bytes()
}

// =============================================================================
// Local Merkle tree (rebuilt in the browser from on-chain commitments)
// =============================================================================

#[wasm_bindgen]
pub struct WasmMerkleTree {
    inner: MerkleTree<MemoryStorage>,
}

#[wasm_bindgen]
impl WasmMerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new(ledger: u32) -> std::result::Result<WasmMerkleTree, JsValue> {
        let inner = MerkleTree::new(ledger, MemoryStorage::default()).map_err(js_err("merkle new"))?;
        Ok(WasmMerkleTree { inner })
    }

    /// Append a leaf (32-byte commitment, arkworks LE). Returns its index.
    pub fn add_leaf(&mut self, leaf: &[u8]) -> std::result::Result<u32, JsValue> {
        let f = parse_fr(leaf, "leaf")?;
        self.inner.add_leaf(f).map_err(js_err("add_leaf"))
    }

    /// Append many leaves at once (concatenated 32-byte commitments). Returns the next index.
    pub fn add_leaves(&mut self, leaves: &[u8]) -> std::result::Result<u32, JsValue> {
        if leaves.len() % 32 != 0 {
            return Err(JsValue::from_str("leaves must be a multiple of 32 bytes"));
        }
        let mut idx = 0;
        for chunk in leaves.chunks(32) {
            idx = self.inner.add_leaf(parse_fr(chunk, "leaf")?).map_err(js_err("add_leaf"))?;
        }
        Ok(idx + 1)
    }

    /// Persist pending leaves and bump the version. Call after each batch of chain events.
    pub fn commit(&mut self) -> std::result::Result<u32, JsValue> {
        self.inner.commit().map_err(js_err("commit"))
    }

    pub fn root(&self) -> std::result::Result<Vec<u8>, JsValue> {
        Ok(fr_bytes(&self.inner.get_root().map_err(js_err("root"))?))
    }

    /// Root as an EVM `bytes32` (big-endian), directly comparable with the contract.
    pub fn root_evm(&self) -> std::result::Result<Vec<u8>, JsValue> {
        Ok(evm::fr_to_bytes32(&self.inner.get_root().map_err(js_err("root"))?).to_vec())
    }

    pub fn count(&self) -> u32 {
        self.inner.get_count()
    }

    pub fn version(&self) -> u32 {
        self.inner.get_version()
    }

    /// Merkle proof blob for `index` (see `parse_mt_proof` layout). Requires a prior `commit`.
    pub fn proof(&self, index: u32) -> std::result::Result<Vec<u8>, JsValue> {
        let p = self.inner.generate_proof(index).map_err(js_err("generate_proof"))?;
        Ok(serialize_mt_proof(&p))
    }
}

// =============================================================================
// Commitments, nullifiers, memos
// =============================================================================

/// Nullifier = Poseidon(commitment, sk). Needs the owner's secret.
#[wasm_bindgen]
pub fn compute_nullifier(secret: &[u8], asset: u64, amount_low: u64, amount_high: u64, blind: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let kp = Keypair::from_secret_bytes(secret).map_err(js_err("secret"))?;
    let oc = OpenCommitment { asset, amount: u128_of(amount_low, amount_high), owner: kp.public, blind: parse_fr(blind, "blind")? };
    Ok(fr_bytes(&oc.nullify(&kp)))
}

/// Freezer = Poseidon(commitment, owner.x). Computable by the auditor from the audit memo.
#[wasm_bindgen]
pub fn compute_freezer(asset: u64, amount_low: u64, amount_high: u64, owner_pk: &[u8], blind: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let oc = OpenCommitment { asset, amount: u128_of(amount_low, amount_high), owner: parse_pk(owner_pk)?, blind: parse_fr(blind, "blind")? };
    Ok(fr_bytes(&oc.freeze()))
}

/// Encrypt the owner memo (ECDH + AES-GCM, off-circuit) for a UTXO. Output: 104 bytes.
#[wasm_bindgen]
pub fn owner_memo_encrypt(asset: u64, amount_low: u64, amount_high: u64, owner_pk: &[u8], blind: &[u8], seed: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }
    let mut rng = ChaCha20Rng::from_seed(seed.try_into().unwrap());
    let oc = OpenCommitment { asset, amount: u128_of(amount_low, amount_high), owner: parse_pk(owner_pk)?, blind: parse_fr(blind, "blind")? };
    oc.memo_encrypt(&mut rng).map_err(js_err("memo_encrypt"))
}

/// Try to decrypt an owner memo with our secret. Returns
/// asset (8 LE) || amount (16 LE) || blind (32) on success, or an error if it is not ours.
#[wasm_bindgen]
pub fn owner_memo_decrypt(secret: &[u8], commitment: &[u8], memo: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let kp = Keypair::from_secret_bytes(secret).map_err(js_err("secret"))?;
    let comm = parse_fr(commitment, "commitment")?;
    let oc = OpenCommitment::memo_decrypt(&kp, &comm, memo).map_err(js_err("not our memo"))?;
    let mut out = Vec::with_capacity(56);
    out.extend(oc.asset.to_le_bytes());
    out.extend(oc.amount.to_le_bytes());
    out.extend(fr_bytes(&oc.blind));
    Ok(out)
}

/// Encrypt the audit memo (Poseidon stream cipher, proven in-circuit).
/// Output: memo (160) || share (32) — pass both to the prover.
#[wasm_bindgen]
pub fn audit_memo_encrypt(asset: u64, amount_low: u64, amount_high: u64, owner_pk: &[u8], blind: &[u8], auditor_pk: &[u8], seed: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }
    let mut rng = ChaCha20Rng::from_seed(seed.try_into().unwrap());
    let oc = OpenCommitment { asset, amount: u128_of(amount_low, amount_high), owner: parse_pk(owner_pk)?, blind: parse_fr(blind, "blind")? };
    let (memo, share) = oc.audit_encrypt(&mut rng, &parse_pk(auditor_pk)?).map_err(js_err("audit_encrypt"))?;
    let mut out = memo;
    out.extend(fr_bytes(&share));
    Ok(out)
}

/// Auditor-side decryption. Returns asset (8 LE) || amount (16 LE) || owner_x (32) || owner_y (32).
#[wasm_bindgen]
pub fn audit_memo_decrypt(auditor_secret: &[u8], memo: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let kp = Keypair::from_secret_bytes(auditor_secret).map_err(js_err("secret"))?;
    let oc = OpenCommitment::audit_decrypt(&kp, &Fr::from(0u64), memo).map_err(js_err("audit_decrypt"))?;
    let mut out = Vec::with_capacity(88);
    out.extend(oc.asset.to_le_bytes());
    out.extend(oc.amount.to_le_bytes());
    out.extend(fr_bytes(&oc.owner.x));
    out.extend(fr_bytes(&oc.owner.y));
    Ok(out)
}

// =============================================================================
// EVM encoding
// =============================================================================

/// Compressed arkworks proof -> 256-byte EVM proof (8 uint256 words).
#[wasm_bindgen]
pub fn proof_to_evm(proof_bytes: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let proof = transfer::Proof::deserialize_compressed(proof_bytes).map_err(js_err("proof"))?;
    Ok(evm::proof_to_evm(&proof))
}

/// arkworks LE field element -> EVM big-endian bytes32
#[wasm_bindgen]
pub fn fr_to_evm(le: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    Ok(evm::fr_to_bytes32(&parse_fr(le, "field element")?).to_vec())
}

/// EVM big-endian bytes32 -> arkworks LE field element
#[wasm_bindgen]
pub fn fr_from_evm(be: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    Ok(fr_bytes(&evm::fr_from_bytes32(be).map_err(js_err("bytes32"))?))
}

// =============================================================================
// Transfer proving (full)
// =============================================================================

/// Everything the browser needs to submit a transfer on-chain.
#[derive(Serialize)]
pub struct TransferResult {
    /// 8 uint256 words, hex
    pub proof: String,
    /// public inputs in circuit order, hex bytes32 each
    pub publics: Vec<String>,
    pub nullifiers: Vec<String>,
    pub freezers: Vec<String>,
    pub commitments: Vec<String>,
    pub merkle_root: String,
    /// owner memos for each output (hex), to be emitted on-chain for the receivers
    pub owner_memos: Vec<String>,
    /// audit memos for each output (hex), empty if audit is off
    pub audit_memos: Vec<String>,
}

/// Prove a UTXO transfer.
///
/// - `secret`: spender's 32-byte secret key
/// - `inputs`: concatenated records of asset (8 LE) || amount (16 LE) || blind (32) || merkle proof blob (MT_PROOF_LEN)
/// - `outputs`: concatenated records of asset (8 LE) || amount (16 LE) || owner_pk (64) || blind (32)
/// - `auditor_pk`: 64 bytes, or empty for no audit
/// - `audit_memos`: concatenated 192-byte results of `audit_memo_encrypt` (one per output), empty if no audit
/// - `seed`: 32 random bytes
#[wasm_bindgen]
pub fn transfer_prove(
    pk_bytes: &[u8],
    secret: &[u8],
    inputs: &[u8],
    outputs: &[u8],
    auditor_pk: &[u8],
    audit_memos: &[u8],
    seed: &[u8],
) -> std::result::Result<JsValue, JsValue> {
    if seed.len() != 32 {
        return Err(JsValue::from_str("Random seed must be 32 bytes"));
    }
    let mut rng = ChaCha20Rng::from_seed(seed.try_into().unwrap());
    let keypair = Keypair::from_secret_bytes(secret).map_err(js_err("secret"))?;
    let pk = transfer::ProvingKey::deserialize_compressed(pk_bytes).map_err(js_err("proving key"))?;

    const IN_LEN: usize = 8 + 16 + 32 + MT_PROOF_LEN;
    const OUT_LEN: usize = 8 + 16 + 64 + 32;
    if inputs.is_empty() || inputs.len() % IN_LEN != 0 {
        return Err(JsValue::from_str(&format!("inputs must be n × {IN_LEN} bytes")));
    }
    if outputs.is_empty() || outputs.len() % OUT_LEN != 0 {
        return Err(JsValue::from_str(&format!("outputs must be n × {OUT_LEN} bytes")));
    }

    let mut utxo_inputs = vec![];
    for rec in inputs.chunks(IN_LEN) {
        let asset = u64::from_le_bytes(rec[..8].try_into().unwrap());
        let amount = u128::from_le_bytes(rec[8..24].try_into().unwrap());
        let blind = parse_fr(&rec[24..56], "input blind")?;
        let merkle_proof = parse_mt_proof(&rec[56..])?;
        utxo_inputs.push(transfer::UtxoInput {
            commitment: OpenCommitment { asset, amount, owner: keypair.public, blind },
            merkle_proof,
        });
    }

    let mut utxo_outputs = vec![];
    for rec in outputs.chunks(OUT_LEN) {
        let asset = u64::from_le_bytes(rec[..8].try_into().unwrap());
        let amount = u128::from_le_bytes(rec[8..24].try_into().unwrap());
        let owner = parse_pk(&rec[24..88])?;
        let blind = parse_fr(&rec[88..120], "output blind")?;
        utxo_outputs.push(transfer::UtxoOutput { commitment: OpenCommitment { asset, amount, owner, blind } });
    }

    let audit = if auditor_pk.is_empty() {
        None
    } else {
        if audit_memos.len() != utxo_outputs.len() * 192 {
            return Err(JsValue::from_str("audit_memos must be 192 bytes per output"));
        }
        let mut memos = vec![];
        let mut shares = vec![];
        for rec in audit_memos.chunks(192) {
            memos.push(rec[..160].to_vec());
            shares.push(parse_fr(&rec[160..], "audit share")?);
        }
        Some(transfer::AuditCircuit { auditor: parse_pk(auditor_pk)?, memos, shares })
    };

    let circuit = transfer::UtxoCircuit { keypair, inputs: utxo_inputs, outputs: utxo_outputs, audit };
    let utxo = circuit.utxo(&mut rng).map_err(js_err("utxo"))?;
    let proof = transfer::prove(&pk, circuit, &mut rng).map_err(js_err("prove"))?;

    let mut publics = utxo.nullifiers.clone();
    publics.extend(&utxo.freezers);
    publics.extend(&utxo.commitments);
    publics.push(utxo.merkle_root);
    let mut audit_memos_out = vec![];
    if let Some(a) = &utxo.audit {
        publics.push(a.auditor.x);
        publics.push(a.auditor.y);
        for memo in &a.memos {
            for bytes in memo[64..].chunks(32) {
                publics.push(Fr::deserialize_compressed(bytes).map_err(js_err("audit ct"))?);
            }
            audit_memos_out.push(hex(memo));
        }
    }
    let be = |f: &Fr| hex(&evm::fr_to_bytes32(f));
    let result = TransferResult {
        proof: hex(&evm::proof_to_evm(&proof)),
        publics: publics.iter().map(be).collect(),
        nullifiers: utxo.nullifiers.iter().map(be).collect(),
        freezers: utxo.freezers.iter().map(be).collect(),
        commitments: utxo.commitments.iter().map(be).collect(),
        merkle_root: be(&utxo.merkle_root),
        owner_memos: utxo.memos.iter().map(|m| hex(m)).collect(),
        audit_memos: audit_memos_out,
    };
    serde_wasm_bindgen::to_value(&result).map_err(js_err("serialize result"))
}

/// Verify an EVM-encoded proof against EVM-encoded public inputs (bytes32 each) with any vk.
/// Lets the browser self-check a proof before paying for a transaction.
#[wasm_bindgen]
pub fn groth16_verify_evm(vk_bytes: &[u8], proof_evm: &[u8], publics_evm: &[u8]) -> std::result::Result<bool, JsValue> {
    use ark_crypto_primitives::snark::SNARK;
    let vk = transfer::VerifyingKey::deserialize_compressed(vk_bytes).map_err(js_err("vk"))?;
    let proof = evm::proof_from_evm(proof_evm).map_err(js_err("proof"))?;
    if publics_evm.len() % 32 != 0 {
        return Err(JsValue::from_str("publics must be n × 32 bytes"));
    }
    let mut publics = Vec::with_capacity(publics_evm.len() / 32);
    for w in publics_evm.chunks(32) {
        publics.push(evm::fr_from_bytes32(w).map_err(js_err("public input"))?);
    }
    ark_groth16::Groth16::<ark_bn254::Bn254>::verify(&vk, &publics, &proof).map_err(js_err("verify"))
}

/// Freezer straight from a commitment and the owner's x coordinate: Poseidon(commitment, owner.x).
/// This is what the auditor computes after decrypting an audit memo (it never learns the blind).
#[wasm_bindgen]
pub fn freezer_of(commitment: &[u8], owner_x: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let c = parse_fr(commitment, "commitment")?;
    let x = parse_fr(owner_x, "owner_x")?;
    Ok(fr_bytes(&app_payment::poseidon::poseidon_hash(&[c, x])))
}

// =============================================================================
// Authentication with the payment key (Schnorr on BabyJubJub)
// =============================================================================

/// Sign `msg` with the payment secret. Returns 64 bytes: R (32) || s (32).
#[wasm_bindgen]
pub fn sign_message(secret: &[u8], msg: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let kp = Keypair::from_secret_bytes(secret).map_err(js_err("secret"))?;
    Ok(kp.sign(msg).to_vec())
}

/// Verify a signature made with `sign_message` by the holder of `pk` (64 bytes x || y).
#[wasm_bindgen]
pub fn verify_message(pk: &[u8], msg: &[u8], sig: &[u8]) -> std::result::Result<bool, JsValue> {
    let pk = parse_pk(pk)?;
    Ok(app_payment::verify_signature(&pk, msg, sig))
}

// =============================================================================
// Payment address: 32-byte compressed public key
// =============================================================================

/// 64-byte x || y public key -> 32-byte compressed point (the user-facing payment address).
#[wasm_bindgen]
pub fn compress_pk(pk: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let p = parse_pk(pk)?;
    let mut out = vec![];
    p.serialize_compressed(&mut out).map_err(js_err("compress"))?;
    Ok(out)
}

/// 32-byte compressed point -> 64-byte x || y public key. Fails on an invalid encoding.
#[wasm_bindgen]
pub fn decompress_pk(addr: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    if addr.len() != 32 {
        return Err(JsValue::from_str("payment address must be 32 bytes"));
    }
    let p = EdwardsAffine::deserialize_compressed(addr).map_err(js_err("not a valid payment address"))?;
    let mut out = vec![];
    p.x.serialize_compressed(&mut out).map_err(js_err("x"))?;
    p.y.serialize_compressed(&mut out).map_err(js_err("y"))?;
    Ok(out)
}
