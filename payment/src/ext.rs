//! Binding of transaction calldata that lives outside the circuit ("ext data").
//!
//! Groth16 only binds what is a public input. Owner memos (the receiver's encrypted
//! blind) and the relayer that collects a withdraw fee are plain calldata, so without
//! this binding a front-runner can copy a valid proof and swap them. Every circuit
//! therefore carries one extra public input:
//!
//! * deposit / transfer: `memos_hash` = keccak256(ownerMemo_0 || auditMemo_0 || ownerMemo_1 || …) mod r
//! * withdraw:           `relayer`    = the 20-byte EVM address that must be `msg.sender`
//!
//! The contract recomputes the value from calldata and passes it to the verifier, so the
//! proof is only valid for exactly the memos / relayer the prover committed to.
//! Byte layout matches Solidity `abi.encodePacked` of the fixed-length memo blobs.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};

/// Owner memo length in bytes: 32 ephemeral pk || 56 plaintext || 16 GCM tag.
pub const OWNER_MEMO_LEN: usize = 104;
/// Audit memo length in bytes: 64 ephemeral pk || 3 × 32 ciphertexts.
pub const AUDIT_MEMO_LEN: usize = 160;

/// keccak256 of the concatenation of `chunks`, reduced into the BN254 scalar field.
pub fn keccak_to_fr(chunks: &[&[u8]]) -> Fr {
    let mut h = Keccak256::new();
    for c in chunks {
        h.update(c);
    }
    Fr::from_be_bytes_mod_order(&h.finalize())
}

/// Hash binding every output's owner memo (and audit memo when auditing is on), in
/// output order: `ownerMemo_i || auditMemo_i` for each i.
pub fn memos_hash(owner_memos: &[Vec<u8>], audit_memos: Option<&[Vec<u8>]>) -> Fr {
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(owner_memos.len() * 2);
    for (i, m) in owner_memos.iter().enumerate() {
        chunks.push(m.as_slice());
        if let Some(a) = audit_memos {
            chunks.push(a[i].as_slice());
        }
    }
    keccak_to_fr(&chunks)
}

/// A 20-byte EVM address as a field element (big-endian, zero-extended), the same
/// encoding as `uint256(uint160(addr))` on-chain.
pub fn address_to_fr(addr: &[u8]) -> crate::Result<Fr> {
    if addr.len() != 20 {
        return Err(crate::AzError::EvmEncoding);
    }
    Ok(Fr::from_be_bytes_mod_order(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vector() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let f = keccak_to_fr(&[b""]);
        let expected = Fr::from_be_bytes_mod_order(
            &hex_literal("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        );
        assert_eq!(f, expected);
    }

    fn hex_literal(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
