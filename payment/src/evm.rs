//! EVM encoding helpers.
//!
//! Field elements are encoded as 32-byte big-endian `uint256` (arkworks serializes
//! little-endian, so every value crossing the chain boundary passes through here).
//! Curve points follow the BN254 precompile layout: G1 = (x, y), G2 = (x.c1, x.c0, y.c1, y.c0).
//! A Groth16 proof is 8 words: A.x, A.y, B.x.c1, B.x.c0, B.y.c1, B.y.c0, C.x, C.y.

use crate::{AzError, Result, transfer::{Proof, VerifyingKey}};
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, Zero};

pub const PROOF_EVM_LEN: usize = 8 * 32;

/// Fr -> big-endian bytes32
pub fn fr_to_bytes32(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_be());
    out
}

/// big-endian bytes32 -> Fr (must be canonical, i.e. < modulus)
pub fn fr_from_bytes32(b: &[u8]) -> Result<Fr> {
    if b.len() != 32 {
        return Err(AzError::EvmEncoding);
    }
    let v = Fr::from_be_bytes_mod_order(b);
    // reject non-canonical values
    if fr_to_bytes32(&v)[..] != b[..] {
        return Err(AzError::EvmEncoding);
    }
    Ok(v)
}

fn fq_to_bytes32(f: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_be());
    out
}

fn fq_from_bytes32(b: &[u8]) -> Result<Fq> {
    if b.len() != 32 {
        return Err(AzError::EvmEncoding);
    }
    let v = Fq::from_be_bytes_mod_order(b);
    if fq_to_bytes32(&v)[..] != b[..] {
        return Err(AzError::EvmEncoding);
    }
    Ok(v)
}

/// G1 -> [x, y] (point at infinity encodes as [0, 0], as the precompile expects)
pub fn g1_to_evm(p: &G1Affine) -> [[u8; 32]; 2] {
    match p.xy() {
        Some((x, y)) => [fq_to_bytes32(&x), fq_to_bytes32(&y)],
        None => [[0u8; 32], [0u8; 32]],
    }
}

pub fn g1_from_evm(words: &[[u8; 32]; 2]) -> Result<G1Affine> {
    let x = fq_from_bytes32(&words[0])?;
    let y = fq_from_bytes32(&words[1])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(AzError::EvmEncoding);
    }
    Ok(p)
}

/// G2 -> [x.c1, x.c0, y.c1, y.c0]
pub fn g2_to_evm(p: &G2Affine) -> [[u8; 32]; 4] {
    match p.xy() {
        Some((x, y)) => [
            fq_to_bytes32(&x.c1),
            fq_to_bytes32(&x.c0),
            fq_to_bytes32(&y.c1),
            fq_to_bytes32(&y.c0),
        ],
        None => [[0u8; 32]; 4],
    }
}

pub fn g2_from_evm(words: &[[u8; 32]; 4]) -> Result<G2Affine> {
    let x = Fq2::new(fq_from_bytes32(&words[1])?, fq_from_bytes32(&words[0])?);
    let y = Fq2::new(fq_from_bytes32(&words[3])?, fq_from_bytes32(&words[2])?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::identity());
    }
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(AzError::EvmEncoding);
    }
    Ok(p)
}

/// Groth16 proof -> 256 bytes of ABI words
pub fn proof_to_evm(proof: &Proof) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROOF_EVM_LEN);
    for w in g1_to_evm(&proof.a) {
        out.extend_from_slice(&w);
    }
    for w in g2_to_evm(&proof.b) {
        out.extend_from_slice(&w);
    }
    for w in g1_to_evm(&proof.c) {
        out.extend_from_slice(&w);
    }
    out
}

pub fn proof_from_evm(bytes: &[u8]) -> Result<Proof> {
    if bytes.len() != PROOF_EVM_LEN {
        return Err(AzError::EvmEncoding);
    }
    let w = |i: usize| -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        o
    };
    let a = g1_from_evm(&[w(0), w(1)])?;
    let b = g2_from_evm(&[w(2), w(3), w(4), w(5)])?;
    let c = g1_from_evm(&[w(6), w(7)])?;
    Ok(Proof { a, b, c })
}

fn hex32(w: &[u8; 32]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for b in w {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Render a self-contained Solidity Groth16 verifier for `vk`.
///
/// The generated contract exposes
/// `verifyProof(uint256[8] calldata proof, uint256[N] calldata input) external view returns (bool)`
/// and checks `e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1`
/// with the BN254 precompiles. `N` is the number of public inputs (excluding the leading 1).
pub fn vk_to_solidity(vk: &VerifyingKey, contract_name: &str) -> String {
    let n = vk.gamma_abc_g1.len() - 1;
    let alpha = g1_to_evm(&vk.alpha_g1);
    let beta = g2_to_evm(&vk.beta_g2);
    let gamma = g2_to_evm(&vk.gamma_g2);
    let delta = g2_to_evm(&vk.delta_g2);

    let mut ic = String::new();
    for (i, p) in vk.gamma_abc_g1.iter().enumerate() {
        let w = g1_to_evm(p);
        ic.push_str(&format!(
            "    uint256 constant IC{i}x = {};\n    uint256 constant IC{i}y = {};\n",
            hex32(&w[0]),
            hex32(&w[1])
        ));
    }

    let mut icpoints = String::new();
    for i in 0..=n {
        icpoints.push_str(&format!("        p[{}] = IC{i}x; p[{}] = IC{i}y;\n", 14 + 2 * i, 15 + 2 * i));
    }

    // vk_x = IC0 + sum(input[i-1] * ICi)
    let mut vkx = String::new();
    for i in 1..=n {
        vkx.push_str(&format!(
            "            g1_mulAccC(_pVk, IC{i}x, IC{i}y, calldataload(add(pSignals, {})))\n",
            (i - 1) * 32
        ));
    }

    format!(
        r#"// SPDX-License-Identifier: MIT
// Generated by app-payment `vk_to_solidity`. Do not edit by hand.
pragma solidity ^0.8.20;

/// @notice Groth16 verifier for a fixed circuit. {n} public inputs.
contract {contract_name} {{
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 constant alphax = {ax};
    uint256 constant alphay = {ay};
    uint256 constant betax1 = {bx1};
    uint256 constant betax2 = {bx2};
    uint256 constant betay1 = {by1};
    uint256 constant betay2 = {by2};
    uint256 constant gammax1 = {gx1};
    uint256 constant gammax2 = {gx2};
    uint256 constant gammay1 = {gy1};
    uint256 constant gammay2 = {gy2};
    uint256 constant deltax1 = {dx1};
    uint256 constant deltax2 = {dx2};
    uint256 constant deltay1 = {dy1};
    uint256 constant deltay2 = {dy2};

{ic}
    uint256 public constant NUM_INPUTS = {n};

    /// @notice Verifying key as flat words for batch verification:
    ///         [alpha.x, alpha.y, beta(4), gamma(4), delta(4), IC0.x, IC0.y, IC1.x, IC1.y, …]
    function vkPoints() external pure returns (uint256[] memory p) {{
        p = new uint256[](14 + 2 * (NUM_INPUTS + 1));
        p[0] = alphax; p[1] = alphay;
        p[2] = betax1; p[3] = betax2; p[4] = betay1; p[5] = betay2;
        p[6] = gammax1; p[7] = gammax2; p[8] = gammay1; p[9] = gammay2;
        p[10] = deltax1; p[11] = deltax2; p[12] = deltay1; p[13] = deltay2;
{icpoints}    }}

    /// @dev proof = [A.x, A.y, B.x1, B.x2, B.y1, B.y2, C.x, C.y]
    function verifyProof(uint256[8] calldata proof, uint256[{n}] calldata pubSignals) public view returns (bool) {{
        assembly {{
            function checkField(v) {{
                if iszero(lt(v, r)) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            // accumulate vk_x += scalar * (x, y)
            function g1_mulAccC(pR, x, y, s) {{
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)
                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)
                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))
                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)
                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            function checkPairing(pA, pB, pC, pSignals, pMem) -> isOk {{
                let _pPairing := add(pMem, 0)
                let _pVk := add(pMem, 768)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

{vkx}
                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))
                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))
                // alpha, beta
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)
                // vk_x, gamma
                mstore(add(_pPairing, 384), mload(_pVk))
                mstore(add(_pPairing, 416), mload(add(_pVk, 32)))
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)
                // C, delta
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)
                isOk := and(success, mload(_pPairing))
            }}

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, 832))

            // all public inputs must be canonical field elements
            {check_fields}
            let isValid := checkPairing(proof, add(proof, 64), add(proof, 192), pubSignals, pMem)
            mstore(0, isValid)
            return(0, 0x20)
        }}
    }}
}}
"#,
        ax = hex32(&alpha[0]),
        ay = hex32(&alpha[1]),
        bx1 = hex32(&beta[0]),
        bx2 = hex32(&beta[1]),
        by1 = hex32(&beta[2]),
        by2 = hex32(&beta[3]),
        gx1 = hex32(&gamma[0]),
        gx2 = hex32(&gamma[1]),
        gy1 = hex32(&gamma[2]),
        gy2 = hex32(&gamma[3]),
        dx1 = hex32(&delta[0]),
        dx2 = hex32(&delta[1]),
        dy1 = hex32(&delta[2]),
        dy2 = hex32(&delta[3]),
        icpoints = icpoints,
        check_fields = (0..n)
            .map(|i| format!("checkField(calldataload(add(pubSignals, {})))", i * 32))
            .collect::<Vec<_>>()
            .join("\n            "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, OpenCommitment, deposit};
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_fr_roundtrip() {
        let rng = &mut ChaCha20Rng::from_seed([1u8; 32]);
        use ark_std::UniformRand;
        for _ in 0..100 {
            let f = Fr::rand(rng);
            assert_eq!(fr_from_bytes32(&fr_to_bytes32(&f)).unwrap(), f);
        }
        // non-canonical (>= modulus) rejected
        let mut m = fr_to_bytes32(&(-Fr::from(1u64)));
        m[31] = m[31].wrapping_add(1); // = modulus
        assert!(fr_from_bytes32(&m).is_err());
    }

    #[test]
    fn test_proof_roundtrip_and_solidity_render() {
        let rng = &mut ChaCha20Rng::from_seed([5u8; 32]);
        let keypair = Keypair::generate(rng);
        let output = OpenCommitment::generate(rng, 1, 42, keypair.public);
        let (pk, vk) = deposit::setup(false, rng).unwrap();
        let memo = output.memo_encrypt(rng).unwrap();
        let circuit = deposit::DepositCircuit { asset: 1, amount: 42, output: output.clone(), memo: memo.clone(), audit: None };
        let proof = deposit::prove(&pk, circuit, rng).unwrap();

        let bytes = proof_to_evm(&proof);
        assert_eq!(bytes.len(), PROOF_EVM_LEN);
        let back = proof_from_evm(&bytes).unwrap();
        assert_eq!(back, proof);

        let d = deposit::Deposit { asset: 1, amount: 42, commitment: output.commit(), memo, audit: None };
        deposit::verify(&vk, &d, &back).unwrap();

        let sol = vk_to_solidity(&vk, "DepositVerifier");
        assert!(sol.contains("contract DepositVerifier"));
        assert!(sol.contains("uint256 public constant NUM_INPUTS = 4;"));
        assert!(sol.contains("IC3x"));
    }
}
