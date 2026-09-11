// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BatchVerifier
/// @notice Verifies many Groth16 proofs (possibly for several verifying keys) with one pairing
///         call, using a random linear combination:
///
///   Π_i e(rᵢ·Aᵢ, Bᵢ) · Π_g [ e(−(Σ_{i∈g} rᵢ)·α_g, β_g) · e(−Σ_j c_gj·IC_gj, γ_g) · e(−Σ_{i∈g} rᵢ·Cᵢ, δ_g) ] = 1
///
///         with c_gj = Σ_{i∈g} rᵢ·a_ij (a_i0 = 1). Costs n + 3·groups pairings instead of 4n,
///         and one G1 multiplication per public-input slot per group instead of per proof.
///         rᵢ are derived from a keccak of every proof and public input in the batch.
library BatchVerifier {
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct Acc {
        uint256 seed;
        uint256[] sumR; // per group
        uint256[][] coeff; // per group, per IC slot
        uint256[2][] cAcc; // per group
        bool[] used;
        uint256[] pairing; // 6 words per pair
        uint256 pos;
    }

    /// @param vks     vkPoints() of each group: [α(2), β(4), γ(4), δ(4), IC0(2), IC1(2), …]
    /// @param groupOf group index of each proof
    /// @param proofs  [A.x, A.y, B.x1, B.x2, B.y1, B.y2, C.x, C.y] per proof
    /// @param publics public inputs per proof (without the leading 1); length must match the group's IC count − 1
    function verify(
        uint256[][] memory vks,
        uint8[] memory groupOf,
        uint256[8][] memory proofs,
        uint256[][] memory publics
    ) internal view returns (bool) {
        uint256 n = proofs.length;
        if (n == 0 || groupOf.length != n || publics.length != n) return false;

        Acc memory acc = _init(vks, n, uint256(keccak256(abi.encode(proofs, publics))));

        for (uint256 i = 0; i < n; i++) {
            if (groupOf[i] >= vks.length) return false;
            if (!_addProof(acc, groupOf[i], i, proofs[i], publics[i])) return false;
        }
        for (uint256 k = 0; k < vks.length; k++) {
            if (acc.used[k] && !_finishGroup(acc, k, vks[k])) return false;
        }
        return _pairing(acc.pairing, acc.pos);
    }

    function _init(uint256[][] memory vks, uint256 n, uint256 seed) private pure returns (Acc memory acc) {
        uint256 g = vks.length;
        acc.seed = seed;
        acc.sumR = new uint256[](g);
        acc.coeff = new uint256[][](g);
        acc.cAcc = new uint256[2][](g);
        acc.used = new bool[](g);
        for (uint256 k = 0; k < g; k++) {
            acc.coeff[k] = new uint256[]((vks[k].length - 14) / 2);
        }
        acc.pairing = new uint256[]((n + 3 * g) * 6);
    }

    function _addProof(Acc memory acc, uint256 k, uint256 i, uint256[8] memory proof, uint256[] memory pub)
        private
        view
        returns (bool)
    {
        uint256[] memory coeff = acc.coeff[k];
        if (pub.length + 1 != coeff.length) return false;
        uint256 r = uint256(keccak256(abi.encode(acc.seed, i))) % R;
        if (r == 0) r = 1;
        acc.used[k] = true;

        acc.sumR[k] = addmod(acc.sumR[k], r, R);
        coeff[0] = addmod(coeff[0], r, R);
        for (uint256 j = 0; j < pub.length; j++) {
            if (pub[j] >= R) return false;
            coeff[j + 1] = addmod(coeff[j + 1], mulmod(r, pub[j], R), R);
        }

        // e(r·A, B)
        (bool ok, uint256 x, uint256 y) = _mul(proof[0], proof[1], r);
        if (!ok) return false;
        _push(acc, x, y, proof[2], proof[3], proof[4], proof[5]);

        // C_acc += r·C
        (ok, x, y) = _mul(proof[6], proof[7], r);
        if (!ok) return false;
        (ok, acc.cAcc[k][0], acc.cAcc[k][1]) = _add(acc.cAcc[k][0], acc.cAcc[k][1], x, y);
        return ok;
    }

    function _finishGroup(Acc memory acc, uint256 k, uint256[] memory vk) private view returns (bool) {
        // e(−sumR·α, β)
        (bool ok, uint256 x, uint256 y) = _mul(vk[0], vk[1], acc.sumR[k]);
        if (!ok) return false;
        _push(acc, x, _neg(y), vk[2], vk[3], vk[4], vk[5]);

        // e(−Σ c_j·IC_j, γ)
        uint256[] memory coeff = acc.coeff[k];
        uint256 xx = 0;
        uint256 xy = 0;
        for (uint256 j = 0; j < coeff.length; j++) {
            if (coeff[j] == 0) continue;
            (ok, x, y) = _mul(vk[14 + 2 * j], vk[15 + 2 * j], coeff[j]);
            if (!ok) return false;
            (ok, xx, xy) = _add(xx, xy, x, y);
            if (!ok) return false;
        }
        _push(acc, xx, _neg(xy), vk[6], vk[7], vk[8], vk[9]);

        // e(−C_acc, δ)
        _push(acc, acc.cAcc[k][0], _neg(acc.cAcc[k][1]), vk[10], vk[11], vk[12], vk[13]);
        return true;
    }

    function _push(Acc memory acc, uint256 ax, uint256 ay, uint256 b0, uint256 b1, uint256 b2, uint256 b3) private pure {
        uint256[] memory p = acc.pairing;
        uint256 pos = acc.pos;
        p[pos] = ax;
        p[pos + 1] = ay;
        p[pos + 2] = b0;
        p[pos + 3] = b1;
        p[pos + 4] = b2;
        p[pos + 5] = b3;
        acc.pos = pos + 6;
    }

    function _neg(uint256 y) private pure returns (uint256) {
        return y == 0 ? 0 : Q - y;
    }

    function _mul(uint256 x, uint256 y, uint256 s) private view returns (bool ok, uint256 rx, uint256 ry) {
        uint256[3] memory input = [x, y, s];
        uint256[2] memory out;
        assembly {
            ok := staticcall(10000, 7, input, 96, out, 64)
        }
        rx = out[0];
        ry = out[1];
    }

    function _add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) private view returns (bool ok, uint256 rx, uint256 ry) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory out;
        assembly {
            ok := staticcall(2000, 6, input, 128, out, 64)
        }
        rx = out[0];
        ry = out[1];
    }

    function _pairing(uint256[] memory data, uint256 words) private view returns (bool) {
        bool ok;
        uint256 result;
        // 34k per pair + 45k base (EIP-1108); a little headroom, never the whole gas budget
        uint256 gasLimit = 34000 * (words / 6) + 60000;
        assembly {
            ok := staticcall(gasLimit, 8, add(data, 32), mul(words, 32), 0, 32)
            result := mload(0)
        }
        return ok && result == 1;
    }
}
