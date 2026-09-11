// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";

/// @title IncrementalMerkleTree
/// @notice Append-only binary Poseidon Merkle tree, bit-exact with the Rust `MerkleTree`
///         in app-payment: depth 20, parent = PoseidonT3(left, right), and every missing
///         node (leaf or branch) is the literal value 0, not a hash of zeros. The empty
///         tree therefore has root 0, which is never accepted as a known root.
///         Keeps a ring buffer of recent roots so proofs built against a slightly stale
///         root remain acceptable.
abstract contract IncrementalMerkleTree {
    uint32 public constant TREE_DEPTH = 20;
    uint32 public constant ROOT_HISTORY_SIZE = 128;
    uint32 public constant MAX_LEAVES = uint32(1) << TREE_DEPTH;

    /// @dev filledSubtrees[i] is the latest left sibling at level i
    uint256[TREE_DEPTH] internal filledSubtrees;

    mapping(uint256 => uint256) public roots;
    uint32 public currentRootIndex;
    uint32 public nextLeafIndex;

    error TreeFull();

    /// @dev Insert one leaf; returns its index. ~20 hashes.
    function _insert(uint256 leaf) internal returns (uint32 index) {
        index = nextLeafIndex;
        if (index >= MAX_LEAVES) revert TreeFull();

        uint256 current = leaf;
        uint32 idx = index;
        for (uint32 i = 0; i < TREE_DEPTH; i++) {
            uint256 left;
            uint256 right;
            if (idx & 1 == 0) {
                left = current;
                right = 0; // empty sibling
                filledSubtrees[i] = current;
            } else {
                left = filledSubtrees[i];
                right = current;
            }
            current = PoseidonT3.hash(left, right);
            idx >>= 1;
        }
        _pushRoot(current);
        nextLeafIndex = index + 1;
    }

    /// @dev Insert `leaves` consecutively; returns the index of the first one.
    ///      Hashes level by level so siblings inside the batch are combined once:
    ///      about n + TREE_DEPTH hashes instead of n * TREE_DEPTH.
    function _insertMany(uint256[] memory leaves) internal returns (uint32 startIndex) {
        uint256 n = leaves.length;
        startIndex = nextLeafIndex;
        if (n == 0) return startIndex;
        if (uint256(startIndex) + n > MAX_LEAVES) revert TreeFull();

        uint256[] memory layer = leaves;
        uint32 idx = startIndex; // tree index of layer[0] at the current level
        for (uint32 level = 0; level < TREE_DEPTH; level++) {
            uint32 lastIdx = idx + uint32(layer.length) - 1;
            uint256 leftSibling = filledSubtrees[level]; // read before overwriting
            // remember the newest even-index node at this level: it is the left sibling of the
            // next node inserted here (its right partner may still be missing or partial)
            uint32 lastEven = lastIdx & 1 == 0 ? lastIdx : lastIdx - 1;
            if (lastEven >= idx) filledSubtrees[level] = layer[lastEven - idx];

            uint32 parentStart = idx >> 1;
            uint32 parentEnd = lastIdx >> 1;
            uint256[] memory next = new uint256[](parentEnd - parentStart + 1);
            for (uint32 p = parentStart; p <= parentEnd; p++) {
                uint32 li = p << 1;
                uint32 ri = li + 1;
                uint256 left = li < idx ? leftSibling : layer[li - idx];
                uint256 right = ri > lastIdx ? 0 : layer[ri - idx];
                next[p - parentStart] = PoseidonT3.hash(left, right);
            }
            layer = next;
            idx = parentStart;
        }
        _pushRoot(layer[0]);
        nextLeafIndex = startIndex + uint32(n);
    }

    function _pushRoot(uint256 root) private {
        uint32 newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        currentRootIndex = newRootIndex;
        roots[newRootIndex] = root;
    }

    /// @notice Latest root.
    function getLastRoot() public view returns (uint256) {
        return roots[currentRootIndex];
    }

    /// @notice True if `root` is one of the last ROOT_HISTORY_SIZE roots (0 is never known).
    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        uint32 i = currentRootIndex;
        do {
            if (roots[i] == root) return true;
            if (i == 0) i = ROOT_HISTORY_SIZE;
            i--;
        } while (i != currentRootIndex);
        return false;
    }
}
