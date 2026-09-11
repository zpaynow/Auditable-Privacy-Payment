// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PoseidonT3} from "../src/PoseidonT3.sol";
import {IncrementalMerkleTree} from "../src/IncrementalMerkleTree.sol";

contract TreeHarness is IncrementalMerkleTree {
    function insert(uint256 leaf) external returns (uint32) {
        return _insert(leaf);
    }

    function insertMany(uint256[] memory leaves) external returns (uint32) {
        return _insertMany(leaves);
    }
}

/// Vectors come from `cargo run -p app-tools -- poseidon-sol` (Rust `poseidon_merge_hash` / `MerkleTree`).
contract PoseidonTest is Test {
    string json;

    function setUp() public {
        json = vm.readFile("test/fixtures/poseidon.json");
    }

    function test_hash_matches_rust() public view {
        uint256[] memory ls = vm.parseJsonUintArray(json, ".hash_l");
        uint256[] memory rs = vm.parseJsonUintArray(json, ".hash_r");
        uint256[] memory hs = vm.parseJsonUintArray(json, ".hash_h");
        assertEq(ls.length, 8);
        for (uint256 i = 0; i < ls.length; i++) {
            assertEq(PoseidonT3.hash(ls[i], rs[i]), hs[i], "hash mismatch");
        }
    }

    function test_hash_gas() public {
        uint256 g = gasleft();
        PoseidonT3.hash(1, 2);
        uint256 used = g - gasleft();
        emit log_named_uint("PoseidonT3.hash gas", used);
        assertLt(used, 100_000);
    }

    function test_rejects_out_of_field() public {
        vm.expectRevert(bytes("PoseidonT3: input not in field"));
        this.hashExternal(PoseidonT3.Q, 1);
    }

    function hashExternal(uint256 l, uint256 r) external pure returns (uint256) {
        return PoseidonT3.hash(l, r);
    }

    function test_batch_insert_matches_rust() public {
        uint256[] memory sizes = vm.parseJsonUintArray(json, ".batch_sizes");
        uint256[] memory leaves = vm.parseJsonUintArray(json, ".batch_leaves");
        uint256[] memory roots = vm.parseJsonUintArray(json, ".batch_roots");

        TreeHarness t = new TreeHarness();
        uint256 off = 0;
        for (uint256 b = 0; b < sizes.length; b++) {
            uint256[] memory batch = new uint256[](sizes[b]);
            for (uint256 i = 0; i < sizes[b]; i++) batch[i] = leaves[off + i];
            uint256 g = gasleft();
            uint32 start = t.insertMany(batch);
            emit log_named_uint(string.concat("insertMany(", vm.toString(sizes[b]), ") gas"), g - gasleft());
            assertEq(start, uint32(off));
            off += sizes[b];
            assertEq(t.nextLeafIndex(), uint32(off));
            assertEq(t.getLastRoot(), roots[b], "batch root mismatch");
        }
        // single inserts after batches still agree with a fresh sequential tree
        TreeHarness seq = new TreeHarness();
        for (uint256 i = 0; i < leaves.length; i++) seq.insert(leaves[i]);
        assertEq(seq.getLastRoot(), t.getLastRoot(), "sequential vs batched root");
    }

    function test_tree_roots_match_rust() public {
        uint256[] memory leaves = vm.parseJsonUintArray(json, ".leaves");
        uint256[] memory roots = vm.parseJsonUintArray(json, ".roots");

        TreeHarness t = new TreeHarness();
        // empty tree root is 0 (as in Rust) and is never a known root
        assertEq(t.getLastRoot(), 0, "empty root mismatch");
        assertFalse(t.isKnownRoot(0));

        for (uint256 i = 0; i < leaves.length; i++) {
            uint256 g = gasleft();
            uint32 idx = t.insert(leaves[i]);
            emit log_named_uint("insert gas", g - gasleft());
            assertEq(idx, uint32(i));
            assertEq(t.getLastRoot(), roots[i], "root mismatch after insert");
            assertTrue(t.isKnownRoot(roots[i]));
        }
        // older roots are still known, unknown root rejected
        assertTrue(t.isKnownRoot(roots[0]));
        assertFalse(t.isKnownRoot(0));
        assertFalse(t.isKnownRoot(12345));
    }
}
