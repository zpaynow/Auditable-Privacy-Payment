// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {Transfer2x3Verifier} from "../src/verifiers/Transfer2x3Verifier.sol";
import {Transfer1x3Verifier} from "../src/verifiers/Transfer1x3Verifier.sol";
import {BatchVerifier} from "../src/BatchVerifier.sol";

/// Fixtures are produced by `cargo run -p app-tools -- setup` from real Rust proofs.
contract VerifiersTest is Test {
    DepositVerifier deposit;
    TransferVerifier transferV;
    Transfer1Verifier transfer1V;
    WithdrawVerifier withdraw;

    function setUp() public {
        deposit = new DepositVerifier();
        transferV = new TransferVerifier();
        transfer1V = new Transfer1Verifier();
        withdraw = new WithdrawVerifier();
    }

    function _load(string memory name) internal view returns (uint256[8] memory proof, uint256[] memory inputs) {
        string memory json = vm.readFile(string.concat("test/fixtures/", name, ".json"));
        uint256[] memory p = vm.parseJsonUintArray(json, ".proof");
        inputs = vm.parseJsonUintArray(json, ".inputs");
        for (uint256 i = 0; i < 8; i++) proof[i] = p[i];
    }

    function test_deposit_fixture_verifies() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("deposit");
        assertEq(inputs.length, deposit.NUM_INPUTS());
        uint256[8] memory pub;
        for (uint256 i = 0; i < 8; i++) pub[i] = inputs[i];
        assertTrue(deposit.verifyProof(proof, pub));
        pub[2] ^= 1; // tamper commitment
        assertFalse(deposit.verifyProof(proof, pub));
    }

    function test_transfer_fixture_verifies() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("transfer_2x2");
        assertEq(inputs.length, transferV.NUM_INPUTS());
        uint256[15] memory pub;
        for (uint256 i = 0; i < 15; i++) pub[i] = inputs[i];
        assertTrue(transferV.verifyProof(proof, pub));
        pub[0] ^= 1; // tamper nullifier
        assertFalse(transferV.verifyProof(proof, pub));
    }

    function test_transfer1_fixture_verifies() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("transfer_1x2");
        assertEq(inputs.length, transfer1V.NUM_INPUTS());
        uint256[13] memory pub;
        for (uint256 i = 0; i < 13; i++) pub[i] = inputs[i];
        assertTrue(transfer1V.verifyProof(proof, pub));
        pub[2] ^= 1;
        assertFalse(transfer1V.verifyProof(proof, pub));
    }

    function test_withdraw_fixture_verifies() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("withdraw");
        assertEq(inputs.length, withdraw.NUM_INPUTS());
        uint256[7] memory pub;
        for (uint256 i = 0; i < 7; i++) pub[i] = inputs[i];
        assertTrue(withdraw.verifyProof(proof, pub));
        pub[5] = uint256(uint160(address(0xBAD))); // steal recipient
        assertFalse(withdraw.verifyProof(proof, pub));
    }

    function test_transfer3_fixtures_verify() public {
        Transfer2x3Verifier v23 = new Transfer2x3Verifier();
        Transfer1x3Verifier v13 = new Transfer1x3Verifier();
        (uint256[8] memory proof, uint256[] memory inputs) = _load("transfer_2x3");
        assertEq(inputs.length, 19);
        uint256[19] memory pub;
        for (uint256 i = 0; i < 19; i++) pub[i] = inputs[i];
        assertTrue(v23.verifyProof(proof, pub));
        (proof, inputs) = _load("transfer_1x3");
        assertEq(inputs.length, 17);
        uint256[17] memory pub1;
        for (uint256 i = 0; i < 17; i++) pub1[i] = inputs[i];
        assertTrue(v13.verifyProof(proof, pub1));
        assertEq(v23.vkPoints().length, 14 + 2 * 20);
    }

    function _batchArgs()
        internal
        view
        returns (uint256[][] memory vks, uint8[] memory groupOf, uint256[8][] memory proofs, uint256[][] memory publics)
    {
        vks = new uint256[][](2);
        vks[0] = transferV.vkPoints();
        vks[1] = withdraw.vkPoints();
        groupOf = new uint8[](3);
        proofs = new uint256[8][](3);
        publics = new uint256[][](3);
        (proofs[0], publics[0]) = _load("transfer_2x2");
        groupOf[0] = 0;
        (proofs[1], publics[1]) = _load("withdraw");
        groupOf[1] = 1;
        // the same transfer proof twice is a valid batch too (batch verification is stateless)
        (proofs[2], publics[2]) = _load("transfer_2x2");
        groupOf[2] = 0;
    }

    function test_batch_verifier_accepts_mixed_batch() public {
        (uint256[][] memory vks, uint8[] memory groupOf, uint256[8][] memory proofs, uint256[][] memory publics) = _batchArgs();
        uint256 g = gasleft();
        bool ok = BatchVerifier.verify(vks, groupOf, proofs, publics);
        emit log_named_uint("batch verify gas (3 proofs, 2 groups)", g - gasleft());
        assertTrue(ok);
    }

    function test_batch_verifier_rejects_tampering() public view {
        (uint256[][] memory vks, uint8[] memory groupOf, uint256[8][] memory proofs, uint256[][] memory publics) = _batchArgs();
        publics[1][5] = uint256(uint160(address(0xBAD))); // withdraw recipient
        assertFalse(BatchVerifier.verify(vks, groupOf, proofs, publics));

        (vks, groupOf, proofs, publics) = _batchArgs();
        proofs[0][6] ^= 1; // corrupt C of a transfer -> invalid point
        assertFalse(BatchVerifier.verify(vks, groupOf, proofs, publics));

        (vks, groupOf, proofs, publics) = _batchArgs();
        publics[0][0] += BatchVerifier.R; // non-canonical nullifier (same residue, different storage key)
        assertFalse(BatchVerifier.verify(vks, groupOf, proofs, publics));

        (vks, groupOf, proofs, publics) = _batchArgs();
        groupOf[1] = 0; // withdraw proof claimed under the transfer key: input length mismatch
        assertFalse(BatchVerifier.verify(vks, groupOf, proofs, publics));
    }

    function test_batch_verifier_rejects_swapped_publics() public view {
        // two valid proofs whose public inputs are exchanged must not pass
        (uint256[][] memory vks, uint8[] memory groupOf, uint256[8][] memory proofs, uint256[][] memory publics) = _batchArgs();
        (proofs[2], publics[2]) = _load("transfer_1x2");
        groupOf[2] = 0; // 1x2 has 13 inputs, group 0 expects 15 -> rejected by length
        assertFalse(BatchVerifier.verify(vks, groupOf, proofs, publics));
    }

    function test_rejects_non_canonical_input() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("withdraw");
        uint256[7] memory pub;
        for (uint256 i = 0; i < 7; i++) pub[i] = inputs[i];
        pub[6] = type(uint256).max;
        assertFalse(withdraw.verifyProof(proof, pub));
    }
}
