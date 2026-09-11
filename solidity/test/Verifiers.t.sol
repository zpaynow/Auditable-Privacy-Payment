// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

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

    function test_rejects_non_canonical_input() public view {
        (uint256[8] memory proof, uint256[] memory inputs) = _load("withdraw");
        uint256[7] memory pub;
        for (uint256 i = 0; i < 7; i++) pub[i] = inputs[i];
        pub[6] = type(uint256).max;
        assertFalse(withdraw.verifyProof(proof, pub));
    }
}
