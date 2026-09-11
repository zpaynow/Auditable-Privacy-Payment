// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {APP} from "../src/APP.sol";
import {TestToken} from "../src/TestToken.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// End-to-end flow with real proofs from `cargo run -p app-tools -- e2e`:
/// alice deposits 600 + 400 -> transfers 700 to bob + 300 change -> bob withdraws 700 (fee 5).
contract APPTest is Test {
    APP app;
    TestToken usd;
    string json;

    address alice = address(0xA11CE);
    address relayer = address(0x5E1A);
    address auditorAdmin = address(0xA0D1);
    address recipient = address(0x1234);
    uint64 constant ASSET = 1;

    function setUp() public {
        json = vm.readFile("test/fixtures/e2e.json");
        DepositVerifier dv = new DepositVerifier();
        TransferVerifier tv = new TransferVerifier();
        Transfer1Verifier tv1 = new Transfer1Verifier();
        WithdrawVerifier wv = new WithdrawVerifier();
        app = new APP(
            address(dv),
            address(tv),
            address(tv1),
            address(wv),
            vm.parseJsonUint(json, ".auditorX"),
            vm.parseJsonUint(json, ".auditorY"),
            auditorAdmin
        );
        usd = new TestToken("Test USD", "tUSD", 6);
        app.registerAsset(ASSET, address(usd));
        usd.mint(alice, 1_000);
        vm.prank(alice);
        usd.approve(address(app), type(uint256).max);
    }

    // ------------------------------------------------------------ helpers
    function _proof(string memory path) internal view returns (uint256[8] memory p) {
        uint256[] memory w = vm.parseJsonUintArray(json, string.concat(path, ".proof"));
        for (uint256 i = 0; i < 8; i++) p[i] = w[i];
    }

    function _deposit(uint256 i) internal {
        string memory p = string.concat(".deposits[", vm.toString(i), "]");
        vm.prank(alice);
        app.deposit(
            ASSET,
            uint128(vm.parseJsonUint(json, string.concat(p, ".amount"))),
            vm.parseJsonUint(json, string.concat(p, ".commitment")),
            vm.parseJsonBytes(json, string.concat(p, ".ownerMemo")),
            vm.parseJsonBytes(json, string.concat(p, ".auditMemo")),
            _proof(p)
        );
    }

    struct T {
        uint256[2] nullifiers;
        uint256[2] freezers;
        uint256[2] commitments;
        uint256 root;
        bytes[2] ownerMemos;
        bytes[2] auditMemos;
        uint256[8] proof;
    }

    function _transferArgs() internal view returns (T memory t) {
        uint256[] memory n = vm.parseJsonUintArray(json, ".transfer.nullifiers");
        uint256[] memory f = vm.parseJsonUintArray(json, ".transfer.freezers");
        uint256[] memory c = vm.parseJsonUintArray(json, ".transfer.commitments");
        for (uint256 i = 0; i < 2; i++) {
            t.nullifiers[i] = n[i];
            t.freezers[i] = f[i];
            t.commitments[i] = c[i];
            t.ownerMemos[i] = vm.parseJsonBytes(json, string.concat(".transfer.ownerMemos[", vm.toString(i), "]"));
            t.auditMemos[i] = vm.parseJsonBytes(json, string.concat(".transfer.auditMemos[", vm.toString(i), "]"));
        }
        t.root = vm.parseJsonUint(json, ".transfer.root");
        t.proof = _proof(".transfer");
    }

    function _transfer(T memory t) internal {
        app.transfer(t.nullifiers, t.freezers, t.commitments, t.root, t.ownerMemos, t.auditMemos, t.proof);
    }

    function _withdraw(address to, uint128 fee) internal {
        vm.prank(relayer);
        app.withdraw(
            ASSET,
            700,
            vm.parseJsonUint(json, ".withdraw.nullifier"),
            vm.parseJsonUint(json, ".withdraw.freezer"),
            vm.parseJsonUint(json, ".withdraw.root"),
            to,
            fee,
            _proof(".withdraw")
        );
    }

    // -------------------------------------------------------------- tests
    function test_full_flow() public {
        _deposit(0);
        _deposit(1);
        assertEq(usd.balanceOf(address(app)), 1_000);
        assertEq(usd.balanceOf(alice), 0);
        assertEq(app.nextLeafIndex(), 2);
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".root1"), "root after deposits");

        T memory t = _transferArgs();
        uint256 g = gasleft();
        _transfer(t);
        emit log_named_uint("transfer gas", g - gasleft());
        assertEq(app.nextLeafIndex(), 4);
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".root2"), "root after transfer");
        assertTrue(app.nullifiers(t.nullifiers[0]));
        assertTrue(app.nullifiers(t.nullifiers[1]));

        g = gasleft();
        _withdraw(recipient, 5);
        emit log_named_uint("withdraw gas", g - gasleft());
        assertEq(usd.balanceOf(recipient), 695);
        assertEq(usd.balanceOf(relayer), 5);
        assertEq(usd.balanceOf(address(app)), 300);
    }

    function test_deposit_gas() public {
        uint256 g = gasleft();
        _deposit(0);
        emit log_named_uint("deposit gas", g - gasleft());
    }

    function test_double_spend_rejected() public {
        _deposit(0);
        _deposit(1);
        T memory t = _transferArgs();
        _transfer(t);
        vm.expectRevert(APP.NullifierUsed.selector);
        _transfer(t);
    }

    function test_transfer_with_unknown_root_rejected() public {
        // deposits not made: root1 is not in the history
        T memory t = _transferArgs();
        vm.expectRevert(APP.UnknownRoot.selector);
        _transfer(t);
    }

    function test_frozen_utxo_cannot_be_spent() public {
        _deposit(0);
        _deposit(1);
        T memory t = _transferArgs();
        _transfer(t);

        // auditor freezes bob's output before he withdraws
        uint256 freezer = vm.parseJsonUint(json, ".withdraw.freezer");
        vm.prank(auditorAdmin);
        app.setFrozen(freezer, true);
        vm.expectRevert(APP.Frozen.selector);
        _withdraw(recipient, 5);

        vm.prank(auditorAdmin);
        app.setFrozen(freezer, false);
        _withdraw(recipient, 5);
        assertEq(usd.balanceOf(recipient), 695);
    }

    function test_only_auditor_can_freeze() public {
        vm.expectRevert(APP.NotAuditor.selector);
        app.setFrozen(1, true);
    }

    function test_withdraw_front_run_rejected() public {
        _deposit(0);
        _deposit(1);
        _transfer(_transferArgs());
        // attacker swaps the recipient: proof no longer verifies
        vm.expectRevert(APP.InvalidProof.selector);
        _withdraw(address(0xBAD), 5);
        // or the fee
        vm.expectRevert(APP.InvalidProof.selector);
        _withdraw(recipient, 6);
    }

    function test_tampered_transfer_rejected() public {
        _deposit(0);
        _deposit(1);
        T memory t = _transferArgs();
        t.commitments[0] ^= 1;
        vm.expectRevert(APP.InvalidProof.selector);
        _transfer(t);
    }

    function test_deposit_needs_registered_asset() public {
        string memory p = ".deposits[0]";
        vm.prank(alice);
        vm.expectRevert(APP.UnknownAsset.selector);
        app.deposit(
            2,
            600,
            vm.parseJsonUint(json, string.concat(p, ".commitment")),
            vm.parseJsonBytes(json, string.concat(p, ".ownerMemo")),
            vm.parseJsonBytes(json, string.concat(p, ".auditMemo")),
            _proof(p)
        );
    }
}
