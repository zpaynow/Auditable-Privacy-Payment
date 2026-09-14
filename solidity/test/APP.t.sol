// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {APP} from "../src/APP.sol";
import {TestToken} from "../src/TestToken.sol";
import {FeeOnTransferToken} from "./FeeOnTransferToken.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {Transfer2x3Verifier} from "../src/verifiers/Transfer2x3Verifier.sol";
import {Transfer1x3Verifier} from "../src/verifiers/Transfer1x3Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @dev Test-only implementation used to prove a UUPS upgrade preserves APP storage.
contract APPV2 is APP {
    function version2() external pure returns (string memory) {
        return "2.0.1";
    }
}

/// End-to-end flow with real proofs from `cargo run -p app-tools -- e2e`:
///   alice deposits 600 + 400 -> transfers 700 to bob + 300 change -> bob withdraws 700 (fee 5)
///   then (batch) carol deposits 300 + 200, dave deposits 1000, operator submits
///   [carol 2x3: 300 to bob, 190 change, 10 fee] [dave 1x3: 400 to bob, 595 change, 5 fee]
///   [alice withdraws her 300 change to 0x1234, fee 7]
contract APPTest is Test {
    APP app;
    TestToken usd;
    APP.Verifiers v;
    string json;

    address alice = address(0xA11CE);
    address relayer = address(0x5E1A);
    address auditorAdmin = address(0xA0D1);
    address operator = address(0x0BE7);
    address recipient = address(0x1234);
    uint64 constant ASSET = 1;

    function setUp() public {
        json = vm.readFile("test/fixtures/e2e.json");
        v = APP.Verifiers({
            deposit: address(new DepositVerifier()),
            transfer2x2: address(new TransferVerifier()),
            transfer1x2: address(new Transfer1Verifier()),
            transfer2x3: address(new Transfer2x3Verifier()),
            transfer1x3: address(new Transfer1x3Verifier()),
            withdraw: address(new WithdrawVerifier())
        });
        APP impl = new APP();
        app = APP(address(new ERC1967Proxy(
            address(impl),
            abi.encodeCall(APP.initialize, (v, vm.parseJsonUint(json, ".auditorX"), vm.parseJsonUint(json, ".auditorY"), auditorAdmin, address(this)))
        )));
        app.setOperator(operator, true);
        usd = new TestToken("Test USD", "tUSD", 6);
        app.registerAsset(ASSET, address(usd));
        usd.mint(alice, 2_500);
        vm.prank(alice);
        usd.approve(address(app), type(uint256).max);
    }

    // ------------------------------------------------------------ helpers
    function _proof(string memory path) internal view returns (uint256[8] memory p) {
        uint256[] memory w = vm.parseJsonUintArray(json, string.concat(path, ".proof"));
        for (uint256 i = 0; i < 8; i++) p[i] = w[i];
    }

    function _deposit(string memory p) internal {
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
        _withdrawFrom(relayer, to, fee);
    }

    function _withdrawFrom(address caller, address to, uint128 fee) internal {
        vm.prank(caller);
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

    function _phase1() internal {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        _transfer(_transferArgs());
        _withdraw(recipient, 5);
    }

    function _batchTransfer(uint256 i) internal view returns (APP.BatchTransfer memory bt) {
        string memory p = string.concat(".batch.transfers[", vm.toString(i), "]");
        bt.shape = uint8(vm.parseJsonUint(json, string.concat(p, ".shape")));
        bt.nullifiers = vm.parseJsonUintArray(json, string.concat(p, ".nullifiers"));
        bt.freezers = vm.parseJsonUintArray(json, string.concat(p, ".freezers"));
        uint256[] memory c = vm.parseJsonUintArray(json, string.concat(p, ".commitments"));
        for (uint256 j = 0; j < 3; j++) {
            bt.commitments[j] = c[j];
            bt.ownerMemos[j] = vm.parseJsonBytes(json, string.concat(p, ".ownerMemos[", vm.toString(j), "]"));
            bt.auditMemos[j] = vm.parseJsonBytes(json, string.concat(p, ".auditMemos[", vm.toString(j), "]"));
        }
        bt.root = vm.parseJsonUint(json, string.concat(p, ".root"));
        bt.proof = _proof(p);
    }

    function _batchWithdraw() internal view returns (APP.BatchWithdraw memory bw) {
        string memory p = ".batch.withdraws[0]";
        bw.asset = ASSET;
        bw.amount = uint128(vm.parseJsonUint(json, string.concat(p, ".amount")));
        bw.nullifier = vm.parseJsonUint(json, string.concat(p, ".nullifier"));
        bw.freezer = vm.parseJsonUint(json, string.concat(p, ".freezer"));
        bw.root = vm.parseJsonUint(json, string.concat(p, ".root"));
        bw.recipient = vm.parseJsonAddress(json, string.concat(p, ".recipient"));
        bw.fee = uint128(vm.parseJsonUint(json, string.concat(p, ".fee")));
        bw.proof = _proof(p);
    }

    function _batchArgs() internal view returns (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) {
        ts = new APP.BatchTransfer[](2);
        ts[0] = _batchTransfer(0);
        ts[1] = _batchTransfer(1);
        ws = new APP.BatchWithdraw[](1);
        ws[0] = _batchWithdraw();
    }

    function _prepareBatchState() internal {
        _phase1();
        for (uint256 i = 0; i < 3; i++) _deposit(string.concat(".batch.deposits[", vm.toString(i), "]"));
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".batch.root4"), "root before batch");
    }

    // -------------------------------------------------------- phase 1 tests
    function test_full_flow() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        assertEq(usd.balanceOf(address(app)), 1_000);
        assertEq(app.nextLeafIndex(), 2);
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".root1"), "root after deposits");

        T memory t = _transferArgs();
        uint256 g = gasleft();
        _transfer(t);
        emit log_named_uint("transfer gas", g - gasleft());
        assertEq(app.nextLeafIndex(), 4);
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".root2"), "root after transfer");

        g = gasleft();
        _withdraw(recipient, 5);
        emit log_named_uint("withdraw gas", g - gasleft());
        assertEq(usd.balanceOf(recipient), 695);
        assertEq(usd.balanceOf(relayer), 5);
        assertEq(usd.balanceOf(address(app)), 300);
    }

    function test_deposit_gas() public {
        uint256 g = gasleft();
        _deposit(".deposits[0]");
        emit log_named_uint("deposit gas", g - gasleft());
    }

    function test_double_spend_rejected() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        T memory t = _transferArgs();
        _transfer(t);
        vm.expectRevert(APP.NullifierUsed.selector);
        _transfer(t);
    }

    function test_transfer_with_unknown_root_rejected() public {
        T memory t = _transferArgs();
        vm.expectRevert(APP.UnknownRoot.selector);
        _transfer(t);
    }

    function test_frozen_utxo_cannot_be_spent() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        _transfer(_transferArgs());
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
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        _transfer(_transferArgs());
        vm.expectRevert(APP.InvalidProof.selector);
        _withdraw(address(0xBAD), 5);
        vm.expectRevert(APP.InvalidProof.selector);
        _withdraw(recipient, 6);
    }

    function test_withdraw_relayer_is_proof_bound() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        _transfer(_transferArgs());

        vm.expectRevert(APP.InvalidProof.selector);
        _withdrawFrom(address(0xBEEF), recipient, 5);
    }

    function test_tampered_transfer_rejected() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        T memory t = _transferArgs();
        t.commitments[0] ^= 1;
        vm.expectRevert(APP.InvalidProof.selector);
        _transfer(t);
    }

    function test_tampered_owner_memo_rejected() public {
        _deposit(".deposits[0]");
        _deposit(".deposits[1]");
        T memory t = _transferArgs();
        bytes memory memo = t.ownerMemos[0];
        memo[0] = bytes1(uint8(memo[0]) ^ 1);
        t.ownerMemos[0] = memo;
        vm.expectRevert(APP.InvalidProof.selector);
        _transfer(t);
    }

    function test_fee_on_transfer_deposit_rejected() public {
        FeeOnTransferToken taxed = new FeeOnTransferToken();
        APP impl = new APP();
        APP taxedApp = APP(address(new ERC1967Proxy(
            address(impl),
            abi.encodeCall(APP.initialize, (v, vm.parseJsonUint(json, ".auditorX"), vm.parseJsonUint(json, ".auditorY"), auditorAdmin, address(this)))
        )));
        taxedApp.registerAsset(ASSET, address(taxed));
        taxed.mint(alice, 600);
        vm.startPrank(alice);
        taxed.approve(address(taxedApp), type(uint256).max);
        vm.expectRevert(APP.AmountMismatch.selector);
        taxedApp.deposit(
            ASSET,
            600,
            vm.parseJsonUint(json, ".deposits[0].commitment"),
            vm.parseJsonBytes(json, ".deposits[0].ownerMemo"),
            vm.parseJsonBytes(json, ".deposits[0].auditMemo"),
            _proof(".deposits[0]")
        );
        vm.stopPrank();
        assertEq(taxed.balanceOf(address(taxedApp)), 0);
    }

    function test_uups_upgrade_preserves_pool_state() public {
        _deposit(".deposits[0]");
        uint256 root = app.getLastRoot();
        uint32 leafIndex = app.nextLeafIndex();
        address token = app.assetToken(ASSET);

        app.upgradeToAndCall(address(new APPV2()), bytes(""));

        assertEq(APPV2(address(app)).version2(), "2.0.1");
        assertEq(app.getLastRoot(), root);
        assertEq(app.nextLeafIndex(), leafIndex);
        assertEq(app.assetToken(ASSET), token);
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

    // -------------------------------------------------------- phase 2 tests
    function test_batch_flow() public {
        _prepareBatchState();
        (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) = _batchArgs();
        uint256 poolBefore = usd.balanceOf(address(app));
        uint256 recipientBefore = usd.balanceOf(recipient);

        vm.prank(operator);
        uint256 g = gasleft();
        app.submitBatch(ts, ws);
        emit log_named_uint("submitBatch gas (2 transfers + 1 withdraw)", g - gasleft());

        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".batch.root5"), "root after batch");
        assertEq(app.nextLeafIndex(), 7 + 6);
        assertEq(app.batchCount(), 1);
        assertEq(usd.balanceOf(recipient), recipientBefore + 293, "alice recipient gets 300 - 7");
        assertEq(usd.balanceOf(operator), 7, "operator fee");
        assertEq(usd.balanceOf(address(app)), poolBefore - 300);
        for (uint256 i = 0; i < 2; i++) {
            for (uint256 j = 0; j < ts[i].nullifiers.length; j++) assertTrue(app.nullifiers(ts[i].nullifiers[j]));
        }
        assertTrue(app.nullifiers(ws[0].nullifier));
    }

    function test_batch_only_operator() public {
        _prepareBatchState();
        (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) = _batchArgs();
        vm.expectRevert(APP.NotOperator.selector);
        app.submitBatch(ts, ws);
    }

    function test_batch_rejects_replay_and_tampering() public {
        _prepareBatchState();
        (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) = _batchArgs();
        vm.prank(operator);
        app.submitBatch(ts, ws);

        // replay
        vm.prank(operator);
        vm.expectRevert(APP.NullifierUsed.selector);
        app.submitBatch(ts, ws);
    }

    function test_batch_one_bad_proof_fails_whole_batch() public {
        _prepareBatchState();
        (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) = _batchArgs();
        ws[0].recipient = address(0xBAD);
        vm.prank(operator);
        vm.expectRevert(APP.InvalidProof.selector);
        app.submitBatch(ts, ws);
        // nothing applied
        assertFalse(app.nullifiers(ts[0].nullifiers[0]));
        assertEq(app.batchCount(), 0);
    }

    function test_batch_transfers_only_and_withdraws_only() public {
        _prepareBatchState();
        (APP.BatchTransfer[] memory ts, APP.BatchWithdraw[] memory ws) = _batchArgs();
        APP.BatchWithdraw[] memory none;
        vm.prank(operator);
        app.submitBatch(ts, none);
        APP.BatchTransfer[] memory noT;
        vm.prank(operator);
        app.submitBatch(noT, ws);
        assertEq(app.batchCount(), 2);
        assertEq(usd.balanceOf(operator), 7);
    }

    function test_batch_empty_rejected() public {
        APP.BatchTransfer[] memory noT;
        APP.BatchWithdraw[] memory none;
        vm.prank(operator);
        vm.expectRevert(APP.EmptyBatch.selector);
        app.submitBatch(noT, none);
    }
}
