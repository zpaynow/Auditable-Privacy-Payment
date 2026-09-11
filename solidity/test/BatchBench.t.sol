// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {APP} from "../src/APP.sol";
import {TestToken} from "../src/TestToken.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {Transfer2x3Verifier} from "../src/verifiers/Transfer2x3Verifier.sol";
import {Transfer1x3Verifier} from "../src/verifiers/Transfer1x3Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// Gas of submitBatch as the batch grows. Fixture: `cargo run -p app-tools -- bench-batch --n 8`
/// (8 independent 1-in/3-out transfers and 2 withdraws, all against the same root).
contract BatchBenchTest is Test {
    APP app;
    TestToken usd;
    string json;
    address alice = address(0xA11CE);
    address operator = address(0x0BE7);

    function setUp() public {
        json = vm.readFile("test/fixtures/bench.json");
        APP.Verifiers memory v = APP.Verifiers({
            deposit: address(new DepositVerifier()),
            transfer2x2: address(new TransferVerifier()),
            transfer1x2: address(new Transfer1Verifier()),
            transfer2x3: address(new Transfer2x3Verifier()),
            transfer1x3: address(new Transfer1x3Verifier()),
            withdraw: address(new WithdrawVerifier())
        });
        app = new APP(v, vm.parseJsonUint(json, ".auditorX"), vm.parseJsonUint(json, ".auditorY"), address(0xA0D1));
        app.setOperator(operator, true);
        usd = new TestToken("Test USD", "tUSD", 6);
        app.registerAsset(1, address(usd));
        usd.mint(alice, 10_000);
        vm.prank(alice);
        usd.approve(address(app), type(uint256).max);
        uint256 n = 10; // bench-batch --n 8 -> 8 transfers + 2 withdraws funded by 10 deposits
        for (uint256 i = 0; i < n; i++) {
            string memory p = string.concat(".deposits[", vm.toString(i), "]");
            vm.prank(alice);
            app.deposit(
                1,
                100,
                vm.parseJsonUint(json, string.concat(p, ".commitment")),
                vm.parseJsonBytes(json, string.concat(p, ".ownerMemo")),
                vm.parseJsonBytes(json, string.concat(p, ".auditMemo")),
                _proof(p)
            );
        }
        assertEq(app.getLastRoot(), vm.parseJsonUint(json, ".root"));
    }

    function _proof(string memory path) internal view returns (uint256[8] memory p) {
        uint256[] memory w = vm.parseJsonUintArray(json, string.concat(path, ".proof"));
        for (uint256 i = 0; i < 8; i++) p[i] = w[i];
    }

    function _transfer(uint256 i) internal view returns (APP.BatchTransfer memory bt) {
        string memory p = string.concat(".transfers[", vm.toString(i), "]");
        bt.shape = 1;
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

    function _withdraw(uint256 i) internal view returns (APP.BatchWithdraw memory bw) {
        string memory p = string.concat(".withdraws[", vm.toString(i), "]");
        bw.asset = 1;
        bw.amount = 100;
        bw.nullifier = vm.parseJsonUint(json, string.concat(p, ".nullifier"));
        bw.freezer = vm.parseJsonUint(json, string.concat(p, ".freezer"));
        bw.root = vm.parseJsonUint(json, string.concat(p, ".root"));
        bw.recipient = vm.parseJsonAddress(json, string.concat(p, ".recipient"));
        bw.fee = 3;
        bw.proof = _proof(p);
    }

    function _bench(uint256 k, uint256 wd) internal {
        APP.BatchTransfer[] memory ts = new APP.BatchTransfer[](k);
        for (uint256 i = 0; i < k; i++) ts[i] = _transfer(i);
        APP.BatchWithdraw[] memory ws = new APP.BatchWithdraw[](wd);
        for (uint256 i = 0; i < wd; i++) ws[i] = _withdraw(i);
        vm.prank(operator);
        uint256 g = gasleft();
        app.submitBatch(ts, ws);
        uint256 used = g - gasleft();
        emit log_named_uint(string.concat("submitBatch ", vm.toString(k), " transfers + ", vm.toString(wd), " withdraws: gas"), used);
        emit log_named_uint("  per op", used / (k + wd));
    }

    function test_bench_1() public { _bench(1, 0); }
    function test_bench_2() public { _bench(2, 0); }
    function test_bench_4() public { _bench(4, 0); }
    function test_bench_8() public { _bench(8, 0); }
    function test_bench_8_plus_2_withdraws() public { _bench(8, 2); }
    function test_bench_withdraws_only() public { _bench(0, 2); }
}
