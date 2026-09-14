// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {APP} from "../src/APP.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {Transfer2x3Verifier} from "../src/verifiers/Transfer2x3Verifier.sol";
import {Transfer1x3Verifier} from "../src/verifiers/Transfer1x3Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// Upgrades the APP proxy recorded in deployments/<chainid>.json to a freshly deployed
/// implementation and, with NEW_VERIFIERS=true, also deploys the verifiers in src/verifiers/ and
/// points the proxy at them. Must be run by the proxy owner.
///
///   forge script script/Upgrade.s.sol --rpc-url $RPC --private-key $OWNER_PK --broadcast
///   NEW_VERIFIERS=true forge script script/Upgrade.s.sol --rpc-url $RPC --private-key $OWNER_PK --broadcast
contract Upgrade is Script {
    function run() external {
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory json = vm.readFile(path);
        APP app = APP(vm.parseJsonAddress(json, ".app"));
        bool newVerifiers = vm.envOr("NEW_VERIFIERS", false);

        vm.startBroadcast();
        APP impl = new APP();
        app.upgradeToAndCall(address(impl), "");
        if (newVerifiers) {
            APP.Verifiers memory v = APP.Verifiers({
                deposit: address(new DepositVerifier()),
                transfer2x2: address(new TransferVerifier()),
                transfer1x2: address(new Transfer1Verifier()),
                transfer2x3: address(new Transfer2x3Verifier()),
                transfer1x3: address(new Transfer1x3Verifier()),
                withdraw: address(new WithdrawVerifier())
            });
            app.setVerifiers(v);
            vm.writeJson(vm.toString(v.deposit), path, ".depositVerifier");
            vm.writeJson(vm.toString(v.transfer2x2), path, ".transferVerifier");
            vm.writeJson(vm.toString(v.transfer1x2), path, ".transfer1Verifier");
            vm.writeJson(vm.toString(v.transfer2x3), path, ".transfer2x3Verifier");
            vm.writeJson(vm.toString(v.transfer1x3), path, ".transfer1x3Verifier");
            vm.writeJson(vm.toString(v.withdraw), path, ".withdrawVerifier");
        }
        vm.stopBroadcast();

        vm.writeJson(vm.toString(address(impl)), path, ".appImpl");
        console.log("APP proxy", address(app), "now runs", address(impl));
        console.log("version", app.VERSION());
    }
}
