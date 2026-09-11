// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {APP} from "../src/APP.sol";
import {TestToken} from "../src/TestToken.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer1Verifier} from "../src/verifiers/Transfer1Verifier.sol";
import {Transfer2x3Verifier} from "../src/verifiers/Transfer2x3Verifier.sol";
import {Transfer1x3Verifier} from "../src/verifiers/Transfer1x3Verifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// Deploys verifiers, a faucet test token, and APP; registers the token as asset 1;
/// writes addresses to deployments/<chainid>.json for the web app.
///
/// Required env:
///   AUDITOR_X, AUDITOR_Y   auditor BabyJubJub public key (bytes32 hex, from `app-tools keygen`)
/// Optional env:
///   AUDITOR_ADMIN          address allowed to freeze (default: deployer)
///   OPERATOR               address allowed to submit batches (default: deployer)
///   TOKEN                  existing ERC20 to register as asset 1 (default: deploy TestToken)
///
///   forge script script/Deploy.s.sol --rpc-url $RPC --private-key $PK --broadcast
contract Deploy is Script {
    function run() external {
        uint256 auditorX = vm.envUint("AUDITOR_X");
        uint256 auditorY = vm.envUint("AUDITOR_Y");
        address deployer = msg.sender;
        address auditorAdmin = vm.envOr("AUDITOR_ADMIN", deployer);
        address operator = vm.envOr("OPERATOR", deployer);
        address token = vm.envOr("TOKEN", address(0));

        vm.startBroadcast();
        APP.Verifiers memory v = APP.Verifiers({
            deposit: address(new DepositVerifier()),
            transfer2x2: address(new TransferVerifier()),
            transfer1x2: address(new Transfer1Verifier()),
            transfer2x3: address(new Transfer2x3Verifier()),
            transfer1x3: address(new Transfer1x3Verifier()),
            withdraw: address(new WithdrawVerifier())
        });
        APP app = new APP(v, auditorX, auditorY, auditorAdmin);
        if (token == address(0)) {
            token = address(new TestToken("Test USD", "tUSD", 6));
        }
        app.registerAsset(1, token);
        app.setOperator(operator, true);
        vm.stopBroadcast();

        string memory out = "deployment";
        vm.serializeUint(out, "chainId", block.chainid);
        vm.serializeAddress(out, "app", address(app));
        vm.serializeAddress(out, "token", token);
        vm.serializeAddress(out, "depositVerifier", v.deposit);
        vm.serializeAddress(out, "transferVerifier", v.transfer2x2);
        vm.serializeAddress(out, "transfer1Verifier", v.transfer1x2);
        vm.serializeAddress(out, "transfer2x3Verifier", v.transfer2x3);
        vm.serializeAddress(out, "transfer1x3Verifier", v.transfer1x3);
        vm.serializeAddress(out, "withdrawVerifier", v.withdraw);
        vm.serializeUint(out, "auditorX", auditorX);
        vm.serializeUint(out, "auditorY", auditorY);
        vm.serializeAddress(out, "auditorAdmin", auditorAdmin);
        vm.serializeAddress(out, "operator", operator);
        string memory json = vm.serializeUint(out, "deployBlock", block.number);
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        vm.writeJson(json, path);
        console.log("APP deployed at", address(app));
        console.log("token", token);
        console.log("wrote", path);
    }
}
