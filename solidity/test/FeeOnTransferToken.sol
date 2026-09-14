// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TestToken} from "../src/TestToken.sol";

/// ERC20 that burns 1% of every transfer (deflationary / transfer-tax token) — used to check
/// that the pool refuses to credit more than it actually received.
contract FeeOnTransferToken is TestToken {
    constructor() TestToken("Taxed", "TAX", 6) {}

    function _taxed(address from, address to, uint256 amount) internal {
        uint256 tax = amount / 100;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - tax;
        totalSupply -= tax;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        _taxed(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _taxed(from, to, amount);
        return true;
    }
}
