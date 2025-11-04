// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Apa {
    uint256 nextCommitmentIndex = 0;

    mapping(bytes32 => bool) public nullifiers;
    mapping(uint256 => bytes32) public commitments;

    event NewBlock(
        bytes32[] nullifiers,
        bytes32[] commitments,
        bytes32[2][] ownerMemos,
        bytes32[2][] auditMemos
    );

    function submit(
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments,
        bytes32[2][] calldata _ownerMemo,
        bytes32[2][] calldata _auditMemo,
        bytes calldata proof
    ) public {
        // verify groth16 snarkproof

        for(uint i = 0; i < _nullifiers.length; i++) {
            nullifiers[_nullifiers[i]] = true;
        }

        for (uint i = 0; i < _commitments.length; i++) {
            commitments[nextCommitmentIndex] = _commitments[i];
            nextCommitmentIndex += 1;
        }

        emit NewBlock(_nullifiers, _commitments, _ownerMemo, _auditMemo);
    }

    function submitBlock(
        bytes32[] calldata _nullifiers,
        bytes32[] calldata _commitments,
        bytes32[2][] calldata _ownerMemos,
        bytes32[2][] calldata _auditMemos,
        bytes calldata snarkproof
    ) public {
        // verify groth16 snarkproof

        for(uint i = 0; i < _nullifiers.length; i++) {
            nullifiers[_nullifiers[i]] = true;
        }

        for (uint i = 0; i < _commitments.length; i++) {
            commitments[nextCommitmentIndex] = _commitments[i];
            nextCommitmentIndex += 1;
        }

        emit NewBlock(_nullifiers, _commitments, _ownerMemos, _auditMemos);
    }
}
