// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IDepositVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[8] calldata input) external view returns (bool);
}

interface ITransferVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[15] calldata input) external view returns (bool);
}

interface ITransfer1Verifier {
    function verifyProof(uint256[8] calldata proof, uint256[13] calldata input) external view returns (bool);
}

interface IWithdrawVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[7] calldata input) external view returns (bool);
}

/// @title APP — Auditable Privacy Payment
/// @notice UTXO pool: commitments live in a Poseidon Merkle tree, spends publish nullifiers,
///         every output carries an owner memo (for the receiver) and an audit memo encrypted to
///         the registered auditor and proven correct in-circuit. The auditor can freeze a UTXO
///         by its freezer = Poseidon(commitment, owner.x), which it can derive from the audit memo.
///
/// Phase 1: users prove in the browser and call deposit / transfer / withdraw directly.
contract APP is IncrementalMerkleTree {
    // ---------------------------------------------------------------- config
    address public owner;
    /// @notice auditor BabyJubJub public key; every audit memo must be encrypted to it
    uint256 public auditorX;
    uint256 public auditorY;
    /// @notice address allowed to freeze / unfreeze
    address public auditorAdmin;

    IDepositVerifier public immutable depositVerifier;
    ITransferVerifier public immutable transferVerifier;
    ITransfer1Verifier public immutable transfer1Verifier;
    IWithdrawVerifier public immutable withdrawVerifier;

    /// @notice asset id (as used inside the circuits) -> ERC20 token
    mapping(uint64 => address) public assetToken;
    mapping(address => uint64) public tokenAsset;

    // ----------------------------------------------------------------- state
    mapping(uint256 => bool) public nullifiers;
    mapping(uint256 => bool) public frozen;

    uint256 internal constant OWNER_MEMO_LEN = 104; // 32 epk || 56 ptext || 16 tag
    uint256 internal constant AUDIT_MEMO_LEN = 160; // 64 epk || 3 x 32 ciphertexts

    // ---------------------------------------------------------------- events
    /// @dev one per new output; wallets scan these to find their UTXOs
    event NewCommitment(uint32 indexed index, uint256 commitment, bytes ownerMemo, bytes auditMemo);
    event NewNullifier(uint256 nullifier);
    event Deposit(uint64 indexed asset, uint128 amount, uint256 commitment);
    event Withdraw(uint64 indexed asset, uint128 amount, address indexed recipient, uint128 fee, address relayer);
    event FrozenSet(uint256 indexed freezer, bool isFrozen);
    event AssetRegistered(uint64 indexed asset, address token);
    event AuditorSet(uint256 x, uint256 y, address admin);

    // ---------------------------------------------------------------- errors
    error NotOwner();
    error NotAuditor();
    error UnknownAsset();
    error UnknownRoot();
    error NullifierUsed();
    error Frozen();
    error InvalidProof();
    error BadMemoLength();
    error FeeExceedsAmount();
    error AssetAlreadyRegistered();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(
        address _depositVerifier,
        address _transferVerifier,
        address _transfer1Verifier,
        address _withdrawVerifier,
        uint256 _auditorX,
        uint256 _auditorY,
        address _auditorAdmin
    ) {
        owner = msg.sender;
        depositVerifier = IDepositVerifier(_depositVerifier);
        transferVerifier = ITransferVerifier(_transferVerifier);
        transfer1Verifier = ITransfer1Verifier(_transfer1Verifier);
        withdrawVerifier = IWithdrawVerifier(_withdrawVerifier);
        auditorX = _auditorX;
        auditorY = _auditorY;
        auditorAdmin = _auditorAdmin;
        emit AuditorSet(_auditorX, _auditorY, _auditorAdmin);
    }

    // ----------------------------------------------------------------- admin
    function registerAsset(uint64 asset, address token) external onlyOwner {
        if (asset == 0 || token == address(0)) revert UnknownAsset();
        if (assetToken[asset] != address(0) || tokenAsset[token] != 0) revert AssetAlreadyRegistered();
        assetToken[asset] = token;
        tokenAsset[token] = asset;
        emit AssetRegistered(asset, token);
    }

    function setAuditor(uint256 x, uint256 y, address admin) external onlyOwner {
        auditorX = x;
        auditorY = y;
        auditorAdmin = admin;
        emit AuditorSet(x, y, admin);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    /// @notice Freeze or unfreeze a UTXO by its freezer. Spending a frozen UTXO reverts.
    function setFrozen(uint256 freezer, bool isFrozen) external {
        if (msg.sender != auditorAdmin) revert NotAuditor();
        frozen[freezer] = isFrozen;
        emit FrozenSet(freezer, isFrozen);
    }

    // --------------------------------------------------------------- deposit
    /// @notice Lock `amount` of `asset` and create one shielded output.
    /// @dev public inputs: [asset, amount, commitment, auditorX, auditorY, ct0, ct1, ct2]
    function deposit(
        uint64 asset,
        uint128 amount,
        uint256 commitment,
        bytes calldata ownerMemo,
        bytes calldata auditMemo,
        uint256[8] calldata proof
    ) external {
        address token = assetToken[asset];
        if (token == address(0)) revert UnknownAsset();
        _checkMemos(ownerMemo, auditMemo);

        uint256[8] memory input;
        input[0] = asset;
        input[1] = amount;
        input[2] = commitment;
        input[3] = auditorX;
        input[4] = auditorY;
        (input[5], input[6], input[7]) = _auditCiphertexts(auditMemo);
        if (!depositVerifier.verifyProof(proof, input)) revert InvalidProof();

        require(IERC20Minimal(token).transferFrom(msg.sender, address(this), amount), "transferFrom");

        uint32 index = _insert(commitment);
        emit NewCommitment(index, commitment, ownerMemo, auditMemo);
        emit Deposit(asset, amount, commitment);
    }

    // -------------------------------------------------------------- transfer
    /// @notice Spend two UTXOs and create two new ones (2-in / 2-out shape).
    /// @dev public inputs: [n0, n1, f0, f1, c0, c1, root, auditorX, auditorY, ct(memo0) x3, ct(memo1) x3]
    function transfer(
        uint256[2] calldata nullifiers_,
        uint256[2] calldata freezers,
        uint256[2] calldata commitments,
        uint256 root,
        bytes[2] calldata ownerMemos,
        bytes[2] calldata auditMemos,
        uint256[8] calldata proof
    ) external {
        if (!isKnownRoot(root)) revert UnknownRoot();
        _checkMemos(ownerMemos[0], auditMemos[0]);
        _checkMemos(ownerMemos[1], auditMemos[1]);

        uint256[15] memory input;
        for (uint256 i = 0; i < 2; i++) {
            if (nullifiers[nullifiers_[i]]) revert NullifierUsed();
            if (frozen[freezers[i]]) revert Frozen();
            input[i] = nullifiers_[i];
            input[2 + i] = freezers[i];
            input[4 + i] = commitments[i];
        }
        if (nullifiers_[0] == nullifiers_[1]) revert NullifierUsed();
        input[6] = root;
        input[7] = auditorX;
        input[8] = auditorY;
        (input[9], input[10], input[11]) = _auditCiphertexts(auditMemos[0]);
        (input[12], input[13], input[14]) = _auditCiphertexts(auditMemos[1]);
        if (!transferVerifier.verifyProof(proof, input)) revert InvalidProof();

        for (uint256 i = 0; i < 2; i++) {
            nullifiers[nullifiers_[i]] = true;
            emit NewNullifier(nullifiers_[i]);
        }
        for (uint256 i = 0; i < 2; i++) {
            uint32 index = _insert(commitments[i]);
            emit NewCommitment(index, commitments[i], ownerMemos[i], auditMemos[i]);
        }
    }

    /// @notice Spend one UTXO and create two new ones (1-in / 2-out shape).
    /// @dev public inputs: [n0, f0, c0, c1, root, auditorX, auditorY, ct(memo0) x3, ct(memo1) x3]
    function transfer1(
        uint256 nullifier,
        uint256 freezer,
        uint256[2] calldata commitments,
        uint256 root,
        bytes[2] calldata ownerMemos,
        bytes[2] calldata auditMemos,
        uint256[8] calldata proof
    ) external {
        if (!isKnownRoot(root)) revert UnknownRoot();
        if (nullifiers[nullifier]) revert NullifierUsed();
        if (frozen[freezer]) revert Frozen();
        _checkMemos(ownerMemos[0], auditMemos[0]);
        _checkMemos(ownerMemos[1], auditMemos[1]);

        uint256[13] memory input;
        input[0] = nullifier;
        input[1] = freezer;
        input[2] = commitments[0];
        input[3] = commitments[1];
        input[4] = root;
        input[5] = auditorX;
        input[6] = auditorY;
        (input[7], input[8], input[9]) = _auditCiphertexts(auditMemos[0]);
        (input[10], input[11], input[12]) = _auditCiphertexts(auditMemos[1]);
        if (!transfer1Verifier.verifyProof(proof, input)) revert InvalidProof();

        nullifiers[nullifier] = true;
        emit NewNullifier(nullifier);
        for (uint256 i = 0; i < 2; i++) {
            uint32 index = _insert(commitments[i]);
            emit NewCommitment(index, commitments[i], ownerMemos[i], auditMemos[i]);
        }
    }

    // -------------------------------------------------------------- withdraw
    /// @notice Spend one UTXO and release `amount - fee` of `asset` to `recipient`; `fee` goes to msg.sender.
    /// @dev public inputs: [asset, amount, nullifier, freezer, root, recipient, fee]
    function withdraw(
        uint64 asset,
        uint128 amount,
        uint256 nullifier,
        uint256 freezer,
        uint256 root,
        address recipient,
        uint128 fee,
        uint256[8] calldata proof
    ) external {
        address token = assetToken[asset];
        if (token == address(0)) revert UnknownAsset();
        if (!isKnownRoot(root)) revert UnknownRoot();
        if (nullifiers[nullifier]) revert NullifierUsed();
        if (frozen[freezer]) revert Frozen();
        if (fee > amount) revert FeeExceedsAmount();

        uint256[7] memory input =
            [uint256(asset), uint256(amount), nullifier, freezer, root, uint256(uint160(recipient)), uint256(fee)];
        if (!withdrawVerifier.verifyProof(proof, input)) revert InvalidProof();

        nullifiers[nullifier] = true;
        emit NewNullifier(nullifier);

        require(IERC20Minimal(token).transfer(recipient, amount - fee), "transfer");
        if (fee > 0) require(IERC20Minimal(token).transfer(msg.sender, fee), "fee");
        emit Withdraw(asset, amount, recipient, fee, msg.sender);
    }

    // ------------------------------------------------------------- internals
    function _checkMemos(bytes calldata ownerMemo, bytes calldata auditMemo) internal pure {
        if (ownerMemo.length != OWNER_MEMO_LEN || auditMemo.length != AUDIT_MEMO_LEN) revert BadMemoLength();
    }

    /// @dev The audit memo is arkworks-serialized: 64 bytes ephemeral pk, then three 32-byte
    ///      little-endian field elements. The circuit's public inputs are those three values.
    function _auditCiphertexts(bytes calldata memo) internal pure returns (uint256 c0, uint256 c1, uint256 c2) {
        c0 = _le32(memo, 64);
        c1 = _le32(memo, 96);
        c2 = _le32(memo, 128);
    }

    /// @dev read 32 little-endian bytes at `offset` as a uint256
    function _le32(bytes calldata data, uint256 offset) internal pure returns (uint256 v) {
        bytes32 w;
        assembly {
            w := calldataload(add(data.offset, offset))
        }
        // reverse byte order
        v = uint256(w);
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        v = (v >> 128) | (v << 128);
    }
}
