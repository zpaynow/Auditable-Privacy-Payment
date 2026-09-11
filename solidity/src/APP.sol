// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";
import {BatchVerifier} from "./BatchVerifier.sol";

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

interface IVerifierPoints {
    function vkPoints() external pure returns (uint256[] memory);
}

/// @title APP — Auditable Privacy Payment
/// @notice UTXO pool: commitments live in a Poseidon Merkle tree, spends publish nullifiers,
///         every output carries an owner memo (for the receiver) and an audit memo encrypted to
///         the registered auditor and proven correct in-circuit. The auditor can freeze a UTXO
///         by its freezer = Poseidon(commitment, owner.x), which it can derive from the audit memo.
///
/// Phase 1: users prove in the browser and call deposit / transfer / transfer1 / withdraw directly.
/// Phase 2: an operator collects proofs and calls submitBatch, which verifies all of them with one
///          pairing check and inserts all new commitments with one batched tree update. Transfers
///          in a batch use the 3-output shapes (third output = fee to the operator's payment key),
///          withdraws pay `fee` to the operator.
contract APP is IncrementalMerkleTree {
    // ---------------------------------------------------------------- config
    struct Verifiers {
        address deposit;
        address transfer2x2;
        address transfer1x2;
        address transfer2x3;
        address transfer1x3;
        address withdraw;
    }

    address public owner;
    /// @notice auditor BabyJubJub public key; every audit memo must be encrypted to it
    uint256 public auditorX;
    uint256 public auditorY;
    /// @notice address allowed to freeze / unfreeze
    address public auditorAdmin;
    /// @notice addresses allowed to call submitBatch
    mapping(address => bool) public operators;

    Verifiers public verifiers;

    /// @notice asset id (as used inside the circuits) -> ERC20 token
    mapping(uint64 => address) public assetToken;
    mapping(address => uint64) public tokenAsset;

    // ----------------------------------------------------------------- state
    mapping(uint256 => bool) public nullifiers;
    mapping(uint256 => bool) public frozen;
    uint256 public batchCount;

    uint256 internal constant OWNER_MEMO_LEN = 104; // 32 epk || 56 ptext || 16 tag
    uint256 internal constant AUDIT_MEMO_LEN = 160; // 64 epk || 3 x 32 ciphertexts

    // batch verifier group ids
    uint8 internal constant G_T2X3 = 0;
    uint8 internal constant G_T1X3 = 1;
    uint8 internal constant G_WITHDRAW = 2;

    // ---------------------------------------------------------------- events
    /// @dev one per new output; wallets scan these to find their UTXOs
    event NewCommitment(uint32 indexed index, uint256 commitment, bytes ownerMemo, bytes auditMemo);
    event NewNullifier(uint256 nullifier);
    event Deposit(uint64 indexed asset, uint128 amount, uint256 commitment);
    event Withdraw(uint64 indexed asset, uint128 amount, address indexed recipient, uint128 fee, address relayer);
    event BatchSubmitted(uint256 indexed batchId, address indexed operator, uint256 transfers, uint256 withdraws, uint256 newRoot);
    event FrozenSet(uint256 indexed freezer, bool isFrozen);
    event AssetRegistered(uint64 indexed asset, address token);
    event AuditorSet(uint256 x, uint256 y, address admin);
    event OperatorSet(address indexed operator, bool allowed);

    // ---------------------------------------------------------------- errors
    error NotOwner();
    error NotAuditor();
    error NotOperator();
    error UnknownAsset();
    error UnknownRoot();
    error NullifierUsed();
    error Frozen();
    error InvalidProof();
    error BadMemoLength();
    error FeeExceedsAmount();
    error AssetAlreadyRegistered();
    error EmptyBatch();
    error BadShape();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(Verifiers memory _verifiers, uint256 _auditorX, uint256 _auditorY, address _auditorAdmin) {
        owner = msg.sender;
        verifiers = _verifiers;
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

    function setOperator(address operator, bool allowed) external onlyOwner {
        operators[operator] = allowed;
        emit OperatorSet(operator, allowed);
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
        if (!IDepositVerifier(verifiers.deposit).verifyProof(proof, input)) revert InvalidProof();

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
        if (nullifiers_[0] == nullifiers_[1]) revert NullifierUsed();

        uint256[15] memory input;
        for (uint256 i = 0; i < 2; i++) {
            _spend(nullifiers_[i], freezers[i]);
            input[i] = nullifiers_[i];
            input[2 + i] = freezers[i];
            input[4 + i] = commitments[i];
        }
        input[6] = root;
        input[7] = auditorX;
        input[8] = auditorY;
        (input[9], input[10], input[11]) = _auditCiphertexts(auditMemos[0]);
        (input[12], input[13], input[14]) = _auditCiphertexts(auditMemos[1]);
        if (!ITransferVerifier(verifiers.transfer2x2).verifyProof(proof, input)) revert InvalidProof();

        _emitOutputs2(commitments, ownerMemos, auditMemos);
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
        _checkMemos(ownerMemos[0], auditMemos[0]);
        _checkMemos(ownerMemos[1], auditMemos[1]);
        _spend(nullifier, freezer);

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
        if (!ITransfer1Verifier(verifiers.transfer1x2).verifyProof(proof, input)) revert InvalidProof();

        _emitOutputs2(commitments, ownerMemos, auditMemos);
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
        if (fee > amount) revert FeeExceedsAmount();
        _spend(nullifier, freezer);

        uint256[7] memory input =
            [uint256(asset), uint256(amount), nullifier, freezer, root, uint256(uint160(recipient)), uint256(fee)];
        if (!IWithdrawVerifier(verifiers.withdraw).verifyProof(proof, input)) revert InvalidProof();

        _payout(token, asset, amount, recipient, fee);
    }

    // ----------------------------------------------------------------- batch
    struct BatchTransfer {
        /// 0 = 2-in / 3-out, 1 = 1-in / 3-out
        uint8 shape;
        /// nullifiers/freezers: 2 entries for shape 0, 1 entry for shape 1
        uint256[] nullifiers;
        uint256[] freezers;
        uint256[3] commitments;
        uint256 root;
        bytes[3] ownerMemos;
        bytes[3] auditMemos;
        uint256[8] proof;
    }

    struct BatchWithdraw {
        uint64 asset;
        uint128 amount;
        uint256 nullifier;
        uint256 freezer;
        uint256 root;
        address recipient;
        uint128 fee;
        uint256[8] proof;
    }

    /// @notice Operator entry point: apply many transfers and withdraws, verify every proof with a
    ///         single random-linear-combination pairing check, insert all outputs at once.
    ///         Every op must reference a root known *before* this batch.
    function submitBatch(BatchTransfer[] calldata transfers, BatchWithdraw[] calldata withdraws) external {
        if (!operators[msg.sender]) revert NotOperator();
        uint256 n = transfers.length + withdraws.length;
        if (n == 0) revert EmptyBatch();

        uint8[] memory groupOf = new uint8[](n);
        uint256[8][] memory proofs = new uint256[8][](n);
        uint256[][] memory publics = new uint256[][](n);
        uint256[] memory leaves = new uint256[](transfers.length * 3);

        for (uint256 i = 0; i < transfers.length; i++) {
            BatchTransfer calldata t = transfers[i];
            groupOf[i] = t.shape == 0 ? G_T2X3 : G_T1X3;
            proofs[i] = t.proof;
            publics[i] = _transferPublics(t);
            for (uint256 j = 0; j < 3; j++) leaves[i * 3 + j] = t.commitments[j];
        }
        for (uint256 i = 0; i < withdraws.length; i++) {
            BatchWithdraw calldata w = withdraws[i];
            uint256 k = transfers.length + i;
            groupOf[k] = G_WITHDRAW;
            proofs[k] = w.proof;
            publics[k] = _withdrawPublics(w);
        }

        uint256[][] memory vks = new uint256[][](3);
        vks[G_T2X3] = IVerifierPoints(verifiers.transfer2x3).vkPoints();
        vks[G_T1X3] = IVerifierPoints(verifiers.transfer1x3).vkPoints();
        vks[G_WITHDRAW] = IVerifierPoints(verifiers.withdraw).vkPoints();
        if (!BatchVerifier.verify(vks, groupOf, proofs, publics)) revert InvalidProof();

        // state: outputs
        uint32 start = _insertMany(leaves);
        for (uint256 i = 0; i < transfers.length; i++) {
            BatchTransfer calldata t = transfers[i];
            for (uint256 j = 0; j < 3; j++) {
                emit NewCommitment(start + uint32(i * 3 + j), t.commitments[j], t.ownerMemos[j], t.auditMemos[j]);
            }
        }
        // state: payouts
        for (uint256 i = 0; i < withdraws.length; i++) {
            BatchWithdraw calldata w = withdraws[i];
            _payout(assetToken[w.asset], w.asset, w.amount, w.recipient, w.fee);
        }

        uint256 id = ++batchCount;
        emit BatchSubmitted(id, msg.sender, transfers.length, withdraws.length, getLastRoot());
    }

    /// @dev validity checks + nullifier marking + public input vector for a batched transfer
    ///      2x3: [n0, n1, f0, f1, c0, c1, c2, root, ax, ay, ct x 9]   (19)
    ///      1x3: [n0, f0, c0, c1, c2, root, ax, ay, ct x 9]           (17)
    function _transferPublics(BatchTransfer calldata t) internal returns (uint256[] memory pub) {
        uint256 nIn = t.shape == 0 ? 2 : (t.shape == 1 ? 1 : 0);
        if (nIn == 0 || t.nullifiers.length != nIn || t.freezers.length != nIn) revert BadShape();
        if (!isKnownRoot(t.root)) revert UnknownRoot();
        if (nIn == 2 && t.nullifiers[0] == t.nullifiers[1]) revert NullifierUsed();
        for (uint256 j = 0; j < 3; j++) _checkMemos(t.ownerMemos[j], t.auditMemos[j]);

        pub = new uint256[](nIn * 2 + 3 + 1 + 2 + 9);
        uint256 p = 0;
        for (uint256 i = 0; i < nIn; i++) {
            _spend(t.nullifiers[i], t.freezers[i]);
            pub[p++] = t.nullifiers[i];
        }
        for (uint256 i = 0; i < nIn; i++) pub[p++] = t.freezers[i];
        for (uint256 j = 0; j < 3; j++) pub[p++] = t.commitments[j];
        pub[p++] = t.root;
        pub[p++] = auditorX;
        pub[p++] = auditorY;
        for (uint256 j = 0; j < 3; j++) {
            (pub[p], pub[p + 1], pub[p + 2]) = _auditCiphertexts(t.auditMemos[j]);
            p += 3;
        }
    }

    function _withdrawPublics(BatchWithdraw calldata w) internal returns (uint256[] memory pub) {
        if (assetToken[w.asset] == address(0)) revert UnknownAsset();
        if (!isKnownRoot(w.root)) revert UnknownRoot();
        if (w.fee > w.amount) revert FeeExceedsAmount();
        _spend(w.nullifier, w.freezer);
        pub = new uint256[](7);
        pub[0] = w.asset;
        pub[1] = w.amount;
        pub[2] = w.nullifier;
        pub[3] = w.freezer;
        pub[4] = w.root;
        pub[5] = uint256(uint160(w.recipient));
        pub[6] = w.fee;
    }

    // ------------------------------------------------------------- internals
    /// @dev reject used / frozen, then mark the nullifier spent
    function _spend(uint256 nullifier, uint256 freezer) internal {
        if (nullifiers[nullifier]) revert NullifierUsed();
        if (frozen[freezer]) revert Frozen();
        nullifiers[nullifier] = true;
        emit NewNullifier(nullifier);
    }

    function _emitOutputs2(uint256[2] calldata commitments, bytes[2] calldata ownerMemos, bytes[2] calldata auditMemos)
        internal
    {
        uint256[] memory leaves = new uint256[](2);
        leaves[0] = commitments[0];
        leaves[1] = commitments[1];
        uint32 start = _insertMany(leaves);
        emit NewCommitment(start, commitments[0], ownerMemos[0], auditMemos[0]);
        emit NewCommitment(start + 1, commitments[1], ownerMemos[1], auditMemos[1]);
    }

    function _payout(address token, uint64 asset, uint128 amount, address recipient, uint128 fee) internal {
        require(IERC20Minimal(token).transfer(recipient, amount - fee), "transfer");
        if (fee > 0) require(IERC20Minimal(token).transfer(msg.sender, fee), "fee");
        emit Withdraw(asset, amount, recipient, fee, msg.sender);
    }

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
