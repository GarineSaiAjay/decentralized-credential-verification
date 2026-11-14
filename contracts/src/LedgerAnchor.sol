// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {AcvsMerkle} from "./AcvsMerkle.sol";

/// @title Public anchor for one university's ACVS ledger.
/// @notice Stores, for every sealed ledger block, its hash and Merkle root, and one revocation bit per
/// credential position. Nothing here identifies a person: no credential hash is stored, only block-level
/// values and positions (block height + leaf index).
///
/// Two keys:
///   - the owner (the issuer admin, kept offline) replaces the anchorer and starts epochs;
///   - the anchorer (a hot key in the worker) anchors blocks and sets revocation bits, nothing else.
///
/// Nothing written here can be changed or removed: an anchored height cannot be overwritten and a
/// revocation bit cannot be cleared.
contract LedgerAnchor is Ownable2Step {
    struct Anchor {
        bytes32 blockHash; // SHA-256("ACVS-BLOCK-v1|height|prev|root|ts|n"), as the backend computes it
        bytes32 merkleRoot;
        uint32 leafCount;
        uint64 anchoredAt; // chain time; 0 means "not anchored"
    }

    struct AnchorInput {
        bytes32 blockHash;
        bytes32 merkleRoot;
        uint32 leafCount;
    }

    struct Position {
        uint64 epoch;
        uint64 height;
        uint32 leafIndex;
    }

    /// @notice The only address allowed to anchor blocks and set revocation bits.
    address public anchorer;
    /// @notice The current epoch. Starts at 1; grows only through `startEpoch`.
    uint64 public epoch;
    /// @notice The only height the next `anchor` call may use.
    uint64 public nextHeight;
    /// @notice The first height each epoch covers.
    mapping(uint64 epoch => uint64 height) public epochStartHeight;

    mapping(uint64 epoch => mapping(uint64 height => Anchor)) private _anchors;
    mapping(uint64 epoch => mapping(uint64 height => mapping(uint256 word => uint256 bits))) private _revoked;

    event AnchorerChanged(address indexed previous, address indexed current);
    event Anchored(
        uint64 indexed epoch, uint64 indexed height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount
    );
    event Revoked(uint64 indexed epoch, uint64 indexed height, uint32 leafIndex);
    event EpochStarted(uint64 indexed epoch, uint64 fromHeight, string reason);

    error NotAnchorer();
    error ZeroAddress();
    error ZeroValue();
    error EmptyBatch();
    error WrongHeight(uint64 expected, uint64 given);
    error NotAnchored(uint64 epoch, uint64 height);
    error LeafOutOfRange(uint32 leafIndex, uint32 leafCount);
    error AlreadyRevoked(uint64 epoch, uint64 height, uint32 leafIndex);
    error BadEpochStart(uint64 fromHeight, uint64 nextHeight);
    error ReasonRequired();
    error RenounceDisabled();

    modifier onlyAnchorer() {
        if (msg.sender != anchorer) revert NotAnchorer();
        _;
    }

    constructor(address admin, address anchorer_) Ownable(admin) {
        if (anchorer_ == address(0)) revert ZeroAddress();
        anchorer = anchorer_;
        epoch = 1;
        nextHeight = 1;
        epochStartHeight[1] = 1;
        emit AnchorerChanged(address(0), anchorer_);
        emit EpochStarted(1, 1, "genesis");
    }

    // ---- owner (issuer admin) ----

    /// @notice Replaces the anchorer, for example after its key may have leaked.
    function setAnchorer(address anchorer_) external onlyOwner {
        if (anchorer_ == address(0)) revert ZeroAddress();
        emit AnchorerChanged(anchorer, anchorer_);
        anchorer = anchorer_;
    }

    /// @notice Starts a new epoch that continues anchoring from `fromHeight`.
    /// @dev For the case where the ledger no longer matches what was anchored, typically after restoring a
    /// database backup that lost sealed blocks. Earlier anchors are kept forever and stay readable; the
    /// change and its reason are public. `fromHeight` may be anything from 1 to `nextHeight`.
    function startEpoch(uint64 fromHeight, string calldata reason) external onlyOwner {
        if (fromHeight == 0 || fromHeight > nextHeight) revert BadEpochStart(fromHeight, nextHeight);
        if (bytes(reason).length == 0) revert ReasonRequired();
        epoch += 1;
        nextHeight = fromHeight;
        epochStartHeight[epoch] = fromHeight;
        emit EpochStarted(epoch, fromHeight, reason);
    }

    /// @dev Giving up ownership would freeze the anchorer and epochs for good.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }

    // ---- anchorer ----

    /// @notice Records one sealed block. Heights are consecutive and can never be written twice.
    function anchor(uint64 height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount)
        external
        onlyAnchorer
    {
        _anchor(height, blockHash, merkleRoot, leafCount);
    }

    /// @notice Records consecutive blocks starting at `firstHeight` (used to catch up an existing ledger).
    function anchorBatch(uint64 firstHeight, AnchorInput[] calldata blocks) external onlyAnchorer {
        if (blocks.length == 0) revert EmptyBatch();
        for (uint256 i = 0; i < blocks.length; i++) {
            AnchorInput calldata b = blocks[i];
            _anchor(firstHeight + uint64(i), b.blockHash, b.merkleRoot, b.leafCount);
        }
    }

    /// @notice Marks the credential at a ledger position as revoked. Cannot be undone.
    function revoke(uint64 epoch_, uint64 height, uint32 leafIndex) external onlyAnchorer {
        _revoke(epoch_, height, leafIndex);
    }

    function revokeBatch(Position[] calldata positions) external onlyAnchorer {
        if (positions.length == 0) revert EmptyBatch();
        for (uint256 i = 0; i < positions.length; i++) {
            _revoke(positions[i].epoch, positions[i].height, positions[i].leafIndex);
        }
    }

    // ---- anyone ----

    /// @notice The anchor stored for a height in a given epoch (`anchoredAt` is 0 if there is none).
    function anchorOf(uint64 epoch_, uint64 height) external view returns (Anchor memory) {
        return _anchors[epoch_][height];
    }

    /// @notice The anchor that currently stands for a height: the one from the latest epoch covering it.
    /// @return epoch_ 0 if the height is not anchored in the epoch that now covers it.
    function currentAnchor(uint64 height) external view returns (uint64 epoch_, Anchor memory a) {
        for (uint64 e = epoch; e >= 1; e--) {
            a = _anchors[e][height];
            if (a.anchoredAt != 0) return (e, a);
            // This epoch covers the height but has not anchored it (yet): older anchors are superseded.
            if (epochStartHeight[e] <= height) break;
        }
        return (0, Anchor(bytes32(0), bytes32(0), 0, 0));
    }

    function isRevoked(uint64 epoch_, uint64 height, uint32 leafIndex) public view returns (bool) {
        return (_revoked[epoch_][height][leafIndex >> 8] >> (leafIndex & 0xff)) & 1 == 1;
    }

    /// @notice True if `credentialHash` is the leaf at `leafIndex` of the block anchored at this height.
    /// @param siblings The Merkle proof, bottom-up (the `hash` values of the backend's proof steps).
    function verifyInclusion(
        uint64 epoch_,
        uint64 height,
        uint32 leafIndex,
        bytes32 credentialHash,
        bytes32[] calldata siblings
    ) public view returns (bool) {
        Anchor storage a = _anchors[epoch_][height];
        if (a.anchoredAt == 0) return false;
        (bool ok, bytes32 root) = AcvsMerkle.computeRoot(credentialHash, leafIndex, a.leafCount, siblings);
        return ok && root == a.merkleRoot;
    }

    /// @notice Inclusion and revocation in one call, for verifiers.
    function credentialStatus(
        uint64 epoch_,
        uint64 height,
        uint32 leafIndex,
        bytes32 credentialHash,
        bytes32[] calldata siblings
    ) external view returns (bool included, bool revoked) {
        included = verifyInclusion(epoch_, height, leafIndex, credentialHash, siblings);
        revoked = isRevoked(epoch_, height, leafIndex);
    }

    // ---- internal ----

    function _anchor(uint64 height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount) private {
        if (height != nextHeight) revert WrongHeight(nextHeight, height);
        if (blockHash == bytes32(0) || merkleRoot == bytes32(0) || leafCount == 0) revert ZeroValue();
        _anchors[epoch][height] = Anchor(blockHash, merkleRoot, leafCount, uint64(block.timestamp));
        nextHeight = height + 1;
        emit Anchored(epoch, height, blockHash, merkleRoot, leafCount);
    }

    function _revoke(uint64 epoch_, uint64 height, uint32 leafIndex) private {
        Anchor storage a = _anchors[epoch_][height];
        if (a.anchoredAt == 0) revert NotAnchored(epoch_, height);
        if (leafIndex >= a.leafCount) revert LeafOutOfRange(leafIndex, a.leafCount);
        if (isRevoked(epoch_, height, leafIndex)) revert AlreadyRevoked(epoch_, height, leafIndex);
        _revoked[epoch_][height][leafIndex >> 8] |= uint256(1) << (leafIndex & 0xff);
        emit Revoked(epoch_, height, leafIndex);
    }
}
