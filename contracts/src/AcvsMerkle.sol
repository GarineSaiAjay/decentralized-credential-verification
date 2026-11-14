// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title The ACVS ledger's Merkle tree, re-implemented for on-chain checks.
/// @notice Must stay identical to `crypto::merkle` in the Rust backend:
///   - leaf  = SHA-256(0x00 || credential hash)
///   - node  = SHA-256(0x01 || left || right)
///   - a node with no sibling is promoted to the next level unchanged (never duplicated)
/// The tests check this against vectors produced by the Rust code (`test/vectors/merkle.json`).
library AcvsMerkle {
    function leafHash(bytes32 credentialHash) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), credentialHash));
    }

    function nodeHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    /// @notice Recomputes the root for the leaf at `index` in a tree of `leafCount` leaves.
    /// @dev The side of every sibling follows from `index` and `leafCount`, so a proof is bound to one
    /// position: the same leaf cannot be shown to sit at another index. `siblings` are bottom-up and hold no
    /// entry for a level at which the node is promoted.
    /// @return ok False if the index is out of range or the proof has the wrong number of siblings.
    /// @return root The recomputed root (meaningful only when `ok`).
    function computeRoot(
        bytes32 credentialHash,
        uint256 index,
        uint256 leafCount,
        bytes32[] calldata siblings
    ) internal pure returns (bool ok, bytes32 root) {
        if (index >= leafCount) return (false, bytes32(0));
        root = leafHash(credentialHash);
        uint256 used = 0;
        uint256 width = leafCount;
        while (width > 1) {
            // The sibling exists unless this node is the last one of an odd-sized level.
            if ((index ^ 1) < width) {
                if (used == siblings.length) return (false, bytes32(0));
                bytes32 sibling = siblings[used++];
                root = (index & 1) == 1 ? nodeHash(sibling, root) : nodeHash(root, sibling);
            }
            index >>= 1;
            width = (width + 1) >> 1;
        }
        ok = used == siblings.length;
    }
}
