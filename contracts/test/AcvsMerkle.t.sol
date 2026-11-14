// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {AcvsMerkle} from "../src/AcvsMerkle.sol";

/// Exposes the library with calldata arguments, as the contracts call it.
contract MerkleHarness {
    function computeRoot(bytes32 leaf, uint256 index, uint256 leafCount, bytes32[] calldata siblings)
        external
        pure
        returns (bool, bytes32)
    {
        return AcvsMerkle.computeRoot(leaf, index, leafCount, siblings);
    }
}

/// A plain in-memory copy of the tree rules, used to build trees of any size in the fuzz tests.
library RefTree {
    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory level = new bytes32[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            level[i] = AcvsMerkle.leafHash(leaves[i]);
        }
        while (level.length > 1) {
            level = _up(level);
        }
        return level[0];
    }

    function proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory out) {
        bytes32[] memory level = new bytes32[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            level[i] = AcvsMerkle.leafHash(leaves[i]);
        }
        bytes32[] memory buf = new bytes32[](64);
        uint256 used = 0;
        while (level.length > 1) {
            if ((index ^ 1) < level.length) buf[used++] = level[index ^ 1];
            index >>= 1;
            level = _up(level);
        }
        out = new bytes32[](used);
        for (uint256 i = 0; i < used; i++) {
            out[i] = buf[i];
        }
    }

    function _up(bytes32[] memory level) private pure returns (bytes32[] memory next) {
        next = new bytes32[]((level.length + 1) / 2);
        for (uint256 i = 0; i < next.length; i++) {
            next[i] =
                2 * i + 1 < level.length ? AcvsMerkle.nodeHash(level[2 * i], level[2 * i + 1]) : level[2 * i];
        }
    }

    function make(uint256 n, uint256 seed) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = keccak256(abi.encode(seed, i));
        }
    }
}

contract AcvsMerkleTest is Test {
    MerkleHarness h = new MerkleHarness();

    /// Every proof the Rust backend produces, for every tree shape in the vector file, gives the Rust root.
    function test_matchesRustVectors() public view {
        string memory json = vm.readFile("test/vectors/merkle.json");
        uint256 count = vm.parseJsonUint(json, ".count");
        assertGt(count, 10);
        uint256 checked = 0;
        for (uint256 c = 0; c < count; c++) {
            string memory base = string.concat(".cases[", vm.toString(c), "]");
            uint256 n = vm.parseJsonUint(json, string.concat(base, ".n"));
            bytes32 root = vm.parseJsonBytes32(json, string.concat(base, ".root"));
            bytes32[] memory leaves = vm.parseJsonBytes32Array(json, string.concat(base, ".leaves"));
            assertEq(leaves.length, n);
            assertEq(RefTree.root(leaves), root, "reference tree differs from Rust");
            for (uint256 i = 0; i < n; i++) {
                string memory p = string.concat(base, ".proofs[", vm.toString(i), "]");
                uint256 depth = vm.parseJsonUint(json, string.concat(p, ".depth"));
                bytes32[] memory siblings = new bytes32[](0);
                bool[] memory left = new bool[](0);
                if (depth > 0) {
                    siblings = vm.parseJsonBytes32Array(json, string.concat(p, ".siblings"));
                    left = vm.parseJsonBoolArray(json, string.concat(p, ".left"));
                }
                assertEq(siblings.length, depth);
                (bool ok, bytes32 got) = h.computeRoot(leaves[i], i, n, siblings);
                assertTrue(ok, "proof rejected");
                assertEq(got, root, "root differs from Rust");
                _assertSidesMatch(i, n, left);
                checked++;
            }
        }
        assertGt(checked, 150);
    }

    /// The side of each sibling, as Rust records it, is exactly what the contract derives from the index.
    function _assertSidesMatch(uint256 index, uint256 width, bool[] memory left) private pure {
        uint256 used = 0;
        while (width > 1) {
            if ((index ^ 1) < width) {
                assertEq(left[used], (index & 1) == 1, "sibling side differs from Rust");
                used++;
            }
            index >>= 1;
            width = (width + 1) >> 1;
        }
        assertEq(used, left.length);
    }

    function test_singleLeafTreeHasEmptyProof() public view {
        bytes32 leaf = keccak256("only");
        (bool ok, bytes32 root) = h.computeRoot(leaf, 0, 1, new bytes32[](0));
        assertTrue(ok);
        assertEq(root, sha256(abi.encodePacked(bytes1(0x00), leaf)));
    }

    function test_leafAndNodeAreDomainSeparated() public pure {
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        assertEq(AcvsMerkle.leafHash(a), sha256(abi.encodePacked(bytes1(0x00), a)));
        assertEq(AcvsMerkle.nodeHash(a, b), sha256(abi.encodePacked(bytes1(0x01), a, b)));
        assertTrue(AcvsMerkle.nodeHash(a, b) != AcvsMerkle.nodeHash(b, a));
    }

    function test_indexOutOfRangeIsRejected() public view {
        bytes32[] memory leaves = RefTree.make(5, 1);
        (bool ok,) = h.computeRoot(leaves[4], 5, 5, RefTree.proof(leaves, 4));
        assertFalse(ok);
        (ok,) = h.computeRoot(leaves[0], 0, 0, new bytes32[](0));
        assertFalse(ok);
    }

    function testFuzz_everyLeafVerifies(uint8 size, uint256 seed) public view {
        uint256 n = bound(size, 1, 70);
        bytes32[] memory leaves = RefTree.make(n, seed);
        bytes32 root = RefTree.root(leaves);
        for (uint256 i = 0; i < n; i++) {
            (bool ok, bytes32 got) = h.computeRoot(leaves[i], i, n, RefTree.proof(leaves, i));
            assertTrue(ok);
            assertEq(got, root);
        }
    }

    /// A proof is bound to its position: it does not verify at any other index.
    function testFuzz_proofFailsAtAnotherIndex(uint8 size, uint256 seed, uint256 a, uint256 b) public view {
        uint256 n = bound(size, 2, 70);
        a = bound(a, 0, n - 1);
        b = bound(b, 0, n - 1);
        vm.assume(a != b);
        bytes32[] memory leaves = RefTree.make(n, seed);
        (bool ok, bytes32 got) = h.computeRoot(leaves[a], b, n, RefTree.proof(leaves, a));
        assertFalse(ok && got == RefTree.root(leaves));
    }

    function testFuzz_wrongLeafFails(uint8 size, uint256 seed, uint256 index, bytes32 other) public view {
        uint256 n = bound(size, 1, 70);
        index = bound(index, 0, n - 1);
        bytes32[] memory leaves = RefTree.make(n, seed);
        vm.assume(other != leaves[index]);
        (, bytes32 got) = h.computeRoot(other, index, n, RefTree.proof(leaves, index));
        assertTrue(got != RefTree.root(leaves));
    }

    function testFuzz_wrongProofLengthFails(uint8 size, uint256 seed, uint256 index) public view {
        uint256 n = bound(size, 2, 70);
        index = bound(index, 0, n - 1);
        bytes32[] memory leaves = RefTree.make(n, seed);
        bytes32[] memory good = RefTree.proof(leaves, index);

        bytes32[] memory longer = new bytes32[](good.length + 1);
        for (uint256 i = 0; i < good.length; i++) {
            longer[i] = good[i];
        }
        (bool ok,) = h.computeRoot(leaves[index], index, n, longer);
        assertFalse(ok, "extra sibling accepted");

        if (good.length > 0) {
            bytes32[] memory shorter = new bytes32[](good.length - 1);
            for (uint256 i = 0; i < shorter.length; i++) {
                shorter[i] = good[i];
            }
            (ok,) = h.computeRoot(leaves[index], index, n, shorter);
            assertFalse(ok, "missing sibling accepted");
        }
    }

    /// An inner node cannot be passed off as a leaf (the 0x00/0x01 prefixes prevent it).
    function test_innerNodeIsNotALeaf() public view {
        bytes32[] memory leaves = RefTree.make(4, 7);
        bytes32 root = RefTree.root(leaves);
        bytes32 inner = AcvsMerkle.nodeHash(AcvsMerkle.leafHash(leaves[0]), AcvsMerkle.leafHash(leaves[1]));
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = AcvsMerkle.nodeHash(AcvsMerkle.leafHash(leaves[2]), AcvsMerkle.leafHash(leaves[3]));
        (, bytes32 got) = h.computeRoot(inner, 0, 2, siblings);
        assertTrue(got != root);
    }
}
