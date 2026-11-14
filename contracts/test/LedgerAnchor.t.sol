// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {LedgerAnchor} from "../src/LedgerAnchor.sol";
import {RefTree} from "./AcvsMerkle.t.sol";

contract LedgerAnchorTest is Test {
    LedgerAnchor ledger;
    address admin = makeAddr("admin");
    address anchorer = makeAddr("anchorer");
    address stranger = makeAddr("stranger");

    event Anchored(
        uint64 indexed epoch, uint64 indexed height, bytes32 blockHash, bytes32 merkleRoot, uint32 leafCount
    );
    event Revoked(uint64 indexed epoch, uint64 indexed height, uint32 leafIndex);
    event EpochStarted(uint64 indexed epoch, uint64 fromHeight, string reason);
    event AnchorerChanged(address indexed previous, address indexed current);

    function setUp() public {
        ledger = new LedgerAnchor(admin, anchorer);
    }

    function _hash(uint256 h) private pure returns (bytes32) {
        return keccak256(abi.encode("block", h));
    }

    function _root(uint256 h) private pure returns (bytes32) {
        return keccak256(abi.encode("root", h));
    }

    /// Anchors heights `from..=to` with placeholder values and 10 leaves each.
    function _anchorRange(uint64 from, uint64 to) private {
        vm.startPrank(anchorer);
        for (uint64 h = from; h <= to; h++) {
            ledger.anchor(h, _hash(h), _root(h), 10);
        }
        vm.stopPrank();
    }

    // ---- construction ----

    function test_initialState() public view {
        assertEq(ledger.owner(), admin);
        assertEq(ledger.anchorer(), anchorer);
        assertEq(ledger.epoch(), 1);
        assertEq(ledger.nextHeight(), 1);
        assertEq(ledger.epochStartHeight(1), 1);
    }

    function test_constructorRejectsZeroAddresses() public {
        vm.expectRevert(LedgerAnchor.ZeroAddress.selector);
        new LedgerAnchor(admin, address(0));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new LedgerAnchor(address(0), anchorer);
    }

    // ---- anchoring ----

    function test_anchorStoresAndEmits() public {
        vm.warp(1_800_000_000);
        vm.expectEmit();
        emit Anchored(1, 1, _hash(1), _root(1), 42);
        vm.prank(anchorer);
        ledger.anchor(1, _hash(1), _root(1), 42);

        LedgerAnchor.Anchor memory a = ledger.anchorOf(1, 1);
        assertEq(a.blockHash, _hash(1));
        assertEq(a.merkleRoot, _root(1));
        assertEq(a.leafCount, 42);
        assertEq(a.anchoredAt, 1_800_000_000);
        assertEq(ledger.nextHeight(), 2);
    }

    function test_onlyAnchorerCanAnchor() public {
        vm.expectRevert(LedgerAnchor.NotAnchorer.selector);
        vm.prank(stranger);
        ledger.anchor(1, _hash(1), _root(1), 1);
        // The admin key is deliberately not allowed either: it stays offline.
        vm.expectRevert(LedgerAnchor.NotAnchorer.selector);
        vm.prank(admin);
        ledger.anchor(1, _hash(1), _root(1), 1);
    }

    function test_heightsMustBeConsecutive() public {
        vm.startPrank(anchorer);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.WrongHeight.selector, 1, 2));
        ledger.anchor(2, _hash(2), _root(2), 1);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.WrongHeight.selector, 1, 0));
        ledger.anchor(0, _hash(0), _root(0), 1);
        ledger.anchor(1, _hash(1), _root(1), 1);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.WrongHeight.selector, 2, 3));
        ledger.anchor(3, _hash(3), _root(3), 1);
        vm.stopPrank();
    }

    function test_anchoredHeightCannotBeOverwritten() public {
        _anchorRange(1, 3);
        vm.startPrank(anchorer);
        for (uint64 h = 1; h <= 3; h++) {
            vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.WrongHeight.selector, 4, h));
            ledger.anchor(h, keccak256("forged"), keccak256("forged"), 1);
        }
        vm.stopPrank();
        assertEq(ledger.anchorOf(1, 2).blockHash, _hash(2));
    }

    function test_zeroValuesAreRejected() public {
        vm.startPrank(anchorer);
        vm.expectRevert(LedgerAnchor.ZeroValue.selector);
        ledger.anchor(1, bytes32(0), _root(1), 1);
        vm.expectRevert(LedgerAnchor.ZeroValue.selector);
        ledger.anchor(1, _hash(1), bytes32(0), 1);
        vm.expectRevert(LedgerAnchor.ZeroValue.selector);
        ledger.anchor(1, _hash(1), _root(1), 0);
        vm.stopPrank();
    }

    function test_anchorBatch() public {
        _anchorRange(1, 2);
        LedgerAnchor.AnchorInput[] memory blocks = new LedgerAnchor.AnchorInput[](3);
        for (uint64 i = 0; i < 3; i++) {
            blocks[i] = LedgerAnchor.AnchorInput(_hash(3 + i), _root(3 + i), 5);
        }
        vm.prank(anchorer);
        ledger.anchorBatch(3, blocks);
        assertEq(ledger.nextHeight(), 6);
        assertEq(ledger.anchorOf(1, 5).blockHash, _hash(5));

        vm.startPrank(anchorer);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.WrongHeight.selector, 6, 4));
        ledger.anchorBatch(4, blocks);
        vm.expectRevert(LedgerAnchor.EmptyBatch.selector);
        ledger.anchorBatch(6, new LedgerAnchor.AnchorInput[](0));
        vm.stopPrank();
        vm.expectRevert(LedgerAnchor.NotAnchorer.selector);
        vm.prank(stranger);
        ledger.anchorBatch(6, blocks);
    }

    /// A batch with one bad block writes nothing.
    function test_anchorBatchIsAllOrNothing() public {
        LedgerAnchor.AnchorInput[] memory blocks = new LedgerAnchor.AnchorInput[](2);
        blocks[0] = LedgerAnchor.AnchorInput(_hash(1), _root(1), 5);
        blocks[1] = LedgerAnchor.AnchorInput(bytes32(0), _root(2), 5);
        vm.expectRevert(LedgerAnchor.ZeroValue.selector);
        vm.prank(anchorer);
        ledger.anchorBatch(1, blocks);
        assertEq(ledger.nextHeight(), 1);
        assertEq(ledger.anchorOf(1, 1).anchoredAt, 0);
    }

    // ---- revocation ----

    function test_revokeSetsOneBit() public {
        _anchorRange(1, 2);
        vm.expectEmit();
        emit Revoked(1, 2, 7);
        vm.prank(anchorer);
        ledger.revoke(1, 2, 7);
        assertTrue(ledger.isRevoked(1, 2, 7));
        assertFalse(ledger.isRevoked(1, 2, 6));
        assertFalse(ledger.isRevoked(1, 2, 8));
        assertFalse(ledger.isRevoked(1, 1, 7));
    }

    function test_revokeRules() public {
        _anchorRange(1, 1);
        vm.expectRevert(LedgerAnchor.NotAnchorer.selector);
        vm.prank(stranger);
        ledger.revoke(1, 1, 0);

        vm.startPrank(anchorer);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.NotAnchored.selector, 1, 2));
        ledger.revoke(1, 2, 0);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.NotAnchored.selector, 2, 1));
        ledger.revoke(2, 1, 0);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.LeafOutOfRange.selector, 10, 10));
        ledger.revoke(1, 1, 10);
        ledger.revoke(1, 1, 9);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.AlreadyRevoked.selector, 1, 1, 9));
        ledger.revoke(1, 1, 9);
        vm.stopPrank();
    }

    function test_revokeBatch() public {
        _anchorRange(1, 2);
        LedgerAnchor.Position[] memory p = new LedgerAnchor.Position[](3);
        p[0] = LedgerAnchor.Position(1, 1, 0);
        p[1] = LedgerAnchor.Position(1, 1, 9);
        p[2] = LedgerAnchor.Position(1, 2, 4);
        vm.prank(anchorer);
        ledger.revokeBatch(p);
        assertTrue(ledger.isRevoked(1, 1, 0) && ledger.isRevoked(1, 1, 9) && ledger.isRevoked(1, 2, 4));

        // One bad entry (already revoked) and the whole batch is refused.
        p[0] = LedgerAnchor.Position(1, 2, 5);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.AlreadyRevoked.selector, 1, 1, 9));
        vm.prank(anchorer);
        ledger.revokeBatch(p);
        assertFalse(ledger.isRevoked(1, 2, 5));

        vm.expectRevert(LedgerAnchor.EmptyBatch.selector);
        vm.prank(anchorer);
        ledger.revokeBatch(new LedgerAnchor.Position[](0));
    }

    /// Bits in a large block do not collide across the 256-bit word boundary.
    function testFuzz_revocationBitsAreIndependent(uint32 a, uint32 b) public {
        a = uint32(bound(a, 0, 9_999));
        b = uint32(bound(b, 0, 9_999));
        vm.assume(a != b);
        vm.startPrank(anchorer);
        ledger.anchor(1, _hash(1), _root(1), 10_000);
        ledger.revoke(1, 1, a);
        vm.stopPrank();
        assertTrue(ledger.isRevoked(1, 1, a));
        assertFalse(ledger.isRevoked(1, 1, b));
    }

    // ---- inclusion ----

    function _anchorTree(uint64 height, bytes32[] memory leaves) private {
        // Computed first: the SHA-256 precompile call would otherwise use up the prank.
        bytes32 root = RefTree.root(leaves);
        vm.prank(anchorer);
        ledger.anchor(height, _hash(height), root, uint32(leaves.length));
    }

    function test_verifyInclusionAndStatus() public {
        bytes32[] memory leaves = RefTree.make(11, 99);
        _anchorTree(1, leaves);
        for (uint32 i = 0; i < 11; i++) {
            assertTrue(ledger.verifyInclusion(1, 1, i, leaves[i], RefTree.proof(leaves, i)));
        }
        // Wrong position, wrong leaf, wrong block, wrong epoch.
        assertFalse(ledger.verifyInclusion(1, 1, 4, leaves[3], RefTree.proof(leaves, 3)));
        assertFalse(ledger.verifyInclusion(1, 1, 3, keccak256("x"), RefTree.proof(leaves, 3)));
        assertFalse(ledger.verifyInclusion(1, 2, 3, leaves[3], RefTree.proof(leaves, 3)));
        assertFalse(ledger.verifyInclusion(2, 1, 3, leaves[3], RefTree.proof(leaves, 3)));
        assertFalse(ledger.verifyInclusion(1, 1, 11, leaves[3], RefTree.proof(leaves, 3)));

        (bool included, bool revoked) = ledger.credentialStatus(1, 1, 3, leaves[3], RefTree.proof(leaves, 3));
        assertTrue(included);
        assertFalse(revoked);
        vm.prank(anchorer);
        ledger.revoke(1, 1, 3);
        (included, revoked) = ledger.credentialStatus(1, 1, 3, leaves[3], RefTree.proof(leaves, 3));
        assertTrue(included && revoked);
    }

    // ---- anchorer replacement ----

    function test_setAnchorer() public {
        address next = makeAddr("next");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, anchorer));
        vm.prank(anchorer);
        ledger.setAnchorer(next);
        vm.expectRevert(LedgerAnchor.ZeroAddress.selector);
        vm.prank(admin);
        ledger.setAnchorer(address(0));

        vm.expectEmit();
        emit AnchorerChanged(anchorer, next);
        vm.prank(admin);
        ledger.setAnchorer(next);

        // The old key is useless at once; the new one works.
        vm.expectRevert(LedgerAnchor.NotAnchorer.selector);
        vm.prank(anchorer);
        ledger.anchor(1, _hash(1), _root(1), 1);
        vm.prank(next);
        ledger.anchor(1, _hash(1), _root(1), 1);
    }

    // ---- epochs (restoring a backup) ----

    function test_startEpochRewindsAndKeepsHistory() public {
        _anchorRange(1, 5);
        vm.prank(anchorer);
        ledger.revoke(1, 4, 2);

        // The database was restored to a backup holding blocks 1-3; blocks 4 and 5 will be sealed again.
        vm.expectEmit();
        emit EpochStarted(2, 4, "restored backup of 2026-11-01");
        vm.prank(admin);
        ledger.startEpoch(4, "restored backup of 2026-11-01");
        assertEq(ledger.epoch(), 2);
        assertEq(ledger.nextHeight(), 4);
        assertEq(ledger.epochStartHeight(2), 4);

        vm.prank(anchorer);
        ledger.anchor(4, keccak256("new 4"), keccak256("new root 4"), 3);

        // Both versions of block 4 are readable, and the old revocation is still there.
        assertEq(ledger.anchorOf(1, 4).blockHash, _hash(4));
        assertEq(ledger.anchorOf(2, 4).blockHash, keccak256("new 4"));
        assertTrue(ledger.isRevoked(1, 4, 2));
        assertFalse(ledger.isRevoked(2, 4, 2));

        // Blocks before the rewind still stand in epoch 1; block 4 stands in epoch 2; block 5 is superseded
        // and not anchored again yet.
        (uint64 e, LedgerAnchor.Anchor memory a) = ledger.currentAnchor(3);
        assertEq(e, 1);
        assertEq(a.blockHash, _hash(3));
        (e, a) = ledger.currentAnchor(4);
        assertEq(e, 2);
        assertEq(a.blockHash, keccak256("new 4"));
        (e, a) = ledger.currentAnchor(5);
        assertEq(e, 0);
        assertEq(a.anchoredAt, 0);
        (e,) = ledger.currentAnchor(6);
        assertEq(e, 0);

        // A credential in a superseded block can still be revoked.
        vm.prank(anchorer);
        ledger.revoke(1, 5, 0);
        assertTrue(ledger.isRevoked(1, 5, 0));
    }

    function test_startEpochRules() public {
        _anchorRange(1, 3);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, anchorer));
        vm.prank(anchorer);
        ledger.startEpoch(2, "x");

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.BadEpochStart.selector, 0, 4));
        ledger.startEpoch(0, "x");
        vm.expectRevert(abi.encodeWithSelector(LedgerAnchor.BadEpochStart.selector, 5, 4));
        ledger.startEpoch(5, "x");
        vm.expectRevert(LedgerAnchor.ReasonRequired.selector);
        ledger.startEpoch(2, "");
        ledger.startEpoch(1, "everything lost");
        vm.stopPrank();
        assertEq(ledger.nextHeight(), 1);
        (uint64 e,) = ledger.currentAnchor(2);
        assertEq(e, 0);
    }

    function testFuzz_currentAnchorAcrossEpochs(uint8 first, uint8 rewind, uint8 second) public {
        uint64 n1 = uint64(bound(first, 1, 20));
        uint64 from = uint64(bound(rewind, 1, n1 + 1));
        uint64 n2 = uint64(bound(second, 0, 10));
        _anchorRange(1, n1);
        vm.prank(admin);
        ledger.startEpoch(from, "fuzz");
        if (n2 > 0) _anchorRange(from, from + n2 - 1);

        for (uint64 h = 1; h <= n1 + n2 + 1; h++) {
            (uint64 e,) = ledger.currentAnchor(h);
            if (h < from) assertEq(e, 1);
            else if (h < from + n2) assertEq(e, 2);
            else assertEq(e, 0);
        }
    }

    // ---- ownership ----

    function test_ownershipMovesInTwoSteps() public {
        address fresh = makeAddr("fresh admin key");
        vm.prank(admin);
        ledger.transferOwnership(fresh);
        assertEq(ledger.owner(), admin, "must not move until accepted");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        ledger.acceptOwnership();
        vm.prank(fresh);
        ledger.acceptOwnership();
        assertEq(ledger.owner(), fresh);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, admin));
        vm.prank(admin);
        ledger.setAnchorer(stranger);
    }

    function test_renounceIsDisabled() public {
        vm.expectRevert(LedgerAnchor.RenounceDisabled.selector);
        vm.prank(admin);
        ledger.renounceOwnership();
        assertEq(ledger.owner(), admin);
    }
}
