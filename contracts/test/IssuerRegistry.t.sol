// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IssuerRegistry} from "../src/IssuerRegistry.sol";

contract IssuerRegistryTest is Test {
    IssuerRegistry reg;
    address owner = makeAddr("registry owner");
    address admin = makeAddr("issuer admin");
    address stranger = makeAddr("stranger");
    address ledger = makeAddr("ledger");
    uint64 id;

    bytes32 constant K1 = keccak256("key 1");
    bytes32 constant K2 = keccak256("key 2");
    bytes32 constant K3 = keccak256("key 3");

    event IssuerRegistered(
        uint64 indexed issuerId, address indexed admin, address ledger, string name, string did
    );
    event KeyAdded(uint64 indexed issuerId, bytes32 indexed publicKey, IssuerRegistry.Stage stage);
    event KeyRetired(uint64 indexed issuerId, bytes32 indexed publicKey);
    event KeyRevoked(uint64 indexed issuerId, bytes32 indexed publicKey, string reason);

    function setUp() public {
        reg = new IssuerRegistry(owner);
        vm.prank(owner);
        id = reg.registerIssuer(admin, "Example University", "did:web:example.edu", ledger);
    }

    function _status(bytes32 key) private view returns (IssuerRegistry.KeyStatus) {
        return reg.keyInfo(id, key).status;
    }

    // ---- issuers ----

    function test_registerIssuer() public {
        assertEq(id, 1);
        IssuerRegistry.Issuer memory s = reg.issuer(1);
        assertEq(s.admin, admin);
        assertEq(s.ledger, ledger);
        assertEq(s.name, "Example University");
        assertEq(s.did, "did:web:example.edu");
        assertFalse(s.suspended);

        vm.expectEmit();
        emit IssuerRegistered(2, stranger, address(0), "Other", "did:web:other.edu");
        vm.prank(owner);
        assertEq(reg.registerIssuer(stranger, "Other", "did:web:other.edu", address(0)), 2);
        assertEq(reg.issuerCount(), 2);
    }

    function test_onlyOwnerRegistersIssuers() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, admin));
        vm.prank(admin);
        reg.registerIssuer(admin, "Fake University", "did:web:fake.edu", address(0));
    }

    function test_registerRejectsBadInput() public {
        vm.startPrank(owner);
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        reg.registerIssuer(address(0), "A", "did:a", address(0));
        vm.expectRevert(IssuerRegistry.EmptyText.selector);
        reg.registerIssuer(admin, "", "did:a", address(0));
        vm.expectRevert(IssuerRegistry.EmptyText.selector);
        reg.registerIssuer(admin, "A", "", address(0));
        vm.stopPrank();
    }

    function test_unknownIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.UnknownIssuer.selector, 9));
        reg.issuer(9);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.UnknownIssuer.selector, 9));
        vm.prank(admin);
        reg.addKey(9, K1, IssuerRegistry.Stage.Faculty);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.UnknownIssuer.selector, 0));
        vm.prank(owner);
        reg.suspendIssuer(0, "x");
        assertFalse(reg.isKeyTrusted(9, K1));
    }

    function test_profileIsTheOwnersCall() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, admin));
        vm.prank(admin);
        reg.setIssuerProfile(id, "Harvard", "did:web:harvard.edu");
        vm.prank(owner);
        reg.setIssuerProfile(id, "Example University (renamed)", "did:web:example.ac");
        assertEq(reg.issuer(id).name, "Example University (renamed)");
        vm.expectRevert(IssuerRegistry.EmptyText.selector);
        vm.prank(owner);
        reg.setIssuerProfile(id, "", "did:web:example.ac");
    }

    function test_suspendAndReinstate() public {
        vm.prank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.University);
        assertTrue(reg.isKeyTrusted(id, K1));

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, admin));
        vm.prank(admin);
        reg.suspendIssuer(id, "x");

        vm.startPrank(owner);
        vm.expectRevert(IssuerRegistry.ReasonRequired.selector);
        reg.suspendIssuer(id, "");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotSuspended.selector, id));
        reg.reinstateIssuer(id, "x");
        reg.suspendIssuer(id, "accreditation withdrawn");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.AlreadySuspended.selector, id));
        reg.suspendIssuer(id, "again");
        vm.stopPrank();

        assertTrue(reg.issuer(id).suspended);
        assertFalse(reg.isKeyTrusted(id, K1), "a suspended issuer's keys are not trusted");
        // The record itself is untouched, so history stays readable.
        assertEq(uint8(_status(K1)), uint8(IssuerRegistry.KeyStatus.Active));

        vm.prank(owner);
        reg.reinstateIssuer(id, "accreditation restored");
        assertTrue(reg.isKeyTrusted(id, K1));
    }

    // ---- issuer admin ----

    function test_adminTransferTakesTwoSteps() public {
        address fresh = makeAddr("fresh admin key");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        vm.prank(stranger);
        reg.transferIssuerAdmin(id, stranger);

        vm.prank(admin);
        reg.transferIssuerAdmin(id, fresh);
        assertEq(reg.issuer(id).admin, admin, "must not move until accepted");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotPendingAdmin.selector, id));
        vm.prank(stranger);
        reg.acceptIssuerAdmin(id);

        vm.prank(fresh);
        reg.acceptIssuerAdmin(id);
        assertEq(reg.issuer(id).admin, fresh);
        assertEq(reg.issuer(id).pendingAdmin, address(0));

        // The old key has no power left; the new one does.
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        vm.prank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        vm.prank(fresh);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
    }

    function test_adminTransferCanBeCancelled() public {
        vm.startPrank(admin);
        reg.transferIssuerAdmin(id, stranger);
        reg.transferIssuerAdmin(id, address(0));
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotPendingAdmin.selector, id));
        vm.prank(stranger);
        reg.acceptIssuerAdmin(id);
    }

    function test_nobodyCanAcceptWhenNothingIsPending() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotPendingAdmin.selector, id));
        vm.prank(stranger);
        reg.acceptIssuerAdmin(id);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.UnknownIssuer.selector, 5));
        vm.prank(address(0));
        reg.acceptIssuerAdmin(5);
    }

    /// The registry owner lists issuers but cannot touch an issuer's keys or ledger.
    function test_registryOwnerCannotManageAnIssuersKeys() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        reg.setLedger(id, stranger);
        vm.stopPrank();
    }

    function test_setLedger() public {
        address next = makeAddr("next ledger");
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        vm.prank(admin);
        reg.setLedger(id, address(0));
        vm.prank(admin);
        reg.setLedger(id, next);
        assertEq(reg.issuer(id).ledger, next);
    }

    // ---- keys ----

    function test_addKey() public {
        vm.warp(1_800_000_000);
        vm.expectEmit();
        emit KeyAdded(id, K1, IssuerRegistry.Stage.Registrar);
        vm.prank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.Registrar);

        IssuerRegistry.Key memory k = reg.keyInfo(id, K1);
        assertEq(uint8(k.status), uint8(IssuerRegistry.KeyStatus.Active));
        assertEq(uint8(k.stage), uint8(IssuerRegistry.Stage.Registrar));
        assertEq(k.addedAt, 1_800_000_000);
        assertEq(reg.activeKey(id, IssuerRegistry.Stage.Registrar), K1);
        assertTrue(reg.isKeyTrusted(id, K1));
        assertFalse(reg.isKeyTrusted(id, K2), "an unknown key is not trusted");
    }

    function test_addKeyRules() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        vm.prank(stranger);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);

        vm.startPrank(admin);
        vm.expectRevert(IssuerRegistry.ZeroKey.selector);
        reg.addKey(id, bytes32(0), IssuerRegistry.Stage.Faculty);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyExists.selector, K1));
        reg.addKey(id, K1, IssuerRegistry.Stage.ExamCell);
        // One active key per stage, as in the backend.
        vm.expectRevert(
            abi.encodeWithSelector(
                IssuerRegistry.StageHasActiveKey.selector, IssuerRegistry.Stage.Faculty, K1
            )
        );
        reg.addKey(id, K2, IssuerRegistry.Stage.Faculty);
        // Other stages are independent.
        reg.addKey(id, K2, IssuerRegistry.Stage.ExamCell);
        vm.stopPrank();
    }

    function test_rotation() public {
        vm.startPrank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.University);
        vm.expectEmit();
        emit KeyRetired(id, K1);
        reg.retireKey(id, K1);
        assertEq(reg.activeKey(id, IssuerRegistry.Stage.University), bytes32(0));
        reg.addKey(id, K2, IssuerRegistry.Stage.University);
        vm.stopPrank();

        assertEq(uint8(_status(K1)), uint8(IssuerRegistry.KeyStatus.Retired));
        assertTrue(reg.isKeyTrusted(id, K1), "what a retired key signed stays good");
        assertTrue(reg.isKeyTrusted(id, K2));
        assertEq(reg.activeKey(id, IssuerRegistry.Stage.University), K2);
    }

    function test_revokeActiveKey() public {
        vm.startPrank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.ExamCell);
        vm.expectRevert(IssuerRegistry.ReasonRequired.selector);
        reg.revokeKey(id, K1, "");
        vm.expectEmit();
        emit KeyRevoked(id, K1, "laptop stolen");
        reg.revokeKey(id, K1, "laptop stolen");
        vm.stopPrank();

        assertEq(uint8(_status(K1)), uint8(IssuerRegistry.KeyStatus.Revoked));
        assertFalse(reg.isKeyTrusted(id, K1));
        assertEq(
            reg.activeKey(id, IssuerRegistry.Stage.ExamCell), bytes32(0), "the stage is free for a new key"
        );
    }

    /// Revoking a retired key must not disturb the key that replaced it.
    function test_revokeRetiredKeyKeepsTheNewActiveKey() public {
        vm.startPrank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        reg.retireKey(id, K1);
        reg.addKey(id, K2, IssuerRegistry.Stage.Faculty);
        reg.revokeKey(id, K1, "found to be compromised later");
        vm.stopPrank();
        assertFalse(reg.isKeyTrusted(id, K1));
        assertTrue(reg.isKeyTrusted(id, K2));
        assertEq(reg.activeKey(id, IssuerRegistry.Stage.Faculty), K2);
    }

    /// Statuses only move forward: nothing brings a retired or revoked key back.
    function test_statusOnlyMovesForward() public {
        vm.startPrank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        reg.retireKey(id, K1);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyNotActive.selector, K1));
        reg.retireKey(id, K1);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyExists.selector, K1));
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);

        reg.revokeKey(id, K1, "compromised");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyNotRevocable.selector, K1));
        reg.revokeKey(id, K1, "again");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyNotActive.selector, K1));
        reg.retireKey(id, K1);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyExists.selector, K1));
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);

        // A key that was never registered can be neither retired nor revoked.
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyNotActive.selector, K3));
        reg.retireKey(id, K3);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.KeyNotRevocable.selector, K3));
        reg.revokeKey(id, K3, "x");
        vm.stopPrank();
        assertEq(uint8(_status(K1)), uint8(IssuerRegistry.KeyStatus.Revoked));
    }

    function test_keyTimestamps() public {
        vm.startPrank(admin);
        vm.warp(1000);
        reg.addKey(id, K1, IssuerRegistry.Stage.Faculty);
        vm.warp(2000);
        reg.retireKey(id, K1);
        vm.warp(3000);
        reg.revokeKey(id, K1, "compromised");
        vm.stopPrank();
        IssuerRegistry.Key memory k = reg.keyInfo(id, K1);
        assertEq(k.addedAt, 1000);
        assertEq(k.retiredAt, 2000);
        assertEq(k.revokedAt, 3000);
    }

    /// One issuer's admin and keys mean nothing for another issuer.
    function test_issuersAreIsolated() public {
        address admin2 = makeAddr("second admin");
        vm.prank(owner);
        uint64 id2 = reg.registerIssuer(admin2, "Second University", "did:web:second.edu", address(0));

        vm.prank(admin);
        reg.addKey(id, K1, IssuerRegistry.Stage.University);
        assertFalse(reg.isKeyTrusted(id2, K1));

        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id2));
        vm.prank(admin);
        reg.addKey(id2, K2, IssuerRegistry.Stage.University);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotIssuerAdmin.selector, id));
        vm.prank(admin2);
        reg.revokeKey(id, K1, "sabotage");

        // The same public key may be registered by both without one affecting the other.
        vm.prank(admin2);
        reg.addKey(id2, K1, IssuerRegistry.Stage.Faculty);
        vm.prank(admin2);
        reg.revokeKey(id2, K1, "x");
        assertTrue(reg.isKeyTrusted(id, K1));
    }

    // ---- registry ownership ----

    function test_registryOwnershipMovesInTwoSteps() public {
        vm.prank(owner);
        reg.transferOwnership(stranger);
        assertEq(reg.owner(), owner);
        vm.prank(stranger);
        reg.acceptOwnership();
        assertEq(reg.owner(), stranger);
    }

    function test_renounceIsDisabled() public {
        vm.expectRevert(IssuerRegistry.RenounceDisabled.selector);
        vm.prank(owner);
        reg.renounceOwnership();
        assertEq(reg.owner(), owner);
    }
}
