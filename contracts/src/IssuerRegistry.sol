// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @title Registry of credential issuers (universities) and their ACVS signing keys.
/// @notice Answers two questions for a verifier who does not trust any one server:
///   "is this a recognised issuer?" and "is this Ed25519 key one of its own, and is it still trusted?"
///
/// Roles:
///   - the registry owner lists issuers and can suspend one (a governance role; see docs/ONCHAIN-PLAN.md);
///   - each issuer's admin (kept offline) manages that issuer's keys and its ledger contract address.
///
/// Key statuses mirror the backend's `signing_keys.status` and only move forward:
///   Active -> Retired (replaced; what it signed stays good) -> Revoked (compromised; what it signed is not).
contract IssuerRegistry is Ownable2Step {
    enum KeyStatus {
        None,
        Active,
        Retired,
        Revoked
    }

    /// @dev The four approval stages, in the order they sign.
    enum Stage {
        Faculty,
        ExamCell,
        Registrar,
        University
    }

    struct Issuer {
        address admin;
        address pendingAdmin;
        address ledger; // this issuer's LedgerAnchor contract
        bool suspended;
        uint64 registeredAt;
        string name;
        string did;
    }

    struct Key {
        KeyStatus status;
        Stage stage;
        uint64 addedAt;
        uint64 retiredAt;
        uint64 revokedAt;
    }

    /// @notice Issuer ids run from 1 to `issuerCount`.
    uint64 public issuerCount;
    /// @notice The one active key of each stage (zero if the stage has none).
    mapping(uint64 issuerId => mapping(Stage => bytes32 publicKey)) public activeKey;

    mapping(uint64 issuerId => Issuer) private _issuers;
    mapping(uint64 issuerId => mapping(bytes32 publicKey => Key)) private _keys;

    event IssuerRegistered(
        uint64 indexed issuerId, address indexed admin, address ledger, string name, string did
    );
    event IssuerProfileChanged(uint64 indexed issuerId, string name, string did);
    event IssuerSuspended(uint64 indexed issuerId, string reason);
    event IssuerReinstated(uint64 indexed issuerId, string reason);
    event IssuerAdminTransferStarted(
        uint64 indexed issuerId, address indexed current, address indexed proposed
    );
    event IssuerAdminChanged(uint64 indexed issuerId, address indexed previous, address indexed current);
    event LedgerChanged(uint64 indexed issuerId, address indexed previous, address indexed current);
    event KeyAdded(uint64 indexed issuerId, bytes32 indexed publicKey, Stage stage);
    event KeyRetired(uint64 indexed issuerId, bytes32 indexed publicKey);
    event KeyRevoked(uint64 indexed issuerId, bytes32 indexed publicKey, string reason);

    error UnknownIssuer(uint64 issuerId);
    error NotIssuerAdmin(uint64 issuerId);
    error NotPendingAdmin(uint64 issuerId);
    error ZeroAddress();
    error ZeroKey();
    error EmptyText();
    error ReasonRequired();
    error AlreadySuspended(uint64 issuerId);
    error NotSuspended(uint64 issuerId);
    error KeyExists(bytes32 publicKey);
    error StageHasActiveKey(Stage stage, bytes32 publicKey);
    error KeyNotActive(bytes32 publicKey);
    error KeyNotRevocable(bytes32 publicKey);
    error RenounceDisabled();

    modifier onlyIssuerAdmin(uint64 issuerId) {
        if (_issuers[issuerId].admin == address(0)) revert UnknownIssuer(issuerId);
        if (msg.sender != _issuers[issuerId].admin) revert NotIssuerAdmin(issuerId);
        _;
    }

    modifier known(uint64 issuerId) {
        if (_issuers[issuerId].admin == address(0)) revert UnknownIssuer(issuerId);
        _;
    }

    constructor(address owner_) Ownable(owner_) {}

    // ---- registry owner ----

    /// @notice Lists a new issuer. `ledger` may be zero and set later by the issuer's admin.
    function registerIssuer(address admin, string calldata name, string calldata did, address ledger)
        external
        onlyOwner
        returns (uint64 issuerId)
    {
        if (admin == address(0)) revert ZeroAddress();
        if (bytes(name).length == 0 || bytes(did).length == 0) revert EmptyText();
        issuerId = ++issuerCount;
        Issuer storage s = _issuers[issuerId];
        s.admin = admin;
        s.ledger = ledger;
        s.registeredAt = uint64(block.timestamp);
        s.name = name;
        s.did = did;
        emit IssuerRegistered(issuerId, admin, ledger, name, did);
    }

    /// @notice Corrects an issuer's displayed name or DID. Identity is the registry owner's call, not the issuer's.
    function setIssuerProfile(uint64 issuerId, string calldata name, string calldata did)
        external
        onlyOwner
        known(issuerId)
    {
        if (bytes(name).length == 0 || bytes(did).length == 0) revert EmptyText();
        _issuers[issuerId].name = name;
        _issuers[issuerId].did = did;
        emit IssuerProfileChanged(issuerId, name, did);
    }

    /// @notice Marks an issuer as no longer recognised. Its history stays readable.
    function suspendIssuer(uint64 issuerId, string calldata reason) external onlyOwner known(issuerId) {
        if (bytes(reason).length == 0) revert ReasonRequired();
        if (_issuers[issuerId].suspended) revert AlreadySuspended(issuerId);
        _issuers[issuerId].suspended = true;
        emit IssuerSuspended(issuerId, reason);
    }

    function reinstateIssuer(uint64 issuerId, string calldata reason) external onlyOwner known(issuerId) {
        if (bytes(reason).length == 0) revert ReasonRequired();
        if (!_issuers[issuerId].suspended) revert NotSuspended(issuerId);
        _issuers[issuerId].suspended = false;
        emit IssuerReinstated(issuerId, reason);
    }

    /// @dev Giving up ownership would leave nobody able to list or suspend issuers.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }

    // ---- issuer admin ----

    /// @notice First half of moving the admin role to a new key; the new key must call `acceptIssuerAdmin`.
    /// Passing the zero address cancels a transfer that has not been accepted.
    function transferIssuerAdmin(uint64 issuerId, address proposed) external onlyIssuerAdmin(issuerId) {
        _issuers[issuerId].pendingAdmin = proposed;
        emit IssuerAdminTransferStarted(issuerId, msg.sender, proposed);
    }

    function acceptIssuerAdmin(uint64 issuerId) external known(issuerId) {
        Issuer storage s = _issuers[issuerId];
        if (msg.sender != s.pendingAdmin) revert NotPendingAdmin(issuerId);
        emit IssuerAdminChanged(issuerId, s.admin, msg.sender);
        s.admin = msg.sender;
        s.pendingAdmin = address(0);
    }

    function setLedger(uint64 issuerId, address ledger) external onlyIssuerAdmin(issuerId) {
        if (ledger == address(0)) revert ZeroAddress();
        emit LedgerChanged(issuerId, _issuers[issuerId].ledger, ledger);
        _issuers[issuerId].ledger = ledger;
    }

    /// @notice Registers an Ed25519 public key as the active key of a stage. A stage has one active key at
    /// a time (as in the backend), so the previous one must be retired or revoked first.
    function addKey(uint64 issuerId, bytes32 publicKey, Stage stage) external onlyIssuerAdmin(issuerId) {
        if (publicKey == bytes32(0)) revert ZeroKey();
        if (_keys[issuerId][publicKey].status != KeyStatus.None) revert KeyExists(publicKey);
        bytes32 current = activeKey[issuerId][stage];
        if (current != bytes32(0)) revert StageHasActiveKey(stage, current);
        _keys[issuerId][publicKey] = Key(KeyStatus.Active, stage, uint64(block.timestamp), 0, 0);
        activeKey[issuerId][stage] = publicKey;
        emit KeyAdded(issuerId, publicKey, stage);
    }

    /// @notice Marks an active key as replaced. Signatures it already made stay trusted.
    function retireKey(uint64 issuerId, bytes32 publicKey) external onlyIssuerAdmin(issuerId) {
        Key storage k = _keys[issuerId][publicKey];
        if (k.status != KeyStatus.Active) revert KeyNotActive(publicKey);
        k.status = KeyStatus.Retired;
        k.retiredAt = uint64(block.timestamp);
        delete activeKey[issuerId][k.stage];
        emit KeyRetired(issuerId, publicKey);
    }

    /// @notice Marks an active or retired key as compromised. Nothing it signed is trusted any more. Final.
    function revokeKey(uint64 issuerId, bytes32 publicKey, string calldata reason)
        external
        onlyIssuerAdmin(issuerId)
    {
        if (bytes(reason).length == 0) revert ReasonRequired();
        Key storage k = _keys[issuerId][publicKey];
        if (k.status != KeyStatus.Active && k.status != KeyStatus.Retired) revert KeyNotRevocable(publicKey);
        if (k.status == KeyStatus.Active) delete activeKey[issuerId][k.stage];
        k.status = KeyStatus.Revoked;
        k.revokedAt = uint64(block.timestamp);
        emit KeyRevoked(issuerId, publicKey, reason);
    }

    // ---- anyone ----

    function issuer(uint64 issuerId) external view known(issuerId) returns (Issuer memory) {
        return _issuers[issuerId];
    }

    /// @notice A key's record (`status` is `None` if this issuer never registered it).
    function keyInfo(uint64 issuerId, bytes32 publicKey) external view returns (Key memory) {
        return _keys[issuerId][publicKey];
    }

    /// @notice True if a signature by this key should be accepted for this issuer: the issuer is listed and
    /// not suspended, and the key is active or retired (not revoked, not unknown).
    function isKeyTrusted(uint64 issuerId, bytes32 publicKey) external view returns (bool) {
        Issuer storage s = _issuers[issuerId];
        if (s.admin == address(0) || s.suspended) return false;
        KeyStatus st = _keys[issuerId][publicKey].status;
        return st == KeyStatus.Active || st == KeyStatus.Retired;
    }
}
