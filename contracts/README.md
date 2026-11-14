# ACVS contracts

The smart contracts of the optional on-chain layer. Nothing else in the repository depends on this
directory: the backend runs the same with or without it.

| Contract | What it holds |
|---|---|
| `src/IssuerRegistry.sol` | The list of universities, and each one's Ed25519 signing keys with their status (active, retired, revoked) |
| `src/LedgerAnchor.sol` | For one university: the hash and Merkle root of every sealed ledger block, and one revocation bit per credential position |
| `src/AcvsMerkle.sol` | The ledger's Merkle rules, so inclusion can be checked on-chain |

**No personal data goes on-chain.** A credential hash covers the student's name and ID, so it is never
stored. Only block hashes, Merkle roots, public keys and positions (block height + leaf index) are.

## Who can do what

| Key | Where it lives | Can |
|---|---|---|
| Registry owner | Offline | List an issuer, correct its name or DID, suspend or reinstate it |
| Issuer admin | Offline | Add, retire and revoke that issuer's signing keys; set its ledger address; replace the anchorer; start an epoch |
| Anchorer | The worker (a hot key) | Anchor blocks and set revocation bits. Nothing else |

Ownership and the issuer admin role move in two steps (offer, then accept), so a mistyped address cannot
take them. Giving ownership up entirely is disabled.

## What cannot happen

- An anchored block height cannot be overwritten, and heights cannot be skipped.
- A revocation bit cannot be cleared.
- A key's status only moves forward; a retired or revoked key cannot become active again.
- If the ledger has to be re-anchored (for example after restoring an old database backup), the issuer admin
  starts a new **epoch** with a public reason. The earlier anchors stay readable forever.

## Run the checks

```bash
git submodule update --init contracts/lib/forge-std contracts/lib/openzeppelin-contracts
scripts/contracts-test.sh
```

This needs [Foundry](https://getfoundry.sh) and `cargo`. It checks formatting, builds with warnings as
errors, runs the tests, dry-runs the deployment script and confirms the Merkle vectors are current.

## Merkle vectors

`test/vectors/merkle.json` is written by `tools/merkle-vectors`, a small program that compiles the
backend's own `backend/src/crypto.rs` and prints the roots and proofs it produces for trees of many shapes.
The Solidity tests must reproduce every one. If the backend's Merkle rules ever change, the check fails
until the contract is changed to match.

## Deploy to a local node

```bash
anvil                                   # a local test chain, in another terminal
ISSUER_ADMIN=0x... ANCHORER=0x... ISSUER_NAME="Example University" ISSUER_DID="did:web:example.edu" \
  forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key 0x... --broadcast
```

The deployer's key is only used for deployment. It lists the issuer, then offers registry ownership to
`REGISTRY_OWNER` (default: the issuer admin), who must accept it.

## Dependencies

`lib/forge-std` (tests only) and `lib/openzeppelin-contracts` (`Ownable2Step`) are git submodules, pinned
to a release commit. The compiler version is fixed in `foundry.toml`.
