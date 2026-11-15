# acvs-chain: the on-chain program

An optional, separate program that links the ACVS ledger to two smart contracts (see `contracts/`):
it anchors each sealed block to `LedgerAnchor`, publishes revocations there, and helps the issuer admin
keep the university's signing keys in `IssuerRegistry`. The backend runs exactly the same without it.

It is separate from the backend on purpose:

- The backend never talks to a chain and never holds a chain key.
- This program never signs a credential, and its database role cannot change the ledger.

## The two keys

| Key | Where | Can |
|---|---|---|
| **Anchorer** | `deploy/chain/anchorer-keystore.json`, encrypted, used by the worker | Anchor blocks; set revocation bits. Nothing else |
| **Issuer admin** | Offline, on a pen drive. **Never on this server** | Manage signing keys in the registry; replace the anchorer; start an epoch; hand the role to another key |

If the anchorer key leaks, the admin replaces it. Nothing already anchored can be changed by either key.

## What the worker does each round

**Anchoring.** For every sealed block with no receipt, lowest height first:

1. **Checks the block** the way the backend's own chain check does (Merkle root, block hash, link to the
   previous block, the university's signature). It compiles `backend/src/crypto.rs` unchanged for this.
2. **Reads the contract.** If the block is already there, it only writes the receipt.
3. **Otherwise sends one transaction**, waits for `CHAIN_CONFIRMATIONS`, reads the contract again, and
   writes a receipt for what the contract really holds.

**Revocations.** For every revoked credential in an anchored block with no revocation receipt:

1. **Checks the signed revocation record** as the backend does (signed by the university key, which has
   not itself been revoked, over this credential, reason and time).
2. **Reads the contract.** If the bit is already set, it finds the transaction and writes the receipt.
3. **Otherwise sets the bit** (one transaction for all that are new) and writes the receipts.

**Signing keys.** If a registry is configured, it compares `signing_keys` with the registry and notes how
many changes wait for the issuer admin. It cannot make them; the backend shows the note.

The contracts are the source of truth and a database row is only a receipt. There is no "in progress"
state, so a crash at any point is repaired by the next round.

## What the worker never does

- Anchor a block, or publish a revocation, that fails its checks.
- Overwrite an anchor or clear a revocation bit (the contract refuses), or change the ledger in the
  database (its role cannot).
- "Repair" a disagreement. If the contract holds something else for a height, it records an **incident**
  in `chain_incidents`, logs it, and stops anchoring and publishing until the issuer admin has decided
  what to do (normally a new epoch, after restoring an older backup).
- Send while the network fee is above `CHAIN_MAX_FEE_GWEI`.

## Set up

```bash
scripts/chain-setup.sh        # adds two secrets to .env; creates the anchorer key in deploy/chain/, prints its address
# create the admin key on the pen drive (below), deploy the contracts with both addresses
# (contracts/README.md), then in .env:
#   CHAIN_RPC_URL=...  CHAIN_ID=...  CHAIN_ANCHOR_CONTRACT=0x...  CHAIN_REGISTRY_CONTRACT=0x...  CHAIN_ISSUER_ID=1
docker compose up -d          # the backend applies the migrations that create the worker's tables
scripts/chain-db-role.sh      # creates the worker's restricted database role
docker compose -f docker-compose.yml -f deploy/chain.yml up -d
```

Both addresses need a little of the network's currency to pay for transactions (test ETH from a faucet
on a test network). To stop everything on-chain, stop the `chain` service; nothing else is affected, and
it catches up when started again.

## The issuer admin key, on a pen drive

The admin key is needed rarely: once after deployment, and when a signing key is rotated or revoked, the
anchorer is replaced, or an epoch is started. Between those moments the drive is unplugged.

These commands run on the computer the drive is plugged into. Build the program there once
(`cargo build --release` in `chain/`), or run it from the worker's image with the drive mounted.
They need `CHAIN_RPC_URL` and `CHAIN_ID`, no database.

**Create it (once)**

```bash
acvs-chain admin-init /Volumes/ACVS-ADMIN/admin-keystore.json     # prints the admin ADDRESS
# copy the file to a second drive kept somewhere else (or print it), then:
acvs-chain admin-check /Volumes/ACVS-ADMIN/admin-keystore.json /Volumes/BACKUP/admin-keystore.json
```

- The key is written straight into an encrypted keystore file on the drive. It is never printed and
  never touches the computer's disk.
- The passphrase is typed at a prompt (at least 20 characters; six random words are easy to type). It is
  never taken from the command line or the environment.
- The command refuses a path inside a git repository, and never overwrites a key.
- **A lost admin key cannot be recovered.** `admin-check` proves the backup copy opens and holds the same
  key before it is needed.

**Use it (each time)**

1. Make a plan. This needs no key and can be done on the server:

   ```bash
   docker compose -f docker-compose.yml -f deploy/chain.yml run --rm chain sync-keys > plan.json
   ```

   `sync-keys` compares ACVS's signing keys with the registry and writes down the changes. Other plans:

   | Command | For |
   |---|---|
   | `acvs-chain plan start-epoch HEIGHT "REASON"` | Continue anchoring from a height, after restoring an older backup |
   | `acvs-chain plan set-anchorer ADDRESS` | Replace the worker's key |
   | `acvs-chain plan transfer-admin ADDRESS` | Offer the admin role to another key |
   | `acvs-chain plan accept-admin` | Take up an offered admin role (signed by the new key) |
   | `acvs-chain plan accept-registry-ownership` | Take up ownership of the registry, offered at deployment |

2. Plug in the drive and sign:

   ```bash
   acvs-chain admin-sign --keystore /Volumes/ACVS-ADMIN/admin-keystore.json --plan plan.json
   ```

   It shows each change in plain words, names the registry entry, asks for the passphrase and a yes/no,
   then signs and sends. A step that is already done is skipped, so the same plan can be run again.

3. Unplug the drive.

**If the drive is lost or the passphrase may have leaked**

Use the backup copy to hand the role to a fresh key, which makes the old one useless:

```bash
acvs-chain admin-init /Volumes/NEW/admin-keystore.json                    # prints the new address
acvs-chain plan transfer-admin 0xNEW... > transfer.json
acvs-chain admin-sign --keystore /Volumes/BACKUP/admin-keystore.json --plan transfer.json
acvs-chain plan accept-admin > accept.json
acvs-chain admin-sign --keystore /Volumes/NEW/admin-keystore.json --plan accept.json
```

Nothing moves until the new key accepts, so a mistyped address cannot take the role.

**Limit.** This is weaker than a hardware wallet: while the drive is plugged in and the passphrase is
typed, malware on that computer could take the key. Keeping the drive unplugged the rest of the time
keeps that window small. For a real deployment use a hardware wallet or a multisig.

## Commands

| Command | Key | What it does |
|---|---|---|
| `acvs-chain run` | anchorer | Anchor blocks and publish revocations, now and every `CHAIN_INTERVAL_SECS` (the default) |
| `acvs-chain once` | anchorer | One round; prints a JSON report; exit code 1 if there is an incident |
| `acvs-chain check` | anchorer | Check the settings, the key, the network and the contract, then exit |
| `acvs-chain address` | anchorer | Print the address of the key in `CHAIN_KEYSTORE_FILE` |
| `acvs-chain keystore-new FILE` | | Create the anchorer key as an encrypted keystore file; print its address |
| `acvs-chain sync-keys` | none | Print the registry changes that bring it in step with ACVS, as a plan |
| `acvs-chain plan ...` | none | Print a plan for one admin action (table above) |
| `acvs-chain admin-init FILE` | | Create the admin key on the drive; print its address |
| `acvs-chain admin-check FILE...` | admin | Open each copy and confirm they hold the same key |
| `acvs-chain admin-sign --keystore FILE --plan FILE [--yes]` | admin | Show a plan, then sign and send it |

At start the worker refuses to run if the node is a different network than `CHAIN_ID`, if there is no
`LedgerAnchor` at `CHAIN_ANCHOR_CONTRACT`, or if its key is not that contract's anchorer.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_DATABASE_URL` | | Connection for the worker's own role, `acvs_chain` |
| `CHAIN_RPC_URL` | | JSON-RPC endpoint of the network. Only its host name is ever logged |
| `CHAIN_ID` | | The network's chain id (31337 for a local node, 11155111 for Sepolia) |
| `CHAIN_ANCHOR_CONTRACT` | | Address of the `LedgerAnchor` contract |
| `CHAIN_REGISTRY_CONTRACT`, `CHAIN_ISSUER_ID` | | Optional, together: the registry and this university's id in it |
| `CHAIN_KEYSTORE_FILE` | | The anchorer's encrypted keystore file |
| `CHAIN_KEYSTORE_PASSPHRASE` | | Opens that file |
| `CHAIN_CONFIRMATIONS` | 2 | Blocks that must follow a transaction before it counts as done |
| `CHAIN_INTERVAL_SECS` | 60 | Time between rounds |
| `CHAIN_MAX_FEE_GWEI` | 50 | Nothing is sent while the network asks for more than this |
| `CHAIN_TX_TIMEOUT_SECS` | 180 | How long to wait for confirmations before looking again |
| `CHAIN_RPC_TIMEOUT_SECS` | 20 | Longest wait for one answer from the node |
| `CHAIN_BATCH_SIZE` | 25 | Most blocks anchored by one transaction |
| `CHAIN_LOG_WINDOW` | 2000 | Most chain blocks searched by one event query (public nodes limit this) |

## What the backend shows

The backend never talks to the chain. With `deploy/chain.yml` it is given `CHAIN_ID`,
`CHAIN_ANCHOR_CONTRACT` and (optionally) `CHAIN_EXPLORER_URL`, and then shows what the worker recorded:

| Where | What |
|---|---|
| `GET /api/v1/verify/:id` | `anchor.onchain`: `status` (`none`, `ok`, `mismatch`) and, once anchored, chain, contract, epoch, transaction. For a revoked credential also `revocation`: whether it has been published |
| `GET /api/v1/ledger/blocks` | The same per block, plus an `onchain` summary: blocks waiting, revocations not yet published, key changes waiting for the admin, open incidents |
| `GET /api/v1/ledger/verify` | `onchain` per block. A receipt that names a different hash than its block fails the check |
| `GET /api/v1/ledger/blocks/:n/anchor` | Public: one block's receipt, with the values the contract must hold |
| Ledger and Verify pages | An "On-chain" column, notices for waiting key changes and incidents, and "On-chain anchor" / "On-chain revocation" lines, linked to the explorer when one is set |
| Metrics | `acvs_onchain_unanchored_blocks`, `_mismatched_blocks`, `_open_incidents`, `_unpublished_revocations`, `_key_changes_pending` |

With `CHAIN_REGISTRY_CONTRACT` and `CHAIN_ISSUER_ID` also set, exports carry what a verifier needs to
check a credential without this server (see `verifier/`):

| Where | What |
|---|---|
| `GET /api/v1/credentials/:id/export` | Gains an `evidence` entry once the block is anchored: chain, registry, issuer id, ledger, epoch, position and Merkle proof |
| `GET /api/v1/credentials/:id/export-full` | Signed-in staff only, audit-logged: the same file plus the student ID and the exact text the hash covers |
| `GET /.well-known/did.json` | The university's `did:web` document: its trusted signing keys, and where its anchors are |

A receipt never changes a credential's verdict. Without those settings none of these fields exist and
every response is exactly as it was before. A half-finished setting (for example `CHAIN_ID` without the
contract) is logged as a warning and treated as "off"; it never stops the backend.

## Things that lag, by design

- **A key revoked or rotated in ACVS is not in the registry until the admin signs.** Until then the
  standalone verifier still trusts the old state. The Ledger page and the
  `acvs_onchain_key_changes_pending` metric show it.
- **A revocation reaches the chain on the worker's next round**, and only for a credential whose block is
  anchored. The university's own verification page is always current.

## Backup and restore

- The worker's tables are part of the normal database backup.
- Roles are not part of a backup. After `scripts/restore.sh` on a new host, run `scripts/chain-db-role.sh`.
- Restoring a backup older than the newest anchored block means later blocks will differ from what was
  anchored. The worker reports an `anchor_mismatch` incident and stops. The issuer admin then signs
  `acvs-chain plan start-epoch HEIGHT "restored backup"`, and anchoring continues in a new epoch. The
  earlier anchors stay readable.

## Tests

```bash
(cd chain && cargo test)      # unit tests
scripts/chain-test.sh         # the whole flow against a local chain (needs Docker, forge and cast)
```
