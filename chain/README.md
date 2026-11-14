# acvs-chain: the on-chain worker

An optional, separate program that anchors each sealed ledger block to the `LedgerAnchor` smart contract
(see `contracts/`). The backend runs exactly the same without it.

It is separate from the backend on purpose:

- The backend never talks to a chain and never holds a chain key.
- The worker never signs a credential, and its database role cannot change the ledger.

## What it does each round

For every sealed block with no receipt, lowest height first:

1. **Checks the block** the way the backend's own chain check does (Merkle root, block hash, link to the
   previous block, the university's signature). It compiles `backend/src/crypto.rs` unchanged for this.
2. **Reads the contract.** If the block is already there, it only writes the receipt.
3. **Otherwise sends one transaction**, waits for `CHAIN_CONFIRMATIONS`, reads the contract again, and
   writes a receipt for what the contract really holds.

The contract is the source of truth and a database row is only a receipt. There is no "in progress" state,
so a crash at any point is repaired by the next round. Several pending blocks go in one transaction.

## What it never does

- Anchor a block that fails its checks.
- Overwrite an anchor (the contract refuses), or change a block in the database (its role cannot).
- "Repair" a disagreement. If the contract holds something else for a height, it records an **incident**
  in `chain_incidents`, logs it, and stops anchoring until the issuer admin has decided what to do
  (normally `startEpoch`, after restoring an older backup).
- Send while the network fee is above `CHAIN_MAX_FEE_GWEI`.

## Set up

```bash
scripts/chain-setup.sh        # adds two secrets to .env; creates the anchorer key in deploy/chain/, prints its address
# deploy the contracts with that address as ANCHORER (contracts/README.md), then in .env:
#   CHAIN_RPC_URL=...  CHAIN_ID=...  CHAIN_ANCHOR_CONTRACT=0x...
docker compose up -d          # the backend applies the migration that creates the worker's tables
scripts/chain-db-role.sh      # creates the worker's restricted database role
docker compose -f docker-compose.yml -f deploy/chain.yml up -d
```

The anchorer address needs a little of the network's currency to pay for transactions (test ETH from a
faucet on a test network).

To stop anchoring, stop the `chain` service. Nothing else is affected, and it catches up when started again.

## Commands

| Command | What it does |
|---|---|
| `acvs-chain run` | Anchor pending blocks now and every `CHAIN_INTERVAL_SECS` (the default) |
| `acvs-chain once` | One round; prints a JSON report; exit code 1 if there is an incident |
| `acvs-chain check` | Check the settings, the key, the network and the contract, then exit |
| `acvs-chain address` | Print the address of the key in `CHAIN_KEYSTORE_FILE` |
| `acvs-chain keystore-new FILE` | Create the anchorer key as an encrypted keystore file; print its address |

At start it refuses to run if the node is a different network than `CHAIN_ID`, if there is no
`LedgerAnchor` at `CHAIN_ANCHOR_CONTRACT`, or if its key is not that contract's anchorer.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_DATABASE_URL` | | Connection for the worker's own role, `acvs_chain` |
| `CHAIN_RPC_URL` | | JSON-RPC endpoint of the network. Only its host name is ever logged |
| `CHAIN_ID` | | The network's chain id (31337 for a local node, 11155111 for Sepolia) |
| `CHAIN_ANCHOR_CONTRACT` | | Address of the `LedgerAnchor` contract |
| `CHAIN_KEYSTORE_FILE` | | The anchorer's encrypted keystore file |
| `CHAIN_KEYSTORE_PASSPHRASE` | | Opens that file |
| `CHAIN_CONFIRMATIONS` | 2 | Blocks that must follow a transaction before its receipt is written |
| `CHAIN_INTERVAL_SECS` | 60 | Time between rounds |
| `CHAIN_MAX_FEE_GWEI` | 50 | Nothing is sent while the network asks for more than this |
| `CHAIN_TX_TIMEOUT_SECS` | 180 | How long to wait for confirmations before looking again next round |
| `CHAIN_RPC_TIMEOUT_SECS` | 20 | Longest wait for one answer from the node |
| `CHAIN_BATCH_SIZE` | 25 | Most blocks anchored by one transaction |

## The two keys

| Key | Where | Can |
|---|---|---|
| Anchorer | `deploy/chain/anchorer-keystore.json`, encrypted, used by this worker | Anchor blocks; set revocation bits |
| Issuer admin | Offline (a pen drive). **Never on this server** | Replace the anchorer; start an epoch; manage signing keys |

If the anchorer key leaks, the admin replaces it with `setAnchorer`. Nothing already anchored can be changed.

## Backup and restore

- `chain_anchors`, `chain_revocations` and `chain_incidents` are part of the normal database backup.
- Roles are not part of a backup. After `scripts/restore.sh` on a new host, run `scripts/chain-db-role.sh`.
- Restoring a backup older than the newest anchored block means later blocks will differ from what was
  anchored. The worker reports an `anchor_mismatch` incident and stops. The issuer admin then calls
  `startEpoch(height, reason)` on the contract, and anchoring continues in a new epoch. The earlier
  anchors stay readable.

## Tests

```bash
(cd chain && cargo test)      # unit tests
scripts/chain-test.sh         # the whole flow against a local chain (needs Docker, forge and cast)
```
