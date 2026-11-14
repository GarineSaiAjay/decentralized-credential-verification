#!/usr/bin/env bash
# Proves that the optional on-chain worker anchors sealed blocks to a smart contract, and that it cannot
# hurt the existing ledger while doing so.
# Usage: scripts/chain-test.sh        (needs Docker, and Foundry's forge and cast on the host)
#
# Runs a throwaway copy of the development stack ("acvschain") plus the worker (deploy/chain.yml) and a
# throwaway local chain (deploy/test-chain.yml). Nothing leaves this machine.
# It publishes the same ports as the main dev stack (and 8545), so stop that first: docker compose down
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }
for tool in forge cast docker python3; do
  command -v $tool >/dev/null || { echo "$tool not found (forge and cast come with Foundry: https://getfoundry.sh)" >&2; exit 2; }
done
[ -f contracts/lib/forge-std/src/Script.sol ] || { echo "run: git submodule update --init contracts/lib/forge-std contracts/lib/openzeppelin-contracts" >&2; exit 2; }

T=$(mktemp -d); chmod 755 "$T"; mkdir -p "$T/chain" "$T/backups"
# Every `docker compose` below, including the ones inside the scripts this test calls, means this stack.
export COMPOSE_PROJECT_NAME=acvschain
export COMPOSE_FILE=docker-compose.yml:deploy/chain.yml:deploy/test-chain.yml
export CHAIN_KEY_DIR="$T/chain" BACKUP_DIR="$T/backups"
export CHAIN_DB_PASSWORD=$(openssl rand -hex 16) CHAIN_KEYSTORE_PASSPHRASE=$(openssl rand -hex 24)
export CHAIN_RPC_URL=http://anvil:8545 CHAIN_ID=31337 CHAIN_EXPLORER_URL=https://explorer.test
export CHAIN_CONFIRMATIONS=2 CHAIN_INTERVAL_SECS=2 CHAIN_POLL_MS=300 CHAIN_RPC_TIMEOUT_SECS=3
unset BACKUP_PASSPHRASE CHAIN_ANCHOR_CONTRACT
dc() { docker compose "$@"; }
trap 'dc down -v >/dev/null 2>&1; rm -rf "$T"' EXIT

PASS=$(grep '^SEED_DEMO_PASSWORD=' .env | cut -d= -f2)
BASE=http://localhost:3000/api/v1
RPC=http://127.0.0.1:8545
KS="$T/chain/anchorer-keystore.json"
# Anvil's public test accounts: #0 deploys, #1 is the issuer admin. The node signs for them itself
# (--unlocked), so no private key appears in this repository.
DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
ADMIN=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
fails=0
ok() { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3' got '$2'"; fi; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
call() { # METHOD PATH [TOKEN] [BODY] -> sets CODE and BODY
  local args=(-s -o "$T/body" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json')
  [ -n "${3:-}" ] && args+=(-H "Authorization: Bearer $3")
  [ "$1" = POST ] && args+=(-H "X-Nonce: $(python3 -c 'import uuid; print(uuid.uuid4())')" -H "X-Timestamp: $(date +%s)")
  [ -n "${4:-}" ] && args+=(-d "$4")
  CODE=$(curl "${args[@]}"); BODY=$(cat "$T/body")
}
login() { call POST /auth/login "" "{\"email\":\"$1@university.edu\",\"password\":\"$PASS\"}"; echo "$BODY" | j "d['token']"; }
issue() { # takes a credential through all four stages and prints its id
  call POST /credentials "$FAC" '{"student_id":"S-1","student_name":"Ada Lovelace","program":"BSc","graduation_date":"2025-05-15"}'
  local id; id=$(echo "$BODY" | j "d['id']")
  for t in "$EXC" "$REG" "$ADM"; do call POST "/credentials/$id/approve" "$t"; done
  echo "$id"
}
seal() { call POST /ledger/seal "$ADM"; [ "$CODE" = 200 ] && echo "$BODY" | j "d['height']"; } # prints the new height
new_block() { LAST_ID=$(issue); LAST_H=$(seal); }
DB() { dc exec -T postgres psql -U acvs -d acvs -qAt -c "$1" 2>&1; }
AS_WORKER() { dc exec -T postgres psql -U acvs_chain -h 127.0.0.1 -d acvs -qAt -c "$1" 2>&1; }
receipts() { DB "SELECT count(*) FROM chain_anchors WHERE block_height = $1 AND contract = '$LOWER'"; }
wait_receipt() { for _ in $(seq 1 "$2"); do [ "$(receipts "$1")" = 1 ] && return 0; sleep 1; done; return 1; } # height seconds
incidents() { DB "SELECT count(*) FROM chain_incidents WHERE kind = '$1' AND block_height = $2"; }
wait_incident() { for _ in $(seq 1 "$3"); do [ "$(incidents "$1" "$2")" = 1 ] && return 0; sleep 1; done; return 1; }
nonce() { cast nonce "$ANCHORER" -r $RPC; }
next_height() { cast call "$LEDGER" 'nextHeight()(uint64)' -r $RPC; }
on_chain() { cast call "$LEDGER" 'anchorOf(uint64,uint64)((bytes32,bytes32,uint32,uint64,uint64))' "$1" "$2" -r $RPC | grep -oE '0x[0-9a-f]{64}' | head -1 | cut -c3-; } # epoch height -> block hash
db_hash() { DB "SELECT block_hash FROM blocks WHERE height = $1"; }
once() { dc run --rm --no-deps -T "$@" chain once 2>"$T/once.err"; } # one round of a second worker; prints its JSON report
# refused RUNNER SQL TEXT: true if running SQL through RUNNER (DB or AS_WORKER) is answered with TEXT.
# (Not a pipe into grep: with pipefail, psql's own failure would hide a match.)
refused() { local out; out=$("$1" "$2"); [[ "$out" == *"$3"* ]]; }
verdicts() { for id in "$@"; do call GET "/verify/$id"; echo "$BODY" | j "d['verdict']"; done | sort | uniq -c | tr -s ' \n' ' '; }

echo "== start (stack + local chain, no worker yet)"
dc build chain >/dev/null 2>&1 && ok "worker image builds" || { bad "worker image did not build"; exit 1; }
dc up -d --build --wait postgres backend frontend anvil >/dev/null 2>&1 && ok "stack and local chain healthy" || { bad "stack did not start"; exit 1; }
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)
[ -n "$FAC$EXC$REG$ADM" ] || { echo "login failed"; exit 1; }
# CHAIN_ID is set but there is no contract yet: a half-finished setup must not stop the backend.
LOGS=$(dc logs backend 2>&1)
[[ "$LOGS" == *'on-chain anchoring is not shown: CHAIN_ID and CHAIN_ANCHOR_CONTRACT must be set together'* ]] \
  && ok "the backend runs with a half-finished on-chain setting and says so" || bad "no warning about the half-set on-chain setting"

echo "== a ledger that exists before the on-chain layer is switched on"
IDS=()
for _ in 1 2 3; do IDS+=("$(issue)" "$(issue)"); seal >/dev/null; done
expect "three blocks sealed" "$(DB 'SELECT count(*) FROM blocks')" 3
expect "all credentials VALID" "$(verdicts "${IDS[@]}")" " 6 VALID "
call GET /ledger/verify; VERIFY_BEFORE=$(echo "$BODY" | j "[d['ok'], d['length'], [b['ok'] for b in d['blocks']]]")
expect "the chain tables exist and are empty (nothing writes them without the worker)" \
  "$(DB "SELECT (SELECT count(*) FROM chain_anchors) + (SELECT count(*) FROM chain_revocations) + (SELECT count(*) FROM chain_incidents)")" 0
call GET "/verify/${IDS[0]}"; VERIFY_OFF=$(echo "$BODY" | j "sorted(d['anchor'].keys())")
call GET /ledger/blocks "$ADM"; expect "nothing about a chain in the API while it is not set up" "$(echo "$BODY" | j "'onchain' in d or 'onchain' in d['blocks'][0]")" False
call GET /ledger/blocks/1/anchor; expect "and no receipt endpoint" "$CODE" 404
BLOCKS_BEFORE=$(DB "SELECT md5(string_agg(height || block_hash || signature || leaves::text, ',' ORDER BY height)) FROM blocks WHERE height <= 3")

echo "== set up the worker: key, contracts, database role"
ANCHORER=$(dc run --rm --no-deps -T --user "$(id -u):$(id -g)" -v "$T/chain:/out" chain keystore-new /out/anchorer-keystore.json 2>/dev/null | tr -d '\r')
[[ "$ANCHORER" =~ ^0x[0-9a-f]{40}$ ]] && ok "anchorer key created as an encrypted keystore ($ANCHORER)" || { bad "keystore-new: $ANCHORER"; exit 1; }
grep -q '"crypto"' "$KS" && ! grep -qi "$CHAIN_KEYSTORE_PASSPHRASE" "$KS" && ok "the keystore file is encrypted" || bad "keystore file looks wrong"
OUT=$(dc run --rm --no-deps -T --user "$(id -u):$(id -g)" -v "$T/chain:/out" chain keystore-new /out/anchorer-keystore.json 2>&1)
echo "$OUT" | grep -q 'refusing to overwrite' && ok "an existing key is never overwritten" || bad "overwrite not refused: $OUT"
chmod 644 "$KS"
cast rpc anvil_setBalance "$ANCHORER" 0x8AC7230489E80000 -r $RPC >/dev/null
OUT=$(cd contracts && ISSUER_ADMIN=$ADMIN ANCHORER=$ANCHORER ISSUER_NAME="Example University" ISSUER_DID="did:web:example.edu" \
  forge script script/Deploy.s.sol --rpc-url $RPC --unlocked --sender $DEPLOYER --broadcast 2>&1)
LEDGER=$(echo "$OUT" | grep 'LedgerAnchor  ' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
[ -n "$LEDGER" ] && ok "contracts deployed to the local chain (LedgerAnchor $LEDGER)" || { bad "deployment failed: $(echo "$OUT" | tail -5)"; exit 1; }
rm -rf contracts/broadcast contracts/cache/Deploy.s.sol
export CHAIN_ANCHOR_CONTRACT=$LEDGER
LOWER=$(echo "$LEDGER" | tr 'A-F' 'a-f')
scripts/chain-db-role.sh >/dev/null 2>&1 && ok "worker database role created" || bad "chain-db-role.sh failed"
scripts/chain-db-role.sh >/dev/null 2>&1 && ok "running the role script again is harmless" || bad "second run of chain-db-role.sh failed"
dc up -d --wait backend >/dev/null 2>&1 && ok "backend restarted with the contract address (display on)" || bad "backend did not restart"
call GET /ledger/blocks "$ADM"
expect "the API now reports every block as not anchored yet" "$(echo "$BODY" | j "[d['onchain']['unanchored'], sorted({b['onchain']['status'] for b in d['blocks']})]")" "[3, ['none']]"
call GET /ledger/verify; expect "which does not fail the ledger check" "$(echo "$BODY" | j "[d['ok'], d['blocks'][0]['onchain']]")" "[True, 'none']"

echo "== the worker refuses to start with wrong settings"
OUT=$(dc run --rm --no-deps -T chain check 2>&1); echo "$OUT" | grep -q '^ok' && ok "check passes with the right settings" || bad "check: $OUT"
OUT=$(dc run --rm --no-deps -T -e CHAIN_ID=11155111 chain check 2>&1); echo "$OUT" | grep -q 'is chain 31337, but CHAIN_ID is 11155111' && ok "wrong network refused" || bad "wrong chain id: $OUT"
OUT=$(dc run --rm --no-deps -T -e CHAIN_ANCHOR_CONTRACT=0x00000000000000000000000000000000000000AA chain check 2>&1); echo "$OUT" | grep -q 'there is no contract' && ok "an address with no contract refused" || bad "wrong contract: $OUT"
OUT=$(dc run --rm --no-deps -T -e CHAIN_KEYSTORE_PASSPHRASE=wrong-wrong-wrong-wrong chain check 2>&1); echo "$OUT" | grep -q 'cannot open the keystore' && ok "wrong keystore passphrase refused" || bad "wrong passphrase: $OUT"
echo "$OUT" | grep -q 'wrong-wrong' && bad "the passphrase was printed" || ok "the passphrase is not printed"
OUT=$(dc run --rm --no-deps -T -e CHAIN_DATABASE_URL=postgresql://acvs_chain:not-the-password@postgres:5432/acvs chain check 2>&1); echo "$OUT" | grep -qi 'password authentication failed' && ok "wrong database password refused" || bad "wrong db password: $OUT"
cast send "$LEDGER" 'setAnchorer(address)' $DEPLOYER --unlocked --from $ADMIN -r $RPC >/dev/null 2>&1
OUT=$(dc run --rm --no-deps -T chain check 2>&1); echo "$OUT" | grep -q "but the contract's anchorer is" && ok "a key that is not the anchorer refused" || bad "not anchorer: $OUT"
cast send "$LEDGER" 'setAnchorer(address)' "$ANCHORER" --unlocked --from $ADMIN -r $RPC >/dev/null 2>&1
expect "nothing was sent or written by any of that" "$(nonce)/$(DB 'SELECT count(*) FROM chain_anchors')" "0/0"

echo "== the worker's database role can read the ledger and nothing more"
expect "can read blocks" "$(AS_WORKER 'SELECT count(*) FROM blocks')" 3
expect "can read public keys" "$(AS_WORKER "SELECT count(*) > 0 FROM (SELECT id, role, public_key, status FROM signing_keys) k")" t
refused AS_WORKER 'SELECT private_key_enc FROM signing_keys' 'permission denied' && ok "cannot read the encrypted private keys" || bad "private keys readable"
refused AS_WORKER 'SELECT student_name FROM credentials' 'permission denied' && ok "cannot read student names" || bad "names readable"
refused AS_WORKER 'SELECT student_id FROM credentials' 'permission denied' && ok "cannot read student ids" || bad "student ids readable"
refused AS_WORKER 'SELECT count(*) FROM users' 'permission denied' && ok "cannot read users" || bad "users readable"
refused AS_WORKER 'SELECT count(*) FROM audit_logs' 'permission denied' && ok "cannot read the audit log" || bad "audit log readable"
refused AS_WORKER "UPDATE credentials SET status = 'revoked'" 'permission denied' && ok "cannot change a credential" || bad "credentials writable"
refused AS_WORKER "UPDATE blocks SET ts = 0" 'permission denied' && ok "cannot change a block" || bad "blocks writable"
refused AS_WORKER "INSERT INTO blocks SELECT * FROM blocks" 'permission denied' && ok "cannot add a block" || bad "blocks insertable"
refused AS_WORKER "DELETE FROM chain_anchors" 'permission denied' && ok "cannot delete its own receipts" || bad "receipts deletable"
refused AS_WORKER "CREATE TABLE x (i int)" 'permission denied' && ok "cannot create tables" || bad "can create tables"

echo "== catching up: the existing blocks are anchored, and nothing else changes"
dc up -d chain >/dev/null 2>&1
wait_receipt 3 40 && ok "blocks 1-3 anchored without any manual step" || { bad "blocks were not anchored"; dc logs --tail 20 chain; }
expect "one transaction covered all three" "$(DB "SELECT count(DISTINCT tx_hash) || '/' || count(*) FROM chain_anchors")" "1/3"
expect "the anchorer sent exactly one transaction" "$(nonce)" 1
for h in 1 2 3; do expect "the contract holds block $h's hash" "$(on_chain 1 $h)" "$(db_hash $h)"; done
expect "receipts match the blocks" "$(DB "SELECT count(*) FROM chain_anchors a JOIN blocks b ON b.height = a.block_height AND b.block_hash = a.block_hash AND b.merkle_root = a.merkle_root AND jsonb_array_length(b.leaves) = a.leaf_count")" 3
expect "the contract expects block 4 next" "$(next_height)" 4
expect "the existing blocks are byte-for-byte unchanged" "$(DB "SELECT md5(string_agg(height || block_hash || signature || leaves::text, ',' ORDER BY height)) FROM blocks WHERE height <= 3")" "$BLOCKS_BEFORE"
expect "every credential keeps its verdict" "$(verdicts "${IDS[@]}")" " 6 VALID "
call GET /ledger/verify; expect "the ledger check gives the same answer as before" "$(echo "$BODY" | j "[d['ok'], d['length'], [b['ok'] for b in d['blocks']]]")" "$VERIFY_BEFORE"

echo "== the API and the pages show the anchors"
expect "the ledger check reports each block's anchor" "$(echo "$BODY" | j "[b['onchain'] for b in d['blocks']]")" "['ok', 'ok', 'ok']"
call GET /ledger/blocks "$ADM"
expect "the block list shows them anchored, none waiting, no incident" "$(echo "$BODY" | j "[d['onchain']['unanchored'], d['onchain']['open_incidents'], sorted({b['onchain']['status'] for b in d['blocks']})]")" "[0, [], ['ok']]"
expect "and names the contract" "$(echo "$BODY" | j "d['onchain']['contract']")" "$LOWER"
call GET "/verify/${IDS[0]}"
expect "a credential's public verification shows its anchor" "$(echo "$BODY" | j "[d['verdict'], d['anchor']['onchain']['status'], d['anchor']['onchain']['chain_id'], d['anchor']['onchain']['epoch']]")" "['VALID', 'ok', 31337, 1]"
expect "and gains only that one field" "$(echo "$BODY" | j "sorted(k for k in d['anchor'].keys() if k != 'onchain')")" "$VERIFY_OFF"
call GET /ledger/blocks/2/anchor; expect "anyone can read a block's receipt" "$CODE" 200
TX=$(echo "$BODY" | j "d['tx_hash']")
expect "its transaction really is on the chain, sent to the contract" "$(cast tx "$TX" to -r $RPC | tr 'A-F' 'a-f')" "$LOWER"
expect "the receipt's values are what the contract holds" "$(echo "$BODY" | j "d['anchored']['block_hash']")" "$(on_chain 1 2)"
expect "it links to the explorer" "$(echo "$BODY" | j "d['explorer_url']")" "https://explorer.test/tx/$TX"
METRICS=$(dc exec -T backend curl -fsS http://localhost:9090/metrics)
expect "metrics: no block waiting, no mismatch, no incident" "$(echo "$METRICS" | grep -E '^acvs_onchain_(unanchored_blocks|mismatched_blocks|open_incidents) ' | awk '{print $2}' | tr '\n' ' ')" "0 0 0 "
if [ -d e2e/node_modules ]; then
  OUT=$(PASS=$PASS CRED=${IDS[0]} CHAIN_ID=31337 node e2e/chain-ui.mjs 2>&1); RC=$?
  echo "$OUT" | grep -E '^  (ok|FAIL)'
  [ $RC -eq 0 ] || fails=$((fails + $(echo "$OUT" | grep -c '^  FAIL') + ($(echo "$OUT" | grep -c '^  FAIL') == 0)))
elif [ -n "${CHAIN_TEST_UI:-}" ]; then
  bad "the browser check was required (CHAIN_TEST_UI) but e2e/node_modules is missing: run npm ci in e2e/"
else
  echo "  skip the browser check (run 'npm ci' in e2e/ to include it)"
fi
LOGS=$(dc logs chain backend 2>&1)
[[ "$LOGS" == *"$CHAIN_KEYSTORE_PASSPHRASE"* || "$LOGS" == *"$CHAIN_DB_PASSWORD"* ]] && bad "a secret appears in a log" || ok "no secret in the worker's or the backend's log"

echo "== anyone can check a credential against the chain alone"
call GET "/verify/${IDS[3]}"
HASH=0x$(echo "$BODY" | j "d['credential']['credential_hash']"); H=$(echo "$BODY" | j "d['anchor']['height']"); IDX=$(echo "$BODY" | j "d['anchor']['leaf_index']")
PROOF=$(echo "$BODY" | j "'[' + ','.join('0x' + s['hash'] for s in d['anchor']['proof']) + ']'")
INC='verifyInclusion(uint64,uint64,uint32,bytes32,bytes32[])(bool)'
expect "the contract confirms the backend's Merkle proof" "$(cast call "$LEDGER" "$INC" 1 "$H" "$IDX" "$HASH" "$PROOF" -r $RPC)" true
expect "but not for a different credential hash" "$(cast call "$LEDGER" "$INC" 1 "$H" "$IDX" "0x$(printf 'ab%.0s' {1..32})" "$PROOF" -r $RPC)" false
expect "nor at another position" "$(cast call "$LEDGER" "$INC" 1 "$H" "$((1 - IDX))" "$HASH" "$PROOF" -r $RPC)" false

echo "== a newly sealed block is anchored by itself"
new_block; IDS+=("$LAST_ID")
wait_receipt "$LAST_H" 30 && ok "block $LAST_H anchored within seconds of sealing" || bad "block $LAST_H not anchored"
expect "the contract holds its hash" "$(on_chain 1 "$LAST_H")" "$(db_hash "$LAST_H")"
expect "one more transaction" "$(nonce)" 2
refused DB "UPDATE chain_anchors SET tx_hash = 'x' WHERE block_height = 1" 'append-only' && ok "receipts cannot be edited" || bad "receipt editable"
refused DB "DELETE FROM chain_anchors WHERE block_height = 1" 'append-only' && ok "receipts cannot be deleted" || bad "receipt deletable"

echo "== only one worker runs at a time"
once >/dev/null; RC=$?
expect "a second worker exits" "$RC" 2
grep -q 'another acvs-chain worker is already running' "$T/once.err" && ok "and says why" || bad "second worker: $(cat "$T/once.err")"

echo "== the chain is unreachable: sealing and verification carry on, anchoring catches up later"
dc pause anvil >/dev/null 2>&1
new_block; IDS+=("$LAST_ID")
expect "a block can still be sealed" "$LAST_H" 5
call GET "/verify/$LAST_ID"; expect "its credential is VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
sleep 8
expect "no receipt was invented meanwhile" "$(receipts 5)" 0
[ "$(dc ps --status running --services | grep -c '^chain$')" = 1 ] && ok "the worker is still running" || bad "the worker died"
dc unpause anvil >/dev/null 2>&1
wait_receipt 5 40 && ok "block 5 anchored once the chain is back" || bad "block 5 not anchored after the outage"

echo "== the worker dies between sending and recording: the next start records it, with no second transaction"
dc stop chain >/dev/null 2>&1
new_block; IDS+=("$LAST_ID")
N=$(DB "SELECT jsonb_array_length(leaves) FROM blocks WHERE height = $LAST_H")
cast send "$LEDGER" 'anchor(uint64,bytes32,bytes32,uint32)' "$LAST_H" "0x$(db_hash "$LAST_H")" "0x$(DB "SELECT merkle_root FROM blocks WHERE height = $LAST_H")" "$N" \
  --keystore "$KS" --password "$CHAIN_KEYSTORE_PASSPHRASE" -r $RPC >/dev/null 2>&1
SENT=$(nonce)
expect "(the transaction is on the chain, the receipt is not in the database)" "$(on_chain 1 "$LAST_H" | cut -c1-8)/$(receipts "$LAST_H")" "$(db_hash "$LAST_H" | cut -c1-8)/0"
dc up -d chain >/dev/null 2>&1
wait_receipt "$LAST_H" 30 && ok "the receipt is written on the next start" || bad "receipt for block $LAST_H missing"
expect "no second transaction was sent" "$(nonce)" "$SENT"
expect "the receipt names the original transaction" "$(DB "SELECT tx_hash FROM chain_anchors WHERE block_height = $LAST_H")" \
  "$(cast logs --from-block 0 --address "$LEDGER" 'Anchored(uint64 indexed,uint64 indexed,bytes32,bytes32,uint32)' 1 "$LAST_H" -r $RPC --json | j "d[0]['transactionHash']")"

echo "== the network fee is above the limit: nothing is sent"
dc stop chain >/dev/null 2>&1
new_block; IDS+=("$LAST_ID")
SENT=$(nonce)
OUT=$(once -e CHAIN_MAX_FEE_GWEI=0.000000001)
echo "$OUT" | j "d['waiting']" | grep -q 'above CHAIN_MAX_FEE_GWEI' && ok "the round reports it is waiting for a lower fee" || bad "fee cap: $OUT $(cat "$T/once.err")"
expect "nothing was sent and nothing recorded" "$(nonce)/$(receipts "$LAST_H")" "$SENT/0"
expect "the block is still listed as pending" "$(echo "$OUT" | j "d['pending']")" 1

echo "== a chain reorganisation removes the transaction before it is confirmed: no receipt is written"
sleep 6 # leave earlier transactions buried deeper than the reorganisation below
(once -e CHAIN_CONFIRMATIONS=8 -e CHAIN_TX_TIMEOUT_SECS=10 > "$T/reorg.out") &
for _ in $(seq 1 60); do [ "$(next_height)" = "$((LAST_H + 1))" ] && break; sleep 0.3; done
expect "(the transaction was mined)" "$(next_height)" "$((LAST_H + 1))"
expect "no receipt before the confirmations are in" "$(receipts "$LAST_H")" 0
cast rpc anvil_reorg 4 '[]' -r $RPC >/dev/null
expect "(the reorganisation removed it)" "$(next_height)" "$LAST_H"
wait
OUT=$(cat "$T/reorg.out")
echo "$OUT" | j "d['waiting']" | grep -q 'not confirmed yet' && ok "the round ends without claiming success" || bad "reorg: $OUT $(cat "$T/once.err")"
expect "still no receipt" "$(receipts "$LAST_H")" 0
dc up -d chain >/dev/null 2>&1
wait_receipt "$LAST_H" 40 && ok "the worker anchors the block again by itself" || bad "block $LAST_H not anchored after the reorganisation"
expect "and the contract holds it" "$(on_chain 1 "$LAST_H")" "$(db_hash "$LAST_H")"

echo "== backup and restore still work, also onto a new database server"
scripts/backup.sh >/dev/null 2>&1; BACKUP=$(ls "$T"/backups/acvs-*.dump | tail -1)
[ -s "$BACKUP" ] && ok "backup taken at block $LAST_H" || bad "no backup"
GRANTS=$(dc exec -T postgres pg_restore --list < "$BACKUP" | grep -c 'ACL.*chain_anchors')
[ "$GRANTS" -ge 1 ] && ok "(the backup carries the worker's grants, so the restore below has to cope with them)" || bad "no grants in the backup"
KEPT=$LAST_H
new_block; LOST_ID=$LAST_ID
wait_receipt "$LAST_H" 30 && ok "block $LAST_H sealed and anchored after the backup" || bad "block $LAST_H not anchored"
OLD_HASH=$(db_hash "$LAST_H")
dc stop chain backend >/dev/null 2>&1
# A new server has neither the database nor the worker's role.
dc exec -T postgres psql -U acvs -d postgres -q -c "DROP DATABASE acvs WITH (FORCE)" -c "DROP ROLE acvs_chain" >/dev/null 2>&1
expect "(the worker's role is gone)" "$(dc exec -T postgres psql -U acvs -d postgres -qAt -c "SELECT count(*) FROM pg_roles WHERE rolname = 'acvs_chain'")" 0
OUT=$(scripts/restore.sh "$BACKUP" 2>&1) && ok "the backup restores where the worker's role does not exist" || bad "restore failed: $(echo "$OUT" | tail -3)"
expect "the restored ledger has the blocks from the backup" "$(DB 'SELECT max(height) FROM blocks')" "$KEPT"
expect "and their receipts" "$(DB "SELECT count(*) FROM chain_anchors")" "$KEPT"
expect "credentials from before the backup are VALID" "$(verdicts "${IDS[@]}")" " ${#IDS[@]} VALID "
scripts/chain-db-role.sh >/dev/null 2>&1 && ok "the role script sets the worker up again" || bad "chain-db-role.sh after restore failed"
FAC=$(login faculty); EXC=$(login examcell); REG=$(login registrar); ADM=$(login admin)

echo "== the restored ledger no longer matches what was anchored: the worker stops and changes nothing"
new_block; IDS+=("$LAST_ID")
expect "a different block now stands at height $LAST_H" "$([ "$(db_hash "$LAST_H")" != "$OLD_HASH" ] && echo yes)" yes
SENT=$(nonce); NEW_HASH=$(db_hash "$LAST_H")
dc up -d chain >/dev/null 2>&1
wait_incident anchor_mismatch "$LAST_H" 30 && ok "the mismatch is recorded as an incident" || { bad "no incident"; dc logs --tail 20 chain; }
sleep 5
expect "recorded once, however often it is seen" "$(incidents anchor_mismatch "$LAST_H")" 1
expect "no receipt for the block" "$(receipts "$LAST_H")" 0
expect "nothing was sent" "$(nonce)" "$SENT"
expect "the contract still holds the earlier anchor" "$(on_chain 1 "$LAST_H")" "$OLD_HASH"
expect "the database block is untouched" "$(db_hash "$LAST_H")" "$NEW_HASH"
LOGS=$(dc logs chain 2>&1)
[[ "$LOGS" == *'ON-CHAIN INCIDENT'* ]] && ok "the worker's log says so loudly" || bad "no incident in the log"
call GET /ledger/blocks "$ADM"
expect "the ledger page's data reports the open incident" "$(echo "$BODY" | j "[(i['kind'], i['height']) for i in d['onchain']['open_incidents']]")" "[('anchor_mismatch', $LAST_H)]"
expect "metrics: one open incident" "$(dc exec -T backend curl -fsS http://localhost:9090/metrics | grep '^acvs_onchain_open_incidents ' | awk '{print $2}')" 1
call GET /ledger/verify; expect "the ledger itself still verifies (the incident is about anchoring)" "$(echo "$BODY" | j "d['ok']")" True
call GET "/verify/$LAST_ID"; expect "the credential in that block is still VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
MISMATCH_H=$LAST_H
new_block; IDS+=("$LAST_ID"); sleep 6
expect "later blocks are not anchored while the incident stands" "$(receipts "$LAST_H")" 0

echo "== the issuer admin starts a new epoch: anchoring resumes, history stays"
OUT=$(cast send "$LEDGER" 'startEpoch(uint64,string)' "$MISMATCH_H" "restored backup" --keystore "$KS" --password "$CHAIN_KEYSTORE_PASSPHRASE" -r $RPC 2>&1)
echo "$OUT" | grep -qi 'revert\|OwnableUnauthorizedAccount\|error' && ok "the worker's key cannot start an epoch" || bad "anchorer started an epoch: $OUT"
cast send "$LEDGER" 'startEpoch(uint64,string)' "$MISMATCH_H" "restored backup" --unlocked --from $ADMIN -r $RPC >/dev/null 2>&1
expect "the admin key can" "$(cast call "$LEDGER" 'epoch()(uint64)' -r $RPC)" 2
wait_receipt "$LAST_H" 40 && ok "blocks $MISMATCH_H and $LAST_H anchored in the new epoch" || { bad "not anchored after the new epoch"; dc logs --tail 20 chain; }
expect "the receipts name epoch 2" "$(DB "SELECT string_agg(epoch::text, ',' ORDER BY block_height) FROM chain_anchors WHERE block_height >= $MISMATCH_H")" "2,2"
expect "earlier receipts stay in epoch 1" "$(DB "SELECT count(*) FROM chain_anchors WHERE epoch = 1")" "$KEPT"
expect "the new anchor is the database block" "$(on_chain 2 "$MISMATCH_H")" "$NEW_HASH"
expect "the superseded anchor is still readable" "$(on_chain 1 "$MISMATCH_H")" "$OLD_HASH"
expect "the incident stays on record" "$(incidents anchor_mismatch "$MISMATCH_H")" 1
call GET /ledger/blocks "$ADM"
expect "but is no longer reported as open" "$(echo "$BODY" | j "[d['onchain']['open_incidents'], d['onchain']['unanchored']]")" "[[], 0]"
call GET "/ledger/blocks/$MISMATCH_H/anchor"; expect "the receipt shows the new epoch" "$(echo "$BODY" | j "[d['status'], d['epoch']]")" "['ok', 2]"
expect "all credentials VALID" "$(verdicts "${IDS[@]}")" " ${#IDS[@]} VALID "
call GET /ledger/verify; expect "the ledger verifies" "$(echo "$BODY" | j "d['ok']")" True

echo "== a block that fails the ledger's own checks is never anchored"
dc stop chain >/dev/null 2>&1
new_block
DB "ALTER TABLE blocks DISABLE TRIGGER USER; UPDATE blocks SET ts = ts + 1 WHERE height = $LAST_H; ALTER TABLE blocks ENABLE TRIGGER USER" >/dev/null
SENT=$(nonce)
OUT=$(once); RC=$?
expect "the round fails" "$RC" 1
expect "with a block_invalid incident" "$(echo "$OUT" | j "d['incidents'][0]['kind']")" block_invalid
echo "  info $(echo "$OUT" | j "d['incidents'][0]['detail']['reason']")"
expect "nothing was sent and nothing recorded" "$(nonce)/$(receipts "$LAST_H")" "$SENT/0"
expect "the incident is stored" "$(incidents block_invalid "$LAST_H")" 1

echo
[ $fails -eq 0 ] && echo "ALL ON-CHAIN CHECKS PASSED" || { echo "$fails CHECK(S) FAILED"; exit 1; }
