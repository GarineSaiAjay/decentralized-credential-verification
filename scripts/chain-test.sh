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
# Anvil's public test account #0 deploys; the node signs for it itself (--unlocked), so no private key
# appears in this repository. The issuer admin is a real key, created below on a stand-in for the pen drive.
DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
ADMIN_PASS=$(openssl rand -hex 16); NEW_PASS=$(openssl rand -hex 16)
mkdir -p "$T/drive" "$T/drive-copy" "$T/new-drive"
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
# The acvs-chain program with the temporary folder mounted at /t (the "pen drives" and the plans live there).
tool() { dc run --rm --no-deps -T --user "$(id -u):$(id -g)" -v "$T:/t" chain "$@"; }
# sign PASSPHRASE DRIVE PLAN: what the admin does with the drive plugged in. The passphrase goes in on
# standard input, never as an argument.
sign() { echo "$1" | tool admin-sign --keystore "/t/$2/admin-keystore.json" --plan "/t/$3" --yes 2>&1; }
# For the few steps where the test plays a party directly (not through the tools): Anvil signs for the address.
as_admin() { cast send "$@" --unlocked --from "$ADMIN" -r $RPC >/dev/null 2>&1; }
pending_keys() { call GET /ledger/blocks "$ADM"; echo "$BODY" | j "(d['onchain']['key_changes'] or {}).get('pending')"; }
wait_keys() { for _ in $(seq 1 "$2"); do [ "$(pending_keys)" = "$1" ] && return 0; sleep 1; done; return 1; } # count seconds
revocations() { DB "SELECT count(*) FROM chain_revocations WHERE credential_id = '$1' AND contract = '$LOWER'"; }
wait_revocation() { for _ in $(seq 1 "$2"); do [ "$(revocations "$1")" = 1 ] && return 0; sleep 1; done; return 1; }
is_revoked() { cast call "$LEDGER" 'isRevoked(uint64,uint64,uint32)(bool)' "$1" "$2" "$3" -r $RPC; } # epoch height leaf
position() { DB "SELECT block_height || ' ' || leaf_index FROM credentials WHERE id = '$1'"; }
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

ADMIN=$(echo "$ADMIN_PASS" | tool admin-init /t/drive/admin-keystore.json 2>/dev/null | tr -d '\r')
[[ "$ADMIN" =~ ^0x[0-9a-f]{40}$ ]] && [ "$ADMIN" != "$ANCHORER" ] && ok "issuer admin key created straight onto the drive ($ADMIN)" || { bad "admin-init: $ADMIN"; exit 1; }
grep -q '"crypto"' "$T/drive/admin-keystore.json" && ! grep -q "$ADMIN_PASS" "$T/drive/admin-keystore.json" && ok "it is an encrypted keystore file" || bad "admin keystore looks wrong"
OUT=$(echo "$ADMIN_PASS" | tool admin-init /t/drive/admin-keystore.json 2>&1); [[ "$OUT" == *'refusing to overwrite'* ]] && ok "an existing admin key is never overwritten" || bad "admin overwrite: $OUT"
OUT=$(echo "too short" | tool admin-init /t/drive-copy/weak.json 2>&1); [[ "$OUT" == *'at least 20 characters'* ]] && [ ! -e "$T/drive-copy/weak.json" ] && ok "a short passphrase is refused and nothing is written" || bad "weak passphrase: $OUT"
cp "$T/drive/admin-keystore.json" "$T/drive-copy/admin-keystore.json"
OUT=$(echo "$ADMIN_PASS" | tool admin-check /t/drive/admin-keystore.json /t/drive-copy/admin-keystore.json 2>&1); [[ "$OUT" == *'every copy opens and holds the same key'* ]] && ok "the backup copy is checked to hold the same key" || bad "admin-check: $OUT"
OUT=$(echo "not-the-passphrase-not-the-passphrase" | tool admin-check /t/drive/admin-keystore.json 2>&1); [[ "$OUT" == *'cannot open the keystore'* ]] && ok "a wrong passphrase does not open it" || bad "admin-check wrong passphrase: $OUT"
cast rpc anvil_setBalance "$ADMIN" 0x8AC7230489E80000 -r $RPC >/dev/null
cast rpc anvil_impersonateAccount "$ADMIN" -r $RPC >/dev/null
OUT=$(cd contracts && ISSUER_ADMIN=$ADMIN ANCHORER=$ANCHORER ISSUER_NAME="Example University" ISSUER_DID="did:web:localhost%3A3000" \
  forge script script/Deploy.s.sol --rpc-url $RPC --unlocked --sender $DEPLOYER --broadcast 2>&1)
LEDGER=$(echo "$OUT" | grep 'LedgerAnchor  ' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
[ -n "$LEDGER" ] && ok "contracts deployed to the local chain (LedgerAnchor $LEDGER)" || { bad "deployment failed: $(echo "$OUT" | tail -5)"; exit 1; }
rm -rf contracts/broadcast contracts/cache/Deploy.s.sol
REGISTRY=$(echo "$OUT" | grep 'IssuerRegistry  ' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
export CHAIN_ANCHOR_CONTRACT=$LEDGER CHAIN_REGISTRY_CONTRACT=$REGISTRY CHAIN_ISSUER_ID=1
LOWER=$(echo "$LEDGER" | tr 'A-F' 'a-f')
scripts/chain-db-role.sh >/dev/null 2>&1 && ok "worker database role created" || bad "chain-db-role.sh failed"
scripts/chain-db-role.sh >/dev/null 2>&1 && ok "running the role script again is harmless" || bad "second run of chain-db-role.sh failed"
tool plan accept-registry-ownership > "$T/p-registry.json" 2>/dev/null
OUT=$(sign "$ADMIN_PASS" drive p-registry.json); [[ "$OUT" == *'done in transaction'* ]] && ok "the admin takes up ownership of the registry with a signed plan" || bad "accept registry ownership: $OUT"
expect "the registry is now owned by the admin key" "$(cast call "$REGISTRY" 'owner()(address)' -r $RPC | tr 'A-F' 'a-f')" "$ADMIN"
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
tool plan set-anchorer $DEPLOYER > "$T/p-anchorer.json" 2>/dev/null
OUT=$(sign "$ADMIN_PASS" drive p-anchorer.json); [[ "$OUT" == *'done in transaction'* ]] && ok "the admin replaces the anchorer with a signed plan" || bad "set-anchorer: $OUT"
[[ "$OUT" == *"$ADMIN_PASS"* ]] && bad "the admin passphrase was printed" || ok "the admin passphrase is not printed"
OUT=$(dc run --rm --no-deps -T chain check 2>&1); echo "$OUT" | grep -q "but the contract's anchorer is" && ok "a key that is not the anchorer refused" || bad "not anchorer: $OUT"
tool plan set-anchorer "$ANCHORER" > "$T/p-anchorer.json" 2>/dev/null
sign "$ADMIN_PASS" drive p-anchorer.json >/dev/null
OUT=$(sign "$ADMIN_PASS" drive p-anchorer.json); [[ "$OUT" == *'already done'* && "$OUT" != *'done in transaction'* ]] && ok "signing the same plan again changes nothing" || bad "repeat plan: $OUT"
OUT=$(echo "$ADMIN_PASS" | tool admin-sign --keystore /t/chain/anchorer-keystore.json --plan /t/p-anchorer.json --yes 2>&1); [[ "$OUT" == *'cannot open the keystore'* ]] && ok "the worker's key file is not the admin key" || bad "anchorer keystore accepted: $OUT"
expect "nothing was sent or written by any of that" "$(nonce)/$(DB 'SELECT count(*) FROM chain_anchors')" "0/0"

echo "== the worker's database role can read the ledger and nothing more"
expect "can read blocks" "$(AS_WORKER 'SELECT count(*) FROM blocks')" 3
expect "can read public keys" "$(AS_WORKER "SELECT count(*) > 0 FROM (SELECT id, role, public_key, status FROM signing_keys) k")" t
refused AS_WORKER 'SELECT private_key_enc FROM signing_keys' 'permission denied' && ok "cannot read the encrypted private keys" || bad "private keys readable"
refused AS_WORKER 'SELECT student_name FROM credentials' 'permission denied' && ok "cannot read student names" || bad "names readable"
refused AS_WORKER 'SELECT student_id FROM credentials' 'permission denied' && ok "cannot read student ids" || bad "student ids readable"
expect "can read a signed revocation record" "$(AS_WORKER 'SELECT count(*) FROM (SELECT credential_id, kind, stage, reason, key_id, signature, ts, legacy FROM credential_events) e')" 0
refused AS_WORKER 'SELECT actor_id FROM credential_events' 'permission denied' && ok "but not who made it" || bad "actor readable"
refused AS_WORKER "UPDATE chain_sync_state SET key_changes_pending = 0" 'permission denied' && bad "cannot rewrite its own note" || ok "may rewrite its own note of pending key changes"
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

echo "== the university's signing keys reach the registry through a plan the admin signs"
REGISTRAR_KEY=0x$(DB "SELECT public_key FROM signing_keys WHERE role = 'registrar' AND status = 'active'")
trusted() { cast call "$REGISTRY" 'isKeyTrusted(uint64,bytes32)(bool)' 1 "$1" -r $RPC; }
key_status() { cast call "$REGISTRY" 'keyInfo(uint64,bytes32)((uint8,uint8,uint64,uint64,uint64))' 1 "$1" -r $RPC | grep -oE '^\([0-9]+' | tr -d '('; }
# The registry starts empty: the worker notices, and says what the admin has to sign.
wait_keys 4 40 && ok "the worker reports four signing keys missing from the registry" || bad "pending key changes: $(pending_keys)"
expect "metrics say the same" "$(dc exec -T backend curl -fsS http://localhost:9090/metrics | grep '^acvs_onchain_key_changes_pending ' | awk '{print $2}')" 4
tool sync-keys > "$T/p-keys.json" 2> "$T/sync.err"
expect "sync-keys writes them down as a plan, without any key" "$(j "[a['action'] + ':' + a['stage'] for a in d['actions']]" < "$T/p-keys.json")" "['add-key:faculty', 'add-key:exam_cell', 'add-key:registrar', 'add-key:university']"
grep -q 'List signing key .* as the active registrar key' "$T/sync.err" && ok "and says each one in plain words" || bad "sync-keys text: $(cat "$T/sync.err")"
expect "nothing is in the registry before the admin signs" "$(trusted "$REGISTRAR_KEY")" false
OUT=$(sign "not-the-passphrase-not-the-passphrase" drive p-keys.json); [[ "$OUT" == *'cannot open the keystore'* ]] && [ "$(trusted "$REGISTRAR_KEY")" = false ] && ok "a wrong passphrase signs nothing" || bad "wrong passphrase: $OUT"
OUT=$(echo "$ADMIN_PASS" | tool admin-sign --keystore /t/drive/admin-keystore.json --plan /t/p-keys.json 2>&1); [[ "$OUT" == *'add --yes'* ]] && [ "$(trusted "$REGISTRAR_KEY")" = false ] && ok "without a person to ask, it signs only when told to with --yes" || bad "no --yes: $OUT"
OUT=$(sign "$ADMIN_PASS" drive p-keys.json)
expect "the admin signs the plan: four transactions" "$(echo "$OUT" | grep -c 'done in transaction')" 4
[[ "$OUT" == *'Registry entry: Example University'* ]] && ok "it names the registry entry it is about to change" || bad "no registry entry line: $OUT"
expect "the university's keys are listed in the registry" "$(trusted "$REGISTRAR_KEY")" true
wait_keys 0 40 && ok "the worker reports nothing left to sign" || bad "pending key changes after signing: $(pending_keys)"
tool sync-keys > "$T/p-none.json" 2>/dev/null; expect "sync-keys agrees" "$(j "d['actions']" < "$T/p-none.json")" "[]"

# A credential of its own for the revocation checks (it is not counted among the VALID ones later).
new_block; REV_ID=$LAST_ID; REV_H=$LAST_H
wait_receipt "$REV_H" 30 && ok "(block $REV_H sealed and anchored)" || bad "block $REV_H not anchored"
V="$T/v"; mkdir -p "$V"
curl -s "$BASE/credentials/${IDS[0]}/export" > "$V/public.json"
expect "the full export needs a sign-in" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/credentials/${IDS[0]}/export-full")" 401
curl -s -H "Authorization: Bearer $REG" "$BASE/credentials/${IDS[0]}/export-full" > "$V/full.json"
curl -s -H "Authorization: Bearer $REG" "$BASE/credentials/$REV_ID/export-full" > "$V/to-be-revoked.json"
expect "the public export names the anchor and the registry" "$(j "[d['evidence'][0]['chainId'], d['evidence'][0]['ledger'], d['evidence'][0]['registry'], d['evidence'][0]['issuerId']]" < "$V/public.json")" "[31337, '$LOWER', '$(echo "$REGISTRY" | tr 'A-F' 'a-f')', 1]"
expect "and still leaves out the student ID" "$(grep -c 'S-1' "$V/public.json")" 0
expect "the full export carries it, with the text the hash covers" "$(j "[d['credentialSubject']['studentId'], __import__('hashlib').sha256(d['hashedContent'].encode()).hexdigest() == d['credentialHash']]" < "$V/full.json")" "['S-1', True]"
expect "the download is on the audit log" "$(DB "SELECT count(*) FROM audit_logs WHERE action = 'CREDENTIAL_EXPORTED_FULL'")" 2

echo "== a revocation in ACVS is published on the chain by itself"
SENT=$(nonce)
call POST "/credentials/$REV_ID/revoke" "$ADM" '{"reason":"issued in error"}'; expect "revoke the credential in ACVS" "$CODE" 200
wait_revocation "$REV_ID" 30 && ok "the worker publishes it without any manual step" || { bad "revocation not published"; dc logs --tail 20 chain; }
read -r RH RL <<< "$(position "$REV_ID")"
expect "the contract's revocation bit is set for that position" "$(is_revoked 1 "$RH" "$RL")" true
expect "and for no other position in the block" "$(is_revoked 1 "$RH" "$((RL + 1))" 2>&1 | grep -c true)" 0
expect "one transaction" "$(nonce)" "$((SENT + 1))"
TX=$(DB "SELECT tx_hash FROM chain_revocations WHERE credential_id = '$REV_ID'")
expect "the receipt names a real transaction to the contract" "$(cast tx "$TX" to -r $RPC | tr 'A-F' 'a-f')" "$LOWER"
call GET "/verify/$REV_ID"
expect "the verification page's data shows it as published" "$(echo "$BODY" | j "[d['verdict'], d['anchor']['onchain']['revocation']['published'], d['anchor']['onchain']['revocation']['tx_hash'] == '$TX']")" "['REVOKED', True, True]"
call GET /ledger/blocks "$ADM"; expect "no revocation is left unpublished" "$(echo "$BODY" | j "d['onchain']['unpublished_revocations']")" 0
refused DB "DELETE FROM chain_revocations" 'append-only' && ok "revocation receipts cannot be deleted" || bad "revocation receipt deletable"
sleep 4; expect "it is not sent again on later rounds" "$(nonce)" "$((SENT + 1))"

echo "== a key rotation in ACVS reaches the registry once the admin signs"
call POST /keys/registrar/rotate "$ADM"; expect "rotate the registrar key in ACVS" "$CODE" 200
NEW_REGISTRAR_KEY=0x$(DB "SELECT public_key FROM signing_keys WHERE role = 'registrar' AND status = 'active'")
wait_keys 2 40 && ok "the worker reports two changes waiting" || bad "pending key changes after rotation: $(pending_keys)"
call GET /ledger/blocks "$ADM"; echo "$BODY" | j "d['onchain']['key_changes']['changes']" | grep -q 'as replaced' && ok "the ledger page's data lists them in plain words" || bad "no change text"
tool sync-keys > "$T/p-rotate.json" 2>/dev/null
expect "the plan retires the old key, then lists the new one" "$(j "[a['action'] for a in d['actions']]" < "$T/p-rotate.json")" "['retire-key', 'add-key']"
OUT=$(sign "$ADMIN_PASS" drive p-rotate.json); expect "the admin signs: two transactions" "$(echo "$OUT" | grep -c 'done in transaction')" 2
expect "the old key is marked retired in the registry (2 = retired)" "$(key_status "$REGISTRAR_KEY")" 2
expect "what it signed is still trusted" "$(trusted "$REGISTRAR_KEY")" true
expect "the new key is the active one" "$(cast call "$REGISTRY" 'activeKey(uint64,uint8)(bytes32)' 1 2 -r $RPC)" "$NEW_REGISTRAR_KEY"
wait_keys 0 40 && ok "nothing is left to sign" || bad "pending key changes after rotation was signed: $(pending_keys)"

echo "== the verifier page, with the backend switched off"
DID=$(curl -s http://localhost:3000/.well-known/did.json)
expect "the site publishes its DID document: the four active keys and the replaced one" "$(echo "$DID" | j "[d['id'], len(d['verificationMethod']), sorted(m['acvsStatus'] for m in d['verificationMethod'])]")" "['did:web:localhost%3A3000', 5, ['active', 'active', 'active', 'active', 'retired']]"
cast call "$REGISTRY" 'issuer(uint64)((address,address,address,bool,uint64,string,string))' 1 -r $RPC | grep -q 'did:web:localhost%3A3000' && ok "which is the DID the registry lists" || bad "registry DID differs"
expect "the DID document lists the key the registry lists" "$(echo "$DID" | j "'${REGISTRAR_KEY#0x}' in [m['acvsPublicKeyHex'] for m in d['verificationMethod']]")" True
if [ -d e2e/node_modules ]; then
  # Tampered copies: each changes one thing a forger might.
  python3 - "$V" <<'PY'
import json, sys, copy
v = sys.argv[1]
full = json.load(open(f"{v}/full.json")); public = json.load(open(f"{v}/public.json"))
def save(name, d): json.dump(d, open(f"{v}/{name}.json", "w"))
d = copy.deepcopy(full); d["credentialSubject"]["studentName"] = "Someone Else"; save("changed-name", d)
d = copy.deepcopy(full); d["credentialSubject"]["studentName"] = "Someone Else"; d["hashedContent"] = d["hashedContent"].replace("Ada Lovelace", "Someone Else"); save("changed-name-and-content", d)
d = copy.deepcopy(full); p = d["proof"][2]; p["proofValue"] = ("0" if p["proofValue"][0] != "0" else "1") + p["proofValue"][1:]; save("changed-signature", d)
d = copy.deepcopy(full); d["evidence"][0]["leafIndex"] = 1 - d["evidence"][0]["leafIndex"]; save("other-position", d)
d = copy.deepcopy(full); d["evidence"][0]["ledger"] = d["evidence"][0]["registry"]; save("other-ledger", d)
d = copy.deepcopy(full); d["evidence"][0]["chainId"] = 1; save("other-network", d)
d = copy.deepcopy(full); del d["evidence"]; save("no-evidence", d)
d = copy.deepcopy(public); d["credentialSubject"]["studentName"] = "Someone Else"; save("public-changed-name", d)
PY
  node e2e/verifier.mjs forge "$V/full.json" "$V/forged-with-own-keys.json"
  dc stop backend frontend >/dev/null 2>&1
  expect "(the backend is stopped)" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/ledger/verify")" 000
  vcheck() { node e2e/verifier.mjs check "$PWD/verifier/index.html" "$@" > "$T/v.out" 2>&1; cat "$T/v.out"; fails=$((fails + $(grep -c '^  FAIL' "$T/v.out"))); }
  vcheck $RPC yes "$V/full.json=VALID" "$V/public.json=GENUINE RECORD, DETAILS NOT PROVEN" "$V/public-changed-name.json=GENUINE RECORD, DETAILS NOT PROVEN" \
    "$V/changed-name.json=INVALID=fields shown" "$V/changed-name-and-content.json=INVALID=fields shown" "$V/changed-signature.json=INVALID=Signature of the registrar" \
    "$V/forged-with-own-keys.json=INVALID=faculty key" "$V/other-position.json=INVALID=credential is in that block" "$V/other-ledger.json=INVALID=own ledger contract" \
    "$V/other-network.json=COULD NOT BE CHECKED" "$V/no-evidence.json=SIGNATURES ONLY" "$V/to-be-revoked.json=REVOKED=has not been revoked"
  echo "  -- a registry the person has not confirmed is never used"
  vcheck $RPC no "$V/full.json=NOT CHECKED=registry is one you trust" "$V/forged-with-own-keys.json=NOT CHECKED=registry is one you trust"
  echo "  -- the chain node cannot be reached"
  vcheck http://127.0.0.1:9 yes "$V/full.json=COULD NOT BE CHECKED"
  echo "  -- the registry owner suspends the issuer, then reinstates it"
  as_admin "$REGISTRY" 'suspendIssuer(uint64,string)' 1 "test"
  vcheck $RPC yes "$V/full.json=INVALID=issuer is listed"
  as_admin "$REGISTRY" 'reinstateIssuer(uint64,string)' 1 "test"
  echo "  -- the issuer admin revokes a signing key as compromised"
  as_admin "$REGISTRY" 'revokeKey(uint64,bytes32,string)' 1 "$REGISTRAR_KEY" "test"
  vcheck $RPC yes "$V/full.json=INVALID=registrar key"
  dc up -d --wait backend frontend >/dev/null 2>&1 && ok "backend started again" || bad "backend did not come back"
elif [ -n "${CHAIN_TEST_UI:-}" ]; then
  bad "the verifier check was required (CHAIN_TEST_UI) but e2e/node_modules is missing: run npm ci in e2e/"
else
  echo "  skip the verifier page check (run 'npm ci' in e2e/ to include it)"
fi

echo "== only one worker runs at a time"
once >/dev/null; RC=$?
expect "a second worker exits" "$RC" 2
grep -q 'another acvs-chain worker is already running' "$T/once.err" && ok "and says why" || bad "second worker: $(cat "$T/once.err")"

echo "== the chain is unreachable: sealing and verification carry on, anchoring catches up later"
dc pause anvil >/dev/null 2>&1
new_block; IDS+=("$LAST_ID")
[ -n "$LAST_H" ] && ok "a block can still be sealed (block $LAST_H)" || bad "sealing failed during the outage"
OUTAGE_H=$LAST_H
call GET "/verify/$LAST_ID"; expect "its credential is VALID" "$(echo "$BODY" | j "d['verdict']")" VALID
sleep 8
expect "no receipt was invented meanwhile" "$(receipts "$OUTAGE_H")" 0
[ "$(dc ps --status running --services | grep -c '^chain$')" = 1 ] && ok "the worker is still running" || bad "the worker died"
dc unpause anvil >/dev/null 2>&1
wait_receipt "$OUTAGE_H" 40 && ok "block $OUTAGE_H anchored once the chain is back" || bad "block $OUTAGE_H not anchored after the outage"

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

echo "== a revocation whose receipt was lost is recorded from the chain, not sent twice"
new_block; REV2_ID=$LAST_ID
wait_receipt "$LAST_H" 30 || bad "block $LAST_H not anchored"
dc stop chain >/dev/null 2>&1
call POST "/credentials/$REV2_ID/revoke" "$ADM" '{"reason":"issued in error"}'
read -r RH RL <<< "$(position "$REV2_ID")"
TX=$(cast send "$LEDGER" 'revoke(uint64,uint64,uint32)' 1 "$RH" "$RL" --keystore "$KS" --password "$CHAIN_KEYSTORE_PASSPHRASE" -r $RPC --json | j "d['transactionHash']")
SENT=$(nonce)
expect "(the bit is set on the chain, the receipt is not in the database)" "$(is_revoked 1 "$RH" "$RL")/$(revocations "$REV2_ID")" "true/0"
call GET /ledger/blocks "$ADM"; expect "the ledger page's data counts it as not yet published" "$(echo "$BODY" | j "d['onchain']['unpublished_revocations']")" 1
dc up -d chain >/dev/null 2>&1
wait_revocation "$REV2_ID" 30 && ok "the receipt is written on the next start" || { bad "revocation receipt missing"; dc logs --tail 20 chain; }
expect "no second transaction was sent" "$(nonce)" "$SENT"
expect "the receipt names the original transaction" "$(DB "SELECT tx_hash FROM chain_revocations WHERE credential_id = '$REV2_ID'")" "$TX"

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
tool plan start-epoch "$MISMATCH_H" "restored backup" > "$T/p-epoch.json" 2> "$T/plan.err"
grep -q "Start a new ledger epoch that anchors again from block $MISMATCH_H" "$T/plan.err" && ok "the plan says what it does in plain words" || bad "plan text: $(cat "$T/plan.err")"
OUT=$(sign "$ADMIN_PASS" drive p-epoch.json); [[ "$OUT" == *'done in transaction'* ]] && ok "the admin signs the new epoch from the drive" || bad "start-epoch: $OUT"
expect "the contract is in epoch 2" "$(cast call "$LEDGER" 'epoch()(uint64)' -r $RPC)" 2
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

echo "== the drive is lost: the backup copy moves the admin role to a new key"
NEW_ADMIN=$(echo "$NEW_PASS" | tool admin-init /t/new-drive/admin-keystore.json 2>/dev/null | tr -d '\r')
cast rpc anvil_setBalance "$NEW_ADMIN" 0x8AC7230489E80000 -r $RPC >/dev/null
tool plan transfer-admin "$NEW_ADMIN" > "$T/p-transfer.json" 2>/dev/null
OUT=$(sign "$ADMIN_PASS" drive-copy p-transfer.json); expect "the backup copy offers the role to the new key (ledger and registry)" "$(echo "$OUT" | grep -c 'done in transaction')" 2
expect "nothing moves until the new key accepts" "$(cast call "$LEDGER" 'owner()(address)' -r $RPC | tr 'A-F' 'a-f')" "$ADMIN"
tool plan accept-admin > "$T/p-accept.json" 2>/dev/null
OUT=$(sign "$ADMIN_PASS" drive p-accept.json); [[ "$OUT" == *'no admin role has been offered to this key'* ]] && ok "only the key it was offered to can accept" || bad "old key accepted: $OUT"
OUT=$(sign "$NEW_PASS" new-drive p-accept.json); expect "the new key accepts both" "$(echo "$OUT" | grep -c 'done in transaction')" 2
expect "the ledger contract is owned by the new key" "$(cast call "$LEDGER" 'owner()(address)' -r $RPC | tr 'A-F' 'a-f')" "$NEW_ADMIN"
cast call "$REGISTRY" 'issuer(uint64)((address,address,address,bool,uint64,string,string))' 1 -r $RPC | tr 'A-F' 'a-f' | grep -q "^($NEW_ADMIN" && ok "and so is the registry entry" || bad "registry admin did not move"
tool plan start-epoch 1 "the lost drive tries again" > "$T/p-old.json" 2>/dev/null
OUT=$(sign "$ADMIN_PASS" drive p-old.json); [[ "$OUT" == *'not the issuer admin'* ]] && ok "the lost key can no longer change anything" || bad "old key still works: $OUT"
expect "(the contract is still in epoch 2)" "$(cast call "$LEDGER" 'epoch()(uint64)' -r $RPC)" 2
tool plan start-epoch "$(next_height)" "a new admin key is in use" > "$T/p-new.json" 2>/dev/null
OUT=$(sign "$NEW_PASS" new-drive p-new.json); [[ "$OUT" == *'done in transaction'* ]] && [ "$(cast call "$LEDGER" 'epoch()(uint64)' -r $RPC)" = 3 ] && ok "the new key signs for the issuer from now on" || bad "new key cannot sign: $OUT"

echo "== a revocation whose signed record does not verify is not published"
dc stop chain >/dev/null 2>&1
call POST "/credentials/${IDS[0]}/revoke" "$ADM" '{"reason":"the real reason"}'; expect "(a credential is revoked)" "$CODE" 200
DB "ALTER TABLE credential_events DISABLE TRIGGER USER; UPDATE credential_events SET reason = 'edited afterwards' WHERE credential_id = '${IDS[0]}'; ALTER TABLE credential_events ENABLE TRIGGER USER" >/dev/null
read -r RH RL <<< "$(position "${IDS[0]}")"
SENT=$(nonce)
OUT=$(once); RC=$?
expect "the round reports a problem" "$RC" 1
expect "as a revocation_invalid incident" "$(echo "$OUT" | j "d['incidents'][0]['kind']")" revocation_invalid
echo "  info $(echo "$OUT" | j "d['incidents'][0]['detail']['reason']")"
expect "nothing was sent, the bit is not set, no receipt" "$(nonce)/$(is_revoked 1 "$RH" "$RL")/$(revocations "${IDS[0]}")" "$SENT/false/0"

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
