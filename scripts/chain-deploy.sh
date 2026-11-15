#!/usr/bin/env bash
# Deploys the two smart contracts of the optional on-chain layer and lists this university in the registry.
#
# Usage: ISSUER_ADMIN=0x... ISSUER_NAME="Example University" ISSUER_DID="did:web:credentials.example.edu" \
#          scripts/chain-deploy.sh [--yes] [--write-env] [--verify]
#
#   ISSUER_ADMIN   address of the offline issuer admin key (from `acvs-chain admin-init`). The key itself
#                  is NOT needed here and should stay unplugged.
#   --yes          do not ask before sending (a deployment cannot be undone)
#   --write-env    add CHAIN_ANCHOR_CONTRACT, CHAIN_REGISTRY_CONTRACT and CHAIN_ISSUER_ID to .env afterwards
#   --verify       also publish the contracts' source on Sourcify, so anyone can read what was deployed
#
# From the environment or .env: CHAIN_RPC_URL (or CHAIN_DEPLOY_RPC_URL, if this computer reaches the node
# under another address than the containers do), CHAIN_ID, CHAIN_KEYSTORE_PASSPHRASE.
#
# The transactions are signed by the ANCHORER key (deploy/chain/anchorer-keystore.json, made by
# scripts/chain-setup.sh). It needs funds anyway, so no third key is involved. It owns the registry only
# long enough to list the issuer, then offers ownership to ISSUER_ADMIN, who takes it up with
#   acvs-chain plan accept-registry-ownership   and   acvs-chain admin-sign
# Needs Foundry (forge, cast). On a public network this is public and permanent.
set -euo pipefail
cd "$(dirname "$0")/.."

YES=; WRITE=; VERIFY=
for a in "$@"; do
  case "$a" in
    --yes) YES=1 ;; --write-env) WRITE=1 ;; --verify) VERIFY=1 ;;
    *) echo "usage: ISSUER_ADMIN=0x... ISSUER_NAME=... ISSUER_DID=... $0 [--yes] [--write-env] [--verify]" >&2; exit 2 ;;
  esac
done
for tool in forge cast; do command -v $tool >/dev/null || { echo "$tool not found: install Foundry (https://getfoundry.sh)" >&2; exit 2; }; done
[ -f contracts/lib/forge-std/src/Script.sol ] || { echo "run: git submodule update --init contracts/lib/forge-std contracts/lib/openzeppelin-contracts" >&2; exit 2; }

setting() { local v=${!1:-}; [ -n "$v" ] || v=$(grep -s "^$1=" .env | cut -d= -f2- | sed 's/[[:space:]]*#.*//' || true); echo "$v"; }
RPC=$(setting CHAIN_DEPLOY_RPC_URL); [ -n "$RPC" ] || RPC=$(setting CHAIN_RPC_URL)
ID=$(setting CHAIN_ID)
PASS=$(setting CHAIN_KEYSTORE_PASSPHRASE)
KS=${CHAIN_KEY_DIR:-deploy/chain}/anchorer-keystore.json
[ -n "$RPC" ] && [ -n "$ID" ] || { echo "CHAIN_RPC_URL and CHAIN_ID must be set (in the environment or .env)" >&2; exit 1; }
[ -f "$KS" ] && [ -n "$PASS" ] || { echo "the anchorer key is missing: run scripts/chain-setup.sh first" >&2; exit 1; }
KS=$(cd "$(dirname "$KS")" && pwd)/$(basename "$KS") # absolute: forge runs from contracts/
: "${ISSUER_NAME:?set ISSUER_NAME, for example \"Example University\"}" "${ISSUER_DID:?set ISSUER_DID, for example did:web:credentials.example.edu}"
[[ "${ISSUER_ADMIN:-}" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "ISSUER_ADMIN must be the admin key's address (0x and 40 hex digits), as printed by acvs-chain admin-init" >&2; exit 1; }
if [ -n "$WRITE" ] && grep -qs '^CHAIN_ANCHOR_CONTRACT=0x' .env; then
  echo ".env already names a CHAIN_ANCHOR_CONTRACT: a second deployment would start a second, empty ledger anchor. Remove that line first if this is what you want." >&2; exit 1
fi

# The passphrase goes to the tools in a private file, never on a command line.
PWFILE=$(mktemp); chmod 600 "$PWFILE"; trap 'rm -f "$PWFILE"' EXIT
printf '%s' "$PASS" > "$PWFILE"
ANCHORER=$(cast wallet address --keystore "$KS" --password-file "$PWFILE" 2>/dev/null) || { echo "cannot open $KS with CHAIN_KEYSTORE_PASSPHRASE" >&2; exit 1; }
[ "$(echo "$ANCHORER" | tr 'A-F' 'a-f')" != "$(echo "$ISSUER_ADMIN" | tr 'A-F' 'a-f')" ] || { echo "ISSUER_ADMIN is the anchorer's own address; the admin must be a different, offline key" >&2; exit 1; }
NODE_ID=$(cast chain-id -r "$RPC" 2>/dev/null) || { echo "the node at CHAIN_RPC_URL did not answer" >&2; exit 1; }
[ "$NODE_ID" = "$ID" ] || { echo "the node is chain $NODE_ID, but CHAIN_ID is $ID" >&2; exit 1; }
BALANCE=$(cast balance "$ANCHORER" -r "$RPC")
[ "$BALANCE" != 0 ] || { echo "the anchorer address $ANCHORER holds no funds on chain $ID, so it cannot pay for the deployment. Send it some of the network's currency (test ETH from a faucet on a test network)." >&2; exit 1; }

echo "About to deploy on chain $ID:"
echo "  issuer            $ISSUER_NAME ($ISSUER_DID)"
echo "  issuer admin      $ISSUER_ADMIN   (offline key; not used now)"
echo "  anchorer, payer   $ANCHORER   (balance $(cast from-wei "$BALANCE") ETH)"
if [ -z "$YES" ]; then
  [ -t 0 ] || { echo "not run from a terminal: add --yes to deploy without the question" >&2; exit 1; }
  read -r -p "This is public and cannot be undone. Deploy? [y/N] " answer
  [[ "$answer" =~ ^[yY]$ ]] || { echo "nothing was sent"; exit 0; }
fi

EXTRA=(); [ -n "$VERIFY" ] && EXTRA=(--verify --verifier sourcify)
OUT=$(cd contracts && ISSUER_ADMIN=$ISSUER_ADMIN ANCHORER=$ANCHORER ISSUER_NAME=$ISSUER_NAME ISSUER_DID=$ISSUER_DID \
  forge script script/Deploy.s.sol --rpc-url "$RPC" --keystore "$KS" --password-file "$PWFILE" --broadcast ${EXTRA[@]+"${EXTRA[@]}"} 2>&1) \
  || { echo "$OUT" | tail -15 >&2; echo "the deployment failed; see above" >&2; exit 1; }
REGISTRY=$(echo "$OUT" | grep 'IssuerRegistry  ' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
LEDGER=$(echo "$OUT" | grep 'LedgerAnchor  ' | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
ISSUER_ID=$(echo "$OUT" | grep 'issuer id  ' | grep -oE '[0-9]+$' | head -1)
[ -n "$REGISTRY" ] && [ -n "$LEDGER" ] && [ -n "$ISSUER_ID" ] || { echo "$OUT" | tail -15 >&2; echo "could not read the deployed addresses from forge's output" >&2; exit 1; }
# What the chain itself says, not what the tool printed.
[ "$(cast call "$LEDGER" 'anchorer()(address)' -r "$RPC" | tr 'A-F' 'a-f')" = "$(echo "$ANCHORER" | tr 'A-F' 'a-f')" ] \
  && [ "$(cast call "$LEDGER" 'owner()(address)' -r "$RPC" | tr 'A-F' 'a-f')" = "$(echo "$ISSUER_ADMIN" | tr 'A-F' 'a-f')" ] \
  || { echo "the deployed LedgerAnchor does not have the expected owner and anchorer; do not use it" >&2; exit 1; }

echo
echo "deployed on chain $ID:"
echo "CHAIN_ANCHOR_CONTRACT=$LEDGER"
echo "CHAIN_REGISTRY_CONTRACT=$REGISTRY"
echo "CHAIN_ISSUER_ID=$ISSUER_ID"
if [ -n "$WRITE" ]; then
  printf 'CHAIN_ANCHOR_CONTRACT=%s\nCHAIN_REGISTRY_CONTRACT=%s\nCHAIN_ISSUER_ID=%s\n' "$LEDGER" "$REGISTRY" "$ISSUER_ID" >> .env
  echo "(added to .env)"
else
  echo "(put these three lines in .env)"
fi
cat <<NEXT

Next:
  1. docker compose up -d && scripts/chain-db-role.sh
  2. docker compose -f docker-compose.yml -f deploy/chain.yml up -d        (the worker starts anchoring)
  3. with the admin drive plugged in (see chain/README.md):
       acvs-chain plan accept-registry-ownership > plan.json   and   acvs-chain admin-sign --keystore ... --plan plan.json
       docker compose -f docker-compose.yml -f deploy/chain.yml run --rm chain sync-keys > keys.json   and   admin-sign it
NEXT
