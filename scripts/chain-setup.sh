#!/usr/bin/env bash
# One-time preparation for the optional on-chain worker (acvs-chain). Does two things, both local:
#
#   1. adds CHAIN_DB_PASSWORD and CHAIN_KEYSTORE_PASSPHRASE (random) to .env, if they are not there yet;
#   2. creates the ANCHORER key as an encrypted keystore file in deploy/chain/ and prints its address.
#
# Usage: scripts/chain-setup.sh
#
# The anchorer is the worker's hot key. It can only anchor blocks and set revocation bits. It is NOT the
# issuer admin key, which is created separately and kept offline. Nothing is sent to any network here.
# Next: deploy the contracts with this address as ANCHORER (contracts/README.md), put CHAIN_RPC_URL,
# CHAIN_ID and CHAIN_ANCHOR_CONTRACT in .env, run scripts/chain-db-role.sh, then start the worker:
#   docker compose -f docker-compose.yml -f deploy/chain.yml up -d
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "run scripts/gen-env.sh first" >&2; exit 1; }

DIR=${CHAIN_KEY_DIR:-deploy/chain}
FILE=$DIR/anchorer-keystore.json

add() { grep -q "^$1=" .env || { printf '%s=%s\n' "$1" "$2" >> .env; echo "added $1 to .env"; }; }
grep -q '^CHAIN_DB_PASSWORD=\|^CHAIN_KEYSTORE_PASSPHRASE=' .env || printf '\n# On-chain worker (optional; see deploy/chain.yml)\n' >> .env
add CHAIN_DB_PASSWORD "$(openssl rand -hex 16)"
add CHAIN_KEYSTORE_PASSPHRASE "$(openssl rand -hex 24)"

if [ -e "$FILE" ]; then
  echo "$FILE already exists; keeping it"
else
  mkdir -p "$DIR"
  # The key is generated inside the worker's own image and written straight to the encrypted file.
  docker compose -f docker-compose.yml -f deploy/chain.yml run --rm --no-deps -T \
    --user "$(id -u):$(id -g)" -v "$PWD/$DIR:/out" chain keystore-new /out/anchorer-keystore.json
  # The file is encrypted under CHAIN_KEYSTORE_PASSPHRASE. It is made readable so that the worker's
  # unprivileged container user can open it; the passphrase in .env is what protects the key.
  chmod 644 "$FILE"
fi
echo "keystore: $FILE"
