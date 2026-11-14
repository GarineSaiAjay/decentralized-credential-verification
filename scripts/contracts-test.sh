#!/usr/bin/env bash
# Checks the smart contracts of the on-chain layer (contracts/): formatting, a warning-free build, the tests,
# a dry run of the deployment script, and that the Merkle test vectors are what the backend's own code
# produces today.
# Usage: scripts/contracts-test.sh        (needs Foundry: forge; and cargo for the vector check)
# Nothing here touches the backend, the database or a real network.
set -euo pipefail
cd "$(dirname "$0")/../contracts"

command -v forge >/dev/null || { echo "forge not found: install Foundry (https://getfoundry.sh) and re-run" >&2; exit 2; }
[ -f lib/forge-std/src/Test.sol ] && [ -f lib/openzeppelin-contracts/contracts/access/Ownable2Step.sol ] || {
  echo "contract libraries are missing: run 'git submodule update --init contracts/lib/forge-std contracts/lib/openzeppelin-contracts'" >&2; exit 2; }

echo "== format"
forge fmt --check
echo "== build (warnings are errors)"
forge build --deny warnings
echo "== tests"
forge test
echo "== deployment script (dry run, no network)"
# Throw-away addresses; nothing is sent anywhere.
ISSUER_ADMIN=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 ANCHORER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC \
  ISSUER_NAME="Example University" ISSUER_DID="did:web:example.edu" \
  forge script script/Deploy.s.sol >/dev/null
echo "ok"
echo "== Merkle vectors match the backend's code"
(cd tools/merkle-vectors && cargo fmt --check)
cargo run --quiet --locked --manifest-path tools/merkle-vectors/Cargo.toml | diff -q - test/vectors/merkle.json >/dev/null || {
  echo "test/vectors/merkle.json is out of date: backend/src/crypto.rs produces different values." >&2
  echo "If the Merkle rules changed on purpose, src/AcvsMerkle.sol must change with them; then regenerate:" >&2
  echo "  (cd contracts && cargo run --manifest-path tools/merkle-vectors/Cargo.toml > test/vectors/merkle.json)" >&2
  exit 1; }
echo "ok"
echo
echo "ALL CONTRACT CHECKS PASSED"
