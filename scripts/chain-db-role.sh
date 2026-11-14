#!/usr/bin/env bash
# Creates (or resets) the database role of the optional on-chain worker, acvs-chain.
# Usage: scripts/chain-db-role.sh          (CHAIN_DB_PASSWORD from the environment or .env; stack must be up)
#
# The worker gets its own login, not the backend's, so that a bug or a break-in there cannot damage the
# ledger. The role may:
#   read    blocks; the public columns of signing_keys (never private_key_enc); and, of credentials, only
#           id, status, block_height, leaf_index and credential_hash (no name, no student id)
#   insert  into its own tables: chain_anchors, chain_revocations, chain_incidents
# and nothing else: no UPDATE or DELETE anywhere, no other table.
#
# Safe to run again: it sets the password and re-applies exactly these grants. Run it again after
# scripts/restore.sh on a new host (roles live in the server, not in the backup).
#   COMPOSE_FILE   e.g. docker-compose.prod.yml:deploy/chain.yml for the production stack
set -euo pipefail
cd "$(dirname "$0")/.."

PW=${CHAIN_DB_PASSWORD:-$(grep -s '^CHAIN_DB_PASSWORD=' .env | cut -d= -f2- || true)}
[ ${#PW} -ge 16 ] || { echo "CHAIN_DB_PASSWORD must be set (in the environment or .env) and at least 16 characters; scripts/chain-setup.sh creates one" >&2; exit 1; }
[[ "$PW" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "CHAIN_DB_PASSWORD may only contain letters, digits, '.', '_' and '-' (it is used inside a connection URL)" >&2; exit 1; }

docker compose exec -T postgres psql -U acvs -d acvs -q -v ON_ERROR_STOP=1 -v pw="$PW" <<'SQL'
SELECT to_regclass('public.chain_anchors') IS NOT NULL AS ready \gset
\if :ready
\else
  \echo 'the chain tables do not exist yet: start the backend once so it applies migration 0010'
  \quit 3
\endif

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'acvs_chain') THEN CREATE ROLE acvs_chain; END IF;
END $$;
ALTER ROLE acvs_chain WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'pw';

-- Start from nothing, then grant exactly what the worker needs.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM acvs_chain;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM acvs_chain;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM acvs_chain;
REVOKE ALL ON SCHEMA public FROM acvs_chain;

GRANT CONNECT ON DATABASE acvs TO acvs_chain;
GRANT USAGE ON SCHEMA public TO acvs_chain;
GRANT SELECT ON blocks TO acvs_chain;
GRANT SELECT (id, role, public_key, status) ON signing_keys TO acvs_chain;
GRANT SELECT (id, status, block_height, leaf_index, credential_hash) ON credentials TO acvs_chain;
GRANT SELECT, INSERT ON chain_anchors, chain_revocations, chain_incidents TO acvs_chain;
GRANT USAGE ON SEQUENCE chain_incidents_id_seq TO acvs_chain;
SQL
echo "role acvs_chain is ready (read: blocks, public key columns, credential positions; insert: chain_* tables)"
