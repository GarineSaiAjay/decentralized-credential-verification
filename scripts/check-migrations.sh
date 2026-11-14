#!/usr/bin/env bash
# Guards the released database migrations and the schema they produce.
#
#   1. Every file listed in backend/migrations.lock must be present and byte-for-byte unchanged. A released
#      migration is never edited: a change goes into a new, higher-numbered migration.
#   2. On a throwaway database: all migrations are applied, then every migration above the baseline version
#      is undone with its script in backend/migrations-down/. The resulting schema must equal
#      backend/schema-baseline.txt. This proves that later migrations are purely additive and that their
#      down scripts really return the schema to the baseline.
#
# Usage: scripts/check-migrations.sh            check both (needs psql; uses DATABASE_URL or starts Postgres in Docker)
#        scripts/check-migrations.sh --files    check 1 only (needs nothing)
#        scripts/check-migrations.sh --write    rewrite the baseline from migrations up to BASELINE_VERSION
#
# DATABASE_URL must point at a server on which this user may create databases (as for scripts/test.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

BASELINE_VERSION=9 # the schema of the release before the on-chain layer
LOCK=backend/migrations.lock
BASELINE=backend/schema-baseline.txt
MODE=${1:-}

echo "== released migrations are unchanged"
shasum -a 256 -c "$LOCK" --quiet || { echo "a released migration was edited or removed (see above); put the change in a new migration" >&2; exit 1; }
echo "ok: $(grep -c . "$LOCK") files match $LOCK"
[ "$MODE" = "--files" ] && exit 0

command -v psql >/dev/null || { echo "psql is required for the schema check" >&2; exit 2; }

NAME=acvs-schemadb-$$
if [ -z "${DATABASE_URL:-}" ]; then
  PORT=${TEST_DB_PORT:-55433}
  docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -p "$PORT:5432" postgres:16-alpine >/dev/null
  trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
  until docker exec "$NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
  sleep 2 # the server restarts once while it initialises
  DATABASE_URL=postgres://postgres:test@localhost:$PORT/postgres
fi

DB=acvs_schema_check_$$
ADMIN="psql -qAt -v ON_ERROR_STOP=1 $DATABASE_URL"
TARGET="${DATABASE_URL%/*}/$DB"
$ADMIN -c "CREATE DATABASE $DB"
cleanup() { $ADMIN -c "DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1 || true; docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

version() { basename "$1" | cut -d_ -f1 | sed 's/^0*//'; }
run() { psql -q -v ON_ERROR_STOP=1 -1 -f "$1" "$TARGET" >/dev/null; }

echo "== schema after applying every migration, then undoing those above $BASELINE_VERSION"
UP=0
for f in backend/migrations/*.sql; do
  [ "$MODE" = "--write" ] && [ "$(version "$f")" -gt "$BASELINE_VERSION" ] && continue
  run "$f"; UP=$((UP + 1))
done
DOWN=0
for f in $(ls backend/migrations/*.sql | sort -r); do
  v=$(version "$f")
  [ "$v" -gt "$BASELINE_VERSION" ] || continue
  [ "$MODE" = "--write" ] && continue
  d=$(ls backend/migrations-down/"$(printf %04d "$v")"_*.sql 2>/dev/null | head -1 || true)
  [ -n "$d" ] || { echo "migration $v has no script in backend/migrations-down/" >&2; exit 1; }
  run "$d"; DOWN=$((DOWN + 1))
done
echo "applied $UP migration(s), undid $DOWN"

SNAP=$(psql -q -v ON_ERROR_STOP=1 -f scripts/schema-snapshot.sql "$TARGET")
if [ "$MODE" = "--write" ]; then
  printf '%s\n' "$SNAP" > "$BASELINE"
  echo "wrote $BASELINE ($(wc -l < "$BASELINE" | tr -d ' ') lines)"
  exit 0
fi
if ! diff -u "$BASELINE" <(printf '%s\n' "$SNAP"); then
  echo "the schema differs from $BASELINE (see the diff above): an existing table was changed, or a down script is incomplete" >&2
  exit 1
fi
echo "ok: schema matches $BASELINE"
echo
echo "MIGRATION CHECKS PASSED"
