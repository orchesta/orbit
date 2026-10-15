#!/bin/bash
# Migrate the Orbit database from the PostgreSQL 16 volume (orbit-data) to the
# PostgreSQL 18 volume (orbit-pgdata) with pg_dump / psql.
# (pg_dumpall would replay CREATE ROLE/DATABASE for objects the new image already
# created and abort the restore; Orbit only uses the orbit_db database.)
#
# Usage: deploy/docker/upgrade-postgres.sh [--force] [--from=16|18] [LEGACY_VOLUME_NAME]
#
# Stop Orbit first and keep it stopped until the script finishes (its temporary
# containers are named orbit-pgup-*): run `bash run.sh` (it generates the secrets
# compose needs, then stops at the upgrade guard) and
# `docker compose -f deploy/docker/docker-compose.yml down`,
# or `docker stop` the old stack's containers.
# The old volume is never deleted or changed by the migration; only a temporary
# PostgreSQL server is started on it. A dump is kept under deploy/docker/backups/.
# --from picks the source when the old volume holds both a PostgreSQL 16 cluster
# and a PostgreSQL 18 one (18/docker, made by an earlier compose file).
set -euo pipefail

FORCE=0
FROM=
LEGACY_VOLUME=""
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --from=16|--from=18) FROM="${arg#--from=}" ;;
    -h|--help) sed -n '7,17p' "$0"; exit 0 ;;
    -*) echo "Unknown option: $arg" >&2; exit 2 ;;
    *) LEGACY_VOLUME="$arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="$SCRIPT_DIR/backups"
DB_USER=orbit
DB_NAME=orbit_db
DB_PASSWORD="${ORBIT_DATABASE_PASSWORD:-}"
if [ -z "$DB_PASSWORD" ] && [ -r "$SCRIPT_DIR/.env" ]; then
  DB_PASSWORD="$(sed -n 's/^ORBIT_DATABASE_PASSWORD=//p' "$SCRIPT_DIR/.env" | tail -n1)"
fi
DB_PASSWORD="${DB_PASSWORD:-orbit_secret}"

# default_project: the compose project name, as compose resolves it: the
# environment, then COMPOSE_PROJECT_NAME in .env, then "docker". Same lookup as run.sh.
default_project() {
  local p="${COMPOSE_PROJECT_NAME:-}"
  if [ -z "$p" ] && [ -r "$SCRIPT_DIR/.env" ]; then
    p="$(grep '^COMPOSE_PROJECT_NAME=' "$SCRIPT_DIR/.env" | tail -n1 | cut -d= -f2- | tr -d "\\r\"'" | sed 's/^ *//; s/ *$//' || true)"
  fi
  printf '%s\n' "${p:-docker}"
}

# Locate the legacy volume: label com.docker.compose.volume=orbit-data,
# preferring the compose project of this directory (default name "docker").
if [ -z "$LEGACY_VOLUME" ]; then
  PROJECT="$(default_project)"
  candidates="$(docker volume ls -q --filter label=com.docker.compose.volume=orbit-data)"
  if printf '%s\n' "$candidates" | grep -qx "${PROJECT}_orbit-data"; then
    LEGACY_VOLUME="${PROJECT}_orbit-data"
  else
    LEGACY_VOLUME="$(printf '%s\n' "$candidates" | head -n1)"
    if [ "$(printf '%s\n' "$candidates" | grep -c .)" -gt 1 ]; then
      echo "Several legacy volumes found; pass the one to migrate as an argument:" >&2
      printf '  %s\n' "$candidates" >&2
      exit 1
    fi
  fi
fi
if [ -z "$LEGACY_VOLUME" ] || ! docker volume inspect "$LEGACY_VOLUME" >/dev/null 2>&1; then
  echo "No legacy orbit-data volume found. Nothing to migrate." >&2
  exit 1
fi

# The new volume lives in the same compose project as the legacy one.
# A legacy volume without the project label falls back to the compose default.
PROJECT="$(docker volume inspect -f '{{ index .Labels "com.docker.compose.project" }}' "$LEGACY_VOLUME")"
if [ -z "$PROJECT" ] || [ "$PROJECT" = "<no value>" ]; then
  PROJECT="$(default_project)"
fi
NEW_VOLUME="${PROJECT}_orbit-pgdata"
MARKER=/var/lib/postgresql/.orbit-upgraded-from-16
echo "Legacy volume: $LEGACY_VOLUME"
echo "New volume (PostgreSQL 18): $NEW_VOLUME"

# Never start a second postmaster on a data directory that is in use.
for vol in "$LEGACY_VOLUME" "$NEW_VOLUME"; do
  if [ -n "$(docker ps -q --filter volume="$vol")" ]; then
    echo "Volume $vol is in use by a running container. Stop Orbit first:" >&2
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml down" >&2
    echo "If that fails on a missing ORBIT_* variable, run 'bash run.sh' once (it generates them and stops at the upgrade guard)," >&2
    echo "or stop the old stack's containers with 'docker stop'." >&2
    exit 1
  fi
done

# probe VOLUME TEST...: run a read-only shell test in a postgres:18-alpine
# container. Prints nothing; returns 0 (true) or 1 (false). Any other exit code
# (image pull failure, docker error) is fatal, so a failed probe never reads as
# "no cluster".
probe() {
  local vol="$1" rc=0
  shift
  docker run --rm --entrypoint sh -v "$vol":/v:ro postgres:18-alpine -c "$*" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "Probe on volume $vol failed (exit $rc); is Docker working and the image available?" >&2; exit 1 ;;
  esac
}

# Decide the source before anything is written to the legacy volume.
has16=0
has18=0
probe "$LEGACY_VOLUME" 'test -s /v/PG_VERSION' && has16=1
probe "$LEGACY_VOLUME" 'test -s /v/18/docker/PG_VERSION' && has18=1
SRC="$FROM"
if [ -z "$SRC" ]; then
  if [ "$has16" = 1 ] && [ "$has18" = 1 ]; then
    echo "$LEGACY_VOLUME holds both a PostgreSQL 16 cluster and a PostgreSQL 18 cluster (18/docker)." >&2
    echo "Check which one has your data, then re-run with --from=16 or --from=18." >&2
    exit 1
  elif [ "$has16" = 1 ]; then
    SRC=16
  elif [ "$has18" = 1 ]; then
    SRC=18
  else
    echo "No PostgreSQL cluster found in $LEGACY_VOLUME: nothing to migrate." >&2
    exit 1
  fi
fi
if { [ "$SRC" = 16 ] && [ "$has16" != 1 ]; } || { [ "$SRC" = 18 ] && [ "$has18" != 1 ]; }; then
  echo "--from=$SRC given, but $LEGACY_VOLUME has no PostgreSQL $SRC cluster." >&2
  exit 1
fi
echo "Source: PostgreSQL $SRC cluster in $LEGACY_VOLUME"

# Refuse to touch a new volume that already holds a cluster.
CREATED_NEW=0
if docker volume inspect "$NEW_VOLUME" >/dev/null 2>&1; then
  if probe "$NEW_VOLUME" 'test -s /v/18/docker/PG_VERSION' && [ "$FORCE" -ne 1 ]; then
    echo "$NEW_VOLUME already holds a PostgreSQL cluster. Re-run with --force to restore into it anyway." >&2
    exit 1
  fi
fi

# The temporary containers share the fixed prefix orbit-pgup-. Orbit itself must
# stay stopped for the whole run: the in-use check above only sees a stack that
# is already running, and a `docker compose up` started meanwhile would race the
# restore (the check before the marker below catches that).
SUFFIX="$$"
OLD_CT="orbit-pgup-old-$SUFFIX"
NEW_CT="orbit-pgup-new-$SUFFIX"
DONE=0
cleanup() {
  docker stop -t 30 "$OLD_CT" "$NEW_CT" >/dev/null 2>&1 || true
  docker rm -f "$OLD_CT" "$NEW_CT" >/dev/null 2>&1 || true
  # A volume this run created must not outlive a failed run: an empty one would
  # look like an initialised PostgreSQL 18 volume.
  if [ "$CREATED_NEW" = 1 ] && [ "$DONE" != 1 ]; then
    docker volume rm "$NEW_VOLUME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Create the new volume with the labels compose puts on it, so a later
# `docker compose up` adopts it without a warning.
if ! docker volume inspect "$NEW_VOLUME" >/dev/null 2>&1; then
  docker volume create \
    --label com.docker.compose.volume=orbit-pgdata \
    --label com.docker.compose.project="$PROJECT" \
    "$NEW_VOLUME" >/dev/null
  CREATED_NEW=1
fi

# wait_ready CONTAINER: wait until the server accepts TCP connections
# (the entrypoint's temporary init server only listens on the socket).
wait_ready() {
  local ct="$1"
  for _ in $(seq 1 60); do
    if docker exec "$ct" pg_isready -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $ct." >&2
  docker logs "$ct" >&2 || true
  return 1
}

echo "Starting temporary PostgreSQL $SRC on the old volume..."
if [ "$SRC" = 16 ]; then
  docker run -d --name "$OLD_CT" \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" \
    -v "$LEGACY_VOLUME":/var/lib/postgresql/data \
    postgres:16-alpine >/dev/null
else
  docker run -d --name "$OLD_CT" \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" \
    -v "$LEGACY_VOLUME":/var/lib/postgresql \
    postgres:18-alpine >/dev/null
fi
wait_ready "$OLD_CT"

mkdir -p "$BACKUP_DIR"
DUMP="$BACKUP_DIR/orbit-pg${SRC}-$(date +%Y%m%d-%H%M%S).sql"
echo "Dumping to $DUMP ..."
(
  umask 077
  docker exec -e PGPASSWORD="$DB_PASSWORD" "$OLD_CT" \
    pg_dump -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" --clean --if-exists > "$DUMP"
)
[ -s "$DUMP" ] || { echo "Dump is empty." >&2; exit 1; }

echo "Starting temporary PostgreSQL 18 on the new volume..."
docker run -d --name "$NEW_CT" \
  -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" \
  -v "$NEW_VOLUME":/var/lib/postgresql \
  postgres:18-alpine >/dev/null
wait_ready "$NEW_CT"

# A marker from an earlier run must not survive a restore that may fail halfway.
docker exec "$NEW_CT" rm -f "$MARKER"
echo "Restoring..."
docker exec -i -e PGPASSWORD="$DB_PASSWORD" "$NEW_CT" \
  psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -o /dev/null < "$DUMP"

# count CONTAINER TABLE: row count of TABLE in the orbit database
count() {
  docker exec -e PGPASSWORD="$DB_PASSWORD" "$1" \
    psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -tAc "SELECT count(*) FROM $2"
}
ok=1
for t in users repositories scan_results; do
  old="$(count "$OLD_CT" "$t")"
  new="$(count "$NEW_CT" "$t")"
  if [ "$old" = "$new" ]; then
    echo "  $t: $old rows (match)"
  else
    echo "  $t: old=$old new=$new (MISMATCH)" >&2
    ok=0
  fi
done
if [ "$ok" -ne 1 ]; then
  echo "Verification failed. The old volume was not deleted or changed; the dump is at $DUMP." >&2
  exit 1
fi

# Last check: anything besides this script's containers on the new volume means
# someone started the stack mid-migration. Abort without writing the marker.
ps_out="$(docker ps --filter volume="$NEW_VOLUME" --format '{{.Names}}')"
others="$(printf '%s\n' "$ps_out" | grep -vxF -e "$OLD_CT" -e "$NEW_CT" -e '' || true)"
if [ -n "$others" ]; then
  echo "Another container started using $NEW_VOLUME during the migration:" >&2
  printf '  %s\n' "$others" >&2
  echo "Stop it and re-run with --force. No upgrade marker was written." >&2
  exit 1
fi

# The marker tells run.sh this volume was filled by a finished migration.
docker exec "$NEW_CT" sh -c "echo from=$SRC > $MARKER"
DONE=1

cat <<EOF

Migration finished and verified. Dump kept at: $DUMP
Start Orbit with ./run.sh. The old volume was not deleted or changed.
After you have checked the data in the running app, remove it with:
  docker volume rm $LEGACY_VOLUME
EOF
