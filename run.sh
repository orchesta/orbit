#!/bin/bash

# Cleanup macOS metadata files that break Docker on external SSDs
echo "Cleaning up macOS metadata files (._* and .DS_Store)..."
find . -name "._*" -delete
find . -name ".DS_Store" -delete

# docker compose reads generated secrets from this file
ENV_FILE="deploy/docker/.env"

# ensure_secret NAME: put a random 32-byte hex value for NAME into $ENV_FILE
# unless a non-empty value is already there. Aborts instead of rewriting a
# file it cannot fully read, so an existing key is never lost.
ensure_secret() {
  local name="$1"
  if [ -e "$ENV_FILE" ] && { [ ! -r "$ENV_FILE" ] || [ ! -w "$ENV_FILE" ]; }; then
    echo "$ENV_FILE exists but is not readable and writable. Fix its permissions (it holds ORBIT_CRYPTO_ENCRYPTION_KEY; do not delete it)." >&2
    exit 1
  fi
  if [ -e "$ENV_FILE" ]; then
    local status=0
    grep -q "^${name}=..*" "$ENV_FILE" || status=$?
    if [ "$status" -eq 0 ]; then
      return
    fi
    # grep exits 1 for "no match"; anything above that is a read error.
    if [ "$status" -ge 2 ]; then
      echo "Failed to read $ENV_FILE." >&2
      exit 1
    fi
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate ${name}. Install it, or set ${name} in $ENV_FILE." >&2
    exit 1
  fi
  local value
  value="$(openssl rand -hex 32)"
  if [ -z "$value" ]; then
    echo "Failed to generate ${name}." >&2
    exit 1
  fi
  echo "Generating ${name} in $ENV_FILE..."
  if [ "$name" = "ORBIT_SETUP_TOKEN" ]; then
    echo "ℹ️  The first-run setup token is in $ENV_FILE (ORBIT_SETUP_TOKEN). You need it to create the first admin."
  fi
  (
    umask 077
    touch "$ENV_FILE" || exit 1
    # Drop any empty NAME= line, then make sure the file ends in a newline
    status=0
    grep -v "^${name}=\$" "$ENV_FILE" > "$ENV_FILE.tmp" || status=$?
    if [ "$status" -ge 2 ]; then
      rm -f "$ENV_FILE.tmp"
      echo "Failed to read $ENV_FILE." >&2
      exit 1
    fi
    mv "$ENV_FILE.tmp" "$ENV_FILE" || exit 1
    if [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ]; then
      echo >> "$ENV_FILE" || exit 1
    fi
    echo "${name}=${value}" >> "$ENV_FILE" || exit 1
  ) || exit 1
  chmod 600 "$ENV_FILE"
}

ensure_secret ORBIT_JWT_SECRET
ensure_secret ORBIT_CRYPTO_ENCRYPTION_KEY
ensure_secret ORBIT_SETUP_TOKEN

# PostgreSQL 18 uses its own volume (orbit-pgdata). If the old PostgreSQL 16
# volume (orbit-data) still holds data and the new volume has not been filled by
# upgrade-postgres.sh, starting now would create an empty database. Never
# migrate automatically.
# Compose also reads COMPOSE_PROJECT_NAME from deploy/docker/.env.
project="${COMPOSE_PROJECT_NAME:-}"
if [ -z "$project" ] && [ -r "$ENV_FILE" ]; then
  project="$(grep '^COMPOSE_PROJECT_NAME=' "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d "\\r\"'" | sed 's/^ *//; s/ *$//' || true)"
fi
project="${project:-docker}"
# probe VOLUME TEST: read-only shell test in a postgres:18-alpine container;
# returns 0 or 1, anything else aborts so a docker failure never reads as "absent".
probe() {
  local rc=0
  docker run --rm --entrypoint sh -v "$1":/v:ro postgres:18-alpine -c "$2" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
    *) echo "Could not inspect Docker volume $1 (exit $rc)." >&2; exit 1 ;;
  esac
}
legacy_vol="$(docker volume ls -q \
  --filter label=com.docker.compose.volume=orbit-data \
  --filter label=com.docker.compose.project="$project" | head -n1)"
if [ -n "$legacy_vol" ] && { probe "$legacy_vol" 'test -s /v/PG_VERSION' || probe "$legacy_vol" 'test -s /v/18/docker/PG_VERSION'; }; then
  new_vol="${project}_orbit-pgdata"
  migrated=0
  if docker volume inspect "$new_vol" >/dev/null 2>&1 \
    && probe "$new_vol" 'test -s /v/18/docker/PG_VERSION && test -e /v/.orbit-upgraded-from-16'; then
    migrated=1
  fi
  if [ "$migrated" -ne 1 ]; then
    echo "Found PostgreSQL data in the old volume ($legacy_vol) that has not been migrated to $new_vol." >&2
    echo "   Starting now would create an empty database. Stop Orbit and migrate first:" >&2
    echo "     docker compose -f deploy/docker/docker-compose.yml down" >&2
    echo "     deploy/docker/upgrade-postgres.sh" >&2
    exit 1
  fi
fi

# Build and start Orbit
echo "Starting Orbit..."
cd deploy/docker || exit 1
docker compose down
docker compose up --build
