#!/usr/bin/env bash
set -euo pipefail

# FlowOps disaster-recovery drill: real backup -> real restore -> real verify.
#
# Builds the current image, boots a throwaway "primary" instance, seeds a
# unique marker runbook, triggers a real encrypted backup via the actual
# admin API, copies the backup out, decrypts it with the real
# SettingsCipher, restores it onto a completely separate throwaway
# instance on a fresh Docker volume, and asserts the marker runbook
# survived. Every step is a real HTTP call, real Docker operation, and
# real cryptographic round trip -- no mocks. The script's own exit code
# and printed assertions are the DR evidence; nothing here is simulated.
#
# Usage: tools/dr_drill.sh

cd "$(dirname "$0")/.."

RUN_ID="$$-$(date +%s)"
IMAGE_TAG="flowops-dr-drill:${RUN_ID}"
PRIMARY_CONTAINER="flowops-dr-primary-${RUN_ID}"
RESTORE_CONTAINER="flowops-dr-restore-${RUN_ID}"
PRIMARY_VOLUME="flowops-dr-primary-vol-${RUN_ID}"
RESTORE_VOLUME="flowops-dr-restore-vol-${RUN_ID}"
KEY="$(openssl rand -base64 32)"
WORKDIR="$(mktemp -d)"
PRIMARY_PORT=18100
RESTORE_PORT=18101
BOOT_PASSWORD='DrDrill!Primary2026'
MARKER="DR Drill Marker ${RUN_ID}"

cleanup() {
  echo "--- cleanup ---"
  docker rm -f "$PRIMARY_CONTAINER" "$RESTORE_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$PRIMARY_VOLUME" "$RESTORE_VOLUME" >/dev/null 2>&1 || true
  docker rmi "$IMAGE_TAG" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_for_health() {
  local port="$1" label="$2"
  echo "Waiting for ${label} health..."
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      curl -sf "http://127.0.0.1:${port}/health"; echo
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${label} never became healthy" >&2
  return 1
}

echo "=== 1. Building image from current source ==="
docker build -t "$IMAGE_TAG" . >/dev/null

echo "=== 2. Starting primary instance (fresh volume: ${PRIMARY_VOLUME}) ==="
docker volume create "$PRIMARY_VOLUME" >/dev/null
docker run -d --name "$PRIMARY_CONTAINER" \
  -p "${PRIMARY_PORT}:8080" \
  -e FLOWOPS_DB=/data/flowops.db \
  -e FLOWOPS_HOST=0.0.0.0 \
  -e FLOWOPS_PORT=8080 \
  -e FLOWOPS_BOOTSTRAP_PASSWORD="$BOOT_PASSWORD" \
  -e FLOWOPS_PREVIEW_TOKENS=true \
  -e FLOWOPS_SETTINGS_ENCRYPTION_KEY="$KEY" \
  -v "${PRIMARY_VOLUME}:/data" \
  "$IMAGE_TAG" >/dev/null
wait_for_health "$PRIMARY_PORT" primary

echo "=== 3. Seeding a unique marker runbook ==="
LOGIN=$(curl -s -c "$WORKDIR/cookies.txt" -X POST "http://127.0.0.1:${PRIMARY_PORT}/api/auth/login" \
  -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"${BOOT_PASSWORD}\"}")
CSRF=$(echo "$LOGIN" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['csrf_token'])")
curl -sf -b "$WORKDIR/cookies.txt" -X POST "http://127.0.0.1:${PRIMARY_PORT}/api/runbooks" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
  -d "{\"name\":\"${MARKER}\"}" >/dev/null
echo "Seeded: ${MARKER}"

echo "=== 4. Triggering a real backup via the admin API ==="
BACKUP=$(curl -sf -b "$WORKDIR/cookies.txt" -X POST "http://127.0.0.1:${PRIMARY_PORT}/api/admin/backups" \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d '{}')
FILENAME=$(echo "$BACKUP" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['filename'])")
echo "Backup created: ${FILENAME}"

echo "=== 5. Copying the backup file out of the primary container ==="
docker cp "${PRIMARY_CONTAINER}:/data/backups/${FILENAME}" "$WORKDIR/${FILENAME}"
BACKUP_SIZE=$(wc -c < "$WORKDIR/${FILENAME}" | tr -d ' ')
test "$BACKUP_SIZE" -gt 0
echo "Backup file: ${BACKUP_SIZE} bytes"

echo "=== 6. Confirming the backup is NOT a readable SQLite file (encrypted at rest) ==="
if python3 -c "import sqlite3; sqlite3.connect('$WORKDIR/${FILENAME}').execute('SELECT 1')" 2>/dev/null; then
  echo "FAIL: backup file opened as plain SQLite -- it is not actually encrypted" >&2
  exit 1
fi
echo "Confirmed: backup file does not open as SQLite."

echo "=== 7. Decrypting the backup with the real SettingsCipher ==="
python3 - "$WORKDIR/${FILENAME}" "$WORKDIR/restored-flowops.db" "$KEY" <<'PYEOF'
import sys
sys.path.insert(0, ".")
import server
encrypted_path, output_path, key = sys.argv[1], sys.argv[2], sys.argv[3]
cipher = server.SettingsCipher(key)
data = cipher.decrypt(open(encrypted_path, "rb").read())
open(output_path, "wb").write(data)
print(f"Decrypted {len(data)} bytes")
PYEOF

echo "=== 8. Confirming the decrypted file IS a valid SQLite database ==="
python3 -c "import sqlite3; c=sqlite3.connect('$WORKDIR/restored-flowops.db'); c.execute('SELECT 1'); print('Valid SQLite database confirmed')"

echo "=== 9. Standing up a SEPARATE restore instance on a fresh volume from the decrypted backup ==="
docker volume create "$RESTORE_VOLUME" >/dev/null
# The image's container user is uid 10001 / gid 999 (see Dockerfile); a
# plain alpine helper writes the copied-in file as root, which the
# non-root flowops process then can't open. Chown it to match.
docker run --rm -v "${RESTORE_VOLUME}:/data" -v "$WORKDIR:/seed:ro" alpine \
  sh -c "cp /seed/restored-flowops.db /data/flowops.db && chown -R 10001:999 /data"
docker run -d --name "$RESTORE_CONTAINER" \
  -p "${RESTORE_PORT}:8080" \
  -e FLOWOPS_DB=/data/flowops.db \
  -e FLOWOPS_HOST=0.0.0.0 \
  -e FLOWOPS_PORT=8080 \
  -e FLOWOPS_BOOTSTRAP_PASSWORD="$BOOT_PASSWORD" \
  -e FLOWOPS_PREVIEW_TOKENS=true \
  -e FLOWOPS_SETTINGS_ENCRYPTION_KEY="$KEY" \
  -v "${RESTORE_VOLUME}:/data" \
  "$IMAGE_TAG" >/dev/null
wait_for_health "$RESTORE_PORT" restore

echo "=== 10. Verifying the marker runbook survived the restore ==="
curl -s -c "$WORKDIR/restore-cookies.txt" -X POST "http://127.0.0.1:${RESTORE_PORT}/api/auth/login" \
  -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"${BOOT_PASSWORD}\"}" >/dev/null
RUNBOOKS=$(curl -sf -b "$WORKDIR/restore-cookies.txt" "http://127.0.0.1:${RESTORE_PORT}/api/runbooks")
python3 -c "
import json, sys
data = json.load(sys.stdin)
names = [r['name'] for r in data['data']]
marker = '''${MARKER}'''
if marker not in names:
    print(f'FAIL: marker runbook not found after restore. Found: {names}', file=sys.stderr)
    sys.exit(1)
print(f'PASS: marker runbook {marker!r} found in restored instance ({len(names)} runbooks total)')
" <<< "$RUNBOOKS"

echo ""
echo "=== DR DRILL PASSED ==="
echo "Backup file: ${FILENAME} (${BACKUP_SIZE} bytes, confirmed encrypted at rest)"
echo "Restore verified end-to-end against a fresh Docker volume and a separate container."
