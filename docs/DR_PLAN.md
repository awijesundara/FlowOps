# FlowOps Disaster Recovery Plan

## Scope and objective

FlowOps runs as a single SQLite database file per deployment, backed up on
a schedule (`backup_loop()` in `server.py`) and on demand
(`POST /api/admin/backups`). This plan covers recovering that database
from a backup after data loss or a corrupted instance — it does not cover
regional failover (excluded from scope; see `PRODUCT_BACKLOG.md` Epic
4.6, which requires infrastructure in a second geographic region not
available on this single-LAN, 2-node MicroK8s deployment).

- **RPO (Recovery Point Objective):** bounded by the configured backup
  interval/schedule (`FLOWOPS_BACKUP_INTERVAL_MINUTES`, default in
  `server.py`) plus however long since the last successful backup.
- **RTO (Recovery Time Objective):** the time to build/pull the image,
  restore the decrypted backup into a fresh volume, and pass health
  checks — demonstrated at well under 2 minutes end-to-end for the
  automated drill below, on the current single-node instance size.

## Backup mechanism (already shipped, unchanged by this plan)

`backup_database()` takes a hot, consistent snapshot via SQLite's own
backup API, then encrypts it at rest with `SettingsCipher` (the same
authenticated AES-256-CTR cipher used for admin-managed integration
credentials) before writing `flowops-<timestamp>.db.enc` to the backups
directory. The plaintext intermediate is deleted immediately. Backups are
never stored unencrypted.

## Restore procedure (manual, production)

1. Identify the backup file to restore from (`GET /api/admin/backups`
   lists available backups with timestamps and sizes).
2. Retrieve the `.db.enc` file from the running instance's data volume
   (`kubectl cp` on MicroK8s, or `docker cp` for a Compose deployment).
3. Decrypt it with the instance's `FLOWOPS_SETTINGS_ENCRYPTION_KEY`:
   ```python
   import server
   cipher = server.SettingsCipher(key)
   data = cipher.decrypt(open("flowops-<ts>.db.enc", "rb").read())
   open("restored-flowops.db", "wb").write(data)
   ```
4. Verify the decrypted file opens as a valid SQLite database
   (`sqlite3 restored-flowops.db "SELECT 1"`) before trusting it.
5. Stop the target instance, replace its data file with the restored
   one, ensure file ownership matches the container's non-root user
   (uid 10001 / gid 999 — see `Dockerfile`), and restart.
6. Confirm `/health` and `/ready`, then spot-check known data through
   the UI or `GET /api/runbooks` before declaring recovery complete.

## Automated drill: `tools/dr_drill.sh`

Step 5 (file ownership under the container's non-root user) is exactly
the kind of restore-procedure detail that's easy to get wrong under
pressure during a real incident and impossible to verify just by reading
the backup code — so this plan includes a scripted drill that actually
exercises the whole path end to end, not just the backup half:

1. Builds the current image and boots a throwaway "primary" instance on
   a fresh Docker volume.
2. Seeds a unique marker runbook (proves this run's data, not stale data
   from a previous drill or the image itself).
3. Triggers a real backup through the actual admin API
   (`POST /api/admin/backups`), the same code path production uses.
4. Copies the resulting `.db.enc` file out of the container.
5. Confirms it does **not** open as a plain SQLite file (proves it's
   actually encrypted, not just renamed).
6. Decrypts it with the real `SettingsCipher.decrypt()`.
7. Confirms the decrypted file **does** open as a valid SQLite database.
8. Stands up a **separate** throwaway "restore" instance on a **separate**
   fresh Docker volume, seeded only with the decrypted backup file
   (chowned to the container's actual uid/gid — this is the step that
   silently fails if skipped, and did during this plan's own first run;
   see "Known failure mode" below).
9. Confirms the restore instance passes `/health`.
10. Logs in and confirms the marker runbook from step 2 is present in
    the restored instance's `GET /api/runbooks` response.
11. Tears everything down (containers, both volumes, the throwaway
    image) regardless of outcome.

The drill's own exit code and printed PASS/FAIL assertions at each step
are the DR evidence — not just "a script exists."

### Run it

```bash
tools/dr_drill.sh
```

Requires Docker and a real network path to build the image (no other
setup — the script creates and tears down everything else itself,
including a random-per-run encryption key, so it never touches any
real backup, volume, or credential).

### Verified run (2026-09-12)

```
=== 1. Building image from current source ===
=== 2. Starting primary instance (fresh volume: flowops-dr-primary-vol-67822-1789180326) ===
Waiting for primary health...
{"status":"ok","service":"flowops","version":"0.4.8"}
=== 3. Seeding a unique marker runbook ===
Seeded: DR Drill Marker 67822-1789180326
=== 4. Triggering a real backup via the admin API ===
Backup created: flowops-20260912T023209126724Z.db.enc
=== 5. Copying the backup file out of the primary container ===
Backup file: 420592 bytes
=== 6. Confirming the backup is NOT a readable SQLite file (encrypted at rest) ===
Confirmed: backup file does not open as SQLite.
=== 7. Decrypting the backup with the real SettingsCipher ===
Decrypted 315392 bytes
=== 8. Confirming the decrypted file IS a valid SQLite database ===
Valid SQLite database confirmed
=== 9. Standing up a SEPARATE restore instance on a fresh volume from the decrypted backup ===
Waiting for restore health...
{"status":"ok","service":"flowops","version":"0.4.8"}
=== 10. Verifying the marker runbook survived the restore ===
PASS: marker runbook 'DR Drill Marker 67822-1789180326' found in restored instance (2 runbooks total)

=== DR DRILL PASSED ===
Backup file: flowops-20260912T023209126724Z.db.enc (420592 bytes, confirmed encrypted at rest)
Restore verified end-to-end against a fresh Docker volume and a separate container.
```

Post-run cleanup confirmed: no leftover `flowops-dr-*` containers,
volumes, or images.

### Known failure mode found and fixed by this drill

The first run of this script failed at step 9: the restore instance
never became healthy. Root cause, found via direct debugging (not
guessed): the container image's Dockerfile runs the app as a non-root
user (`uid 10001, gid 999`), and `chown -R flowops:flowops /data` only
happens at **image build time** — a fresh named Docker volume gets its
initial ownership from the image path it's mounted over, but a plain
`alpine` helper container copying the decrypted database file *into*
that volume afterward creates the new file as **root**-owned, which the
non-root `flowops` process then cannot open. Fixed by explicitly
`chown -R 10001:999` after the copy, in the same helper step. This is
recorded here because it's exactly the kind of restore-procedure detail
that would be easy to get wrong during a real incident and impossible to
catch without actually running the restore, which is the entire point of
running this drill instead of only reading the backup code.

## Cadence

Run `tools/dr_drill.sh` after any change to `backup_database()`,
`SettingsCipher`, the Docker image's user/permission model, or the
backup file format/naming — and periodically (recommended: before each
phase/wave of work that touches persistence) as a regression check
against silent drift between the backup and restore paths.
