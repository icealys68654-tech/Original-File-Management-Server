# Cloud File Server — Native Node.js MVC (v1.4.2)

The native Node.js MVC runtime remains the only active web server. Flask is not imported or required. This release replaces the JSON metadata file with SQLite, imports existing v1.3.x metadata and CIS inventory when present, and keeps encrypted file bytes in the existing storage directory.

## Requirements and start

- Node.js 24.15.0 or newer (`node:sqlite` release-candidate API; no npm dependencies)
- No Python, Flask, npm package installation, or external database server is required to run the active web server

Windows PowerShell:

```powershell
cd mvc
node --version
node --test
$env:CIS_HOST = "127.0.0.1"
$env:CIS_PORT = "5080"
$env:CFS_ADMIN_EMAIL = "admin@example.com"
$env:CFS_ADMIN_PASSWORD = "replace-with-a-unique-password-of-16-or-more-characters"
node server.mjs
```

macOS/Linux:

```bash
cd mvc
node --test
CIS_HOST=127.0.0.1 CIS_PORT=5080 \
CFS_ADMIN_EMAIL=admin@example.com \
CFS_ADMIN_PASSWORD='replace-with-a-unique-password-of-16-or-more-characters' \
node server.mjs
```

Open http://127.0.0.1:5080. First startup bootstraps the configured administrator if no admin exists. Create ordinary accounts from the sign-in page. Use a secrets manager or protected environment file for credentials. `CFS_COOKIE_SECURE=1` enables the Secure cookie attribute when TLS is terminated in front of Node. For production, set `CFS_ENV=production`; startup then requires Secure cookies, a loopback bind, an administrator email and a 16+ character bootstrap password. Keep the server behind a properly configured TLS reverse proxy for network access.

## MVC architecture

- `server.mjs` — native Node HTTP router, cookie sessions, CSRF checks, request limits and static serving.
- `src/controllers/auth-controller.mjs` — registration, password verification, login sessions and bootstrap admin.
- `src/controllers/secure-file-controller.mjs` — ownership, file metadata, recipient permissions, envelope validation and storage.
- `src/models/database-model.mjs` — SQLite metadata persistence, schema/index setup, transactions and legacy JSON migration.
- `src/services/security-service.mjs` — scrypt password hashes, random session/CSRF tokens and email validation.
- `src/services/encryption-service.mjs` — reference V1 and multi-recipient V2 hybrid encryption.
- `src/controllers/host-controller.mjs` — SQLite host inventory and optional Nmap discovery.
- `src/registry.mjs` — SQLite-backed CIS configuration registry.
- `public/` — account, key, upload, file, sharing and audit UI; `/cis` remains the administrator-only CIS console.
- `test/` — Node built-in tests.

## Implemented in v1.4.2

- All v1.3.2 authentication, ownership, RSA envelope, permissions, audit and CIS dashboard functionality retained.
- SQLite schema v2 supports quarantined ownerless legacy metadata while retaining foreign keys, unique email constraints, lookup indexes, WAL mode, FULL synchronous writes and a 5-second busy timeout. Schema v1 is migrated transactionally.
- SQLite write transactions refresh state after acquiring the write lock, apply the change, and commit atomically. Reads use a consistent SQLite snapshot.
- Host inventory, CIS saved configurations and last Nmap output are persisted in SQLite instead of standalone JSON/text files.
- Encrypted blob byte length and SHA-256 checksum are checked before download; corrupted or truncated blobs are rejected.
- Legacy import for the v1.3.x JSON metadata file, `hosts.json`, CIS `registry.json`, and `last_scan.txt`; original legacy files are preserved. Unowned file metadata remains quarantined and is not listed to ordinary users.
- Existing encrypted file bytes remain in the existing storage directory; no re-encryption is performed during metadata migration.

## Encryption compatibility

The supplied reference dashboard uses `CFS-HYBRID-ENCRYPTED-V1\n` with one `wrapped_key`. Node retains V1 decryption support. Multi-recipient uploads use `CFS-HYBRID-ENCRYPTED-V2\n`, AES-256-GCM content encryption and one RSA-OAEP-SHA256 wrapped content key per selected recipient. Each envelope binds a recipient user ID to its SHA-256 SPKI fingerprint; the recipient list is authenticated as AES-GCM additional data. Python `secure_transfer.py` supports V1 and the authenticated recipient-list V2 format, plus backward decryption compatibility for the earlier v1.3.2 fingerprint-map V2 files.

## Configuration

- `CIS_HOST` (default `127.0.0.1`), `CIS_PORT` (default `5080`), `MAX_UPLOAD_MB` (default `50`), `MAX_CONCURRENT_UPLOADS` (default `2`, maximum `32`).
- `CFS_DB_PATH` (default `mvc/data/cfs.sqlite`), `CFS_STORAGE_PATH` (default project `storage/`), `CFS_AUDIT_PATH` (default project `audit.jsonl`).
- `CFS_LEGACY_JSON_PATH` (default `mvc/data/cfs-db.json`), `CFS_LEGACY_HOSTS_PATH` (default project `hosts.json`), `CFS_LEGACY_REGISTRY_PATH` (default `mvc/data/registry.json`), `CFS_LEGACY_SCAN_PATH` (default project `last_scan.txt`). Set these paths explicitly when migrating a customized v1.3.x deployment.
- `CFS_ADMIN_EMAIL`, `CFS_ADMIN_PASSWORD`, `CFS_COOKIE_SECURE`, `MAX_CONCURRENT_UPLOADS` (default 2).

## Migration from v1.3.2

1. Stop the old Node server and take a backup of the full project, including `mvc/data/cfs-db.json`, `storage/`, `audit.jsonl`, `hosts.json`, `mvc/data/registry.json` and `last_scan.txt` if present.
2. Extract v1.4.2 alongside the backup. Keep the existing `storage/` directory and audit log; do not overwrite them with empty directories.
3. Copy the legacy `mvc/data/cfs-db.json` and any legacy CIS inventory files into their corresponding paths, or set the `CFS_LEGACY_*_PATH` variables.
4. Start v1.4.2. On first access the server imports legacy metadata into `mvc/data/cfs.sqlite` and leaves the JSON/text source files untouched.
5. Verify account login, owner file listings, recipient access, audit history, host inventory and CIS registry before retiring the old copy.
6. Keep the original backup until restore has been tested. Do not run two application versions against the same storage directory at once.

The SQLite migration copies file metadata and ACLs only; encrypted file blobs are not rewritten. Files with missing owners remain quarantined. An administrator can preview them with `GET /api/admin/legacy-files` and assign ownership with `POST /api/admin/legacy-files/assign` using `{"assignments":[{"file_id":"32-hex-character-id","owner_id":"32-hex-character-user-id"}]}`. The API accepts only a registered owner key whose fingerprint has a matching RSA envelope in the encrypted V2 blob; it checks file integrity, rejects unsafe storage references, rechecks the assignment in the transaction, and audits the result. V1 blobs without a verifiable per-user envelope are deliberately not assignable through this workflow. Review the candidate and owner mapping out-of-band before applying it.

## Backups and restore preparation

Stop the server before backing up so the database, encrypted blobs and audit log represent one consistent point in time. From `mvc/`:

```powershell
$env:CFS_BACKUP_QUIESCED = "1"
$env:CFS_BACKUP_DIR = "D:\CFS-Backups\cfs-2026-11-25"
node scripts/backup.mjs
node scripts/verify-backup.mjs $env:CFS_BACKUP_DIR
```

macOS/Linux:

```bash
CFS_BACKUP_QUIESCED=1 CFS_BACKUP_DIR=/secure/backups/cfs-YYYY-MM-DD node scripts/backup.mjs
node scripts/verify-backup.mjs /secure/backups/cfs-YYYY-MM-DD
```

The backup contains the SQLite database, encrypted `storage/` tree, optional audit log, and a SHA-256 manifest. The tool refuses to run without the stopped-server acknowledgement and refuses symlinks. Store backups off-host with restricted access. Restore is an operator-controlled procedure. Use `node scripts/restore.mjs <backup> --target-root <empty-directory>` with `CFS_RESTORE_QUIESCED=1` and `CFS_RESTORE_CONFIRM=RESTORE`; the tool verifies hashes and rejects symlinks, unsafe paths and tampered content. A synthetic restore drill is included in the Node test suite; production-size RPO/RTO remains unmeasured.

## Runtime support

Node.js documents `node:sqlite` as a release-candidate API from Node 24.15.0 and Node 25.7.0 onward. This release sets Node 24.15.0 as its minimum runtime; the database API is not yet designated stable. See the [official Node.js SQLite documentation](https://nodejs.org/api/sqlite.html).

## Known limits and release boundary

**v1.4.2 is a release candidate, not production approved.** `node:sqlite` is a release-candidate API on the supported runtime, not yet stable. The current compatibility adapter rewrites the metadata snapshot inside each SQLite transaction; it is for controlled single-server use, not high-throughput multi-node service. Local synthetic restore, local TLS proxy smoke, and health-only load tests passed, but no independent security assessment, malware scanning, public certificate/renewal validation, realistic upload/download/write load test, or production RPO/RTO exercise has been completed.

RSA key rotation remains blocked and requires re-encryption for the new key. Revocation prevents future server downloads but cannot recall copies already downloaded. New recipients require an upload containing their RSA envelope. Nmap scans must only target systems and networks for which you have explicit authorization.


## Deployment and validation tools

See `../deploy/README.md` for the Nginx TLS reverse proxy, systemd hardening, guarded restore procedure and staging load-test instructions. `node scripts/benchmark.mjs <base-url> <requests> <concurrency> </path>` reports latency percentiles and failures.
