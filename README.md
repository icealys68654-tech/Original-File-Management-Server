# Cloud File Server v1.4.2

The active application is the native Node.js MVC server; Flask is not part of the active runtime. v1.4.2 adds a guarded restore utility, Nginx TLS reverse-proxy and systemd deployment templates, a repeatable load-test tool, bounded upload concurrency, safer backup verification, and an internal security review report.

## Run

Requirements: Node.js 24.15.0 or newer.

```powershell
cd mvc
node --test
$env:CIS_HOST = "127.0.0.1"
$env:CIS_PORT = "5080"
$env:CFS_ADMIN_EMAIL = "admin@example.com"
$env:CFS_ADMIN_PASSWORD = "replace-with-a-unique-random-password-of-24-or-more-characters"
node server.mjs
```

The default upload limit is 50 MiB with at most two simultaneous uploads. Tune only after representative memory/load tests. For network deployment, keep Node bound to loopback and use the Nginx configuration in `deploy/nginx/cfs.conf`. See `deploy/README.md` and `SECURITY-REVIEW.md`.

## Data and operations

- SQLite database: `mvc/data/cfs.sqlite`.
- Encrypted file blobs: `storage/`.
- JSONL application audit log: `audit.jsonl`.
- Offline backup: stop the service, set `CFS_BACKUP_QUIESCED=1` and `CFS_BACKUP_DIR`, then run `node mvc/scripts/backup.mjs`.
- Verify: `node mvc/scripts/verify-backup.mjs <backup-directory>`.
- Restore drill: `CFS_RESTORE_QUIESCED=1 CFS_RESTORE_CONFIRM=RESTORE node mvc/scripts/restore.mjs <backup-directory> --target-root <empty-recovery-directory>`.
- Load test: `node mvc/scripts/benchmark.mjs https://staging.example.com 1000 25 /health`.

## Release status

v1.4.2 is an operational-validation release candidate, **not production approved**. The restore path, local TLS termination, and a small health-endpoint load test passed in this environment. The environment only provides Node.js 22.16.0, so the HTTP smoke test used a temporary local-only runtime-gate bypass; supported-runtime validation on Node.js 24.15+ remains required. TLS used a temporary self-signed certificate, load testing did not exercise uploads/downloads or SQLite writes, and the security review was internal rather than independent. Malware scanning and a third-party security assessment remain required before production exposure.


## Repository umbrella: CMake + GitHub CI

The repository root now provides a CMake validation umbrella and GitHub Actions workflow. This does not replace the Node.js MVC application build; CMake orchestrates validation targets without compiling application code.

- `architecture/c4-model.json` and `architecture/c4-context.mmd`: machine-readable C4 model and Mermaid context diagram.
- `tools/c4-validate.mjs`: validates element IDs, relationship endpoints and diagram references.
- `tools/smoke-probe.mjs`: CI-ready HTTP endpoint probe (defaults to `/health`).
- `tools/env-guard.mjs`: conservative `.env` syntax/placeholder/duplicate-key linter.
- `.github/workflows/ci.yml`: runs the umbrella and app regression checks, starts the app and probes `/health`.
- `CMakeLists.txt`: `env-guard`, `c4-validate`, `smoke-probe`, `ci-validate`, and `full-check` targets.

See `tools/README.md` and `architecture/README.md`. The C4 model is a context-level architecture description, not a compliance certification. The smoke probe is a health check, not a complete end-to-end user workflow. Never commit real `.env` secrets.
