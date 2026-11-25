# v1.4.2 deployment and operations

## Topology

Expose only Nginx on TCP 80/443. The Node process binds to `127.0.0.1:5080`; do not publish the Node port. Use a dedicated unprivileged `cfs` account, a private environment file, and separate off-host backup storage. The provided Nginx file is a template: replace `cfs.example.com`, install a trusted certificate, verify the certificate renewal process, and run `nginx -t` before reload.

The proxy applies TLS 1.2/1.3, redirects HTTP to HTTPS, adds HSTS and browser security headers, caps upload size and concurrent connections, forwards the real client address only through a loopback proxy, and rate-limits authentication endpoints. The app defaults to a 50 MiB upload limit and two simultaneous uploads; tune only after memory/load testing. The app only trusts `X-Real-IP` when the TCP peer is loopback. Do not expose port 5080 or permit arbitrary local processes to reach it.

## Install

1. Install Node.js 24.15.0 or newer. This release uses `node:sqlite`, which is still a release-candidate API rather than a stable API.
2. Create a dedicated `cfs` OS account. Install the project under `/opt/cloud-file-server`, owned by root and read-only to `cfs` except the configured data, storage and audit paths.
3. Copy `deploy/systemd/cfs.env.example` to `/etc/cfs/cfs.env`; use a unique randomly generated administrator password, set permissions to `0600`, and keep it out of source control.
4. Adjust the systemd unit's writable paths if using non-default storage/database/audit paths. Enable the service only after the TLS proxy and firewall are configured.
5. Install `deploy/nginx/cfs.conf` into Nginx, update hostname and certificate paths, run `nginx -t`, reload Nginx, and verify HTTP redirects to HTTPS.
6. Firewall inbound traffic to 80/443 only. Restrict SSH and administrative access separately.

## Restore drill / recovery

Stop the service and take a rollback copy before replacing any existing target. Verify a backup first, then restore into an empty recovery directory:

```bash
node mvc/scripts/verify-backup.mjs /secure/backups/cfs-snapshot
CFS_RESTORE_QUIESCED=1 CFS_RESTORE_CONFIRM=RESTORE \
  node mvc/scripts/restore.mjs /secure/backups/cfs-snapshot \
  --target-root /srv/cfs-restore-drill
```

The restore maps the SQLite DB to `mvc/data/cfs.sqlite`, encrypted blobs to `storage/`, and the optional audit log to `audit.jsonl`. Validate the restored database, verify that encrypted file hashes match, start a staging instance against the restored paths, and test administrator login, owner download, recipient download, revoked access, and audit history. Do not point a production service at the restore directory until the drill passes. The automated test suite performs an isolated restore and reads back SQLite metadata, a storage fixture and audit log; it does not substitute for a production-sized restore/time measurement.

## Load testing

Run the script against a staging deployment, never against a production system without an approved test window:

```bash
node mvc/scripts/benchmark.mjs https://cfs-staging.example.com 1000 25 /health
```

It reports request failures, throughput and p50/p95/p99 latency. Run authenticated upload/download and concurrent SQLite write scenarios separately before setting capacity targets. The script does not itself define an acceptable service-level objective.

## Operational controls

- Back up database, encrypted storage and audit log together; encrypt backups at rest and replicate off-host.
- Monitor free disk, SQLite WAL growth, process restarts, TLS expiry, 4xx/5xx rates and backup age.
- Perform regular restore drills and document RPO/RTO.
- Malware scanning is not built into this release. Add an isolated scanner/quarantine pipeline before accepting untrusted uploads in a production threat model.
- Do not deploy multi-node active/active: the metadata adapter uses a process-local snapshot and SQLite is intended here for a controlled single-server deployment.
