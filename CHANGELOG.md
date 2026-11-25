# Changelog

## 1.4.2 — Restore, TLS deployment and production validation candidate

### v1.4.2 follow-up gate run — 2026-11-25

- Added explicit integration tests for the `ISO_DUPLICATE_VIEW -> SORT_CONTROLLER -> DISC_MODEL + CIS -> MATH + JSON REGISTRY` path, including duplicate sorting, input preservation, deterministic seeded system-check output, JSON serialization and SQLite registry round-trip.
- Re-ran the Node suite (20/20) and Python crypto suite (9/9).
- Validated the shipped Nginx template and local TLS/auth flow with a temporary self-signed certificate; authenticated 500-request CIS API load probe completed with zero failures.
- Updated the MVC startup examples to match the production 16-character minimum administrator password.
- Production status remains blocked by supported-runtime validation, trusted public TLS/renewal, representative encrypted file-transfer and concurrent-write load tests, malware scanning, production-sized disaster recovery and independent security review. Details in `PRODUCTION-GATE-REPORT.md`.


- Added an explicit, stopped-service restore command requiring `CFS_RESTORE_QUIESCED=1`, `CFS_RESTORE_CONFIRM=RESTORE`, and an explicit target root; refuses overlapping paths, non-empty targets without `--replace`, symlinks, duplicate/unsafe manifest entries, missing files and checksum mismatches.
- Restore copies only manifest-listed regular files and maps the database, encrypted storage and audit log to a recovery root. Added an automated isolated restore drill that reads back SQLite metadata, encrypted blob fixture and audit history, then confirms tampered snapshots are rejected.
- Hardened backup verification to reject symlinks and unsafe/duplicate manifest paths.
- Added Nginx TLS 1.2/1.3 reverse-proxy template, HTTP-to-HTTPS redirect, HSTS/security headers, authentication rate limits, connection limits and real-client IP forwarding; added systemd hardening unit and protected environment example.
- Added repeatable concurrent HTTP load-test script reporting throughput and p50/p95/p99 latency.
- Added a bounded in-process login/register rate-limit map and trusted-loopback `X-Real-IP` handling; Nginx applies an edge limit to login and registration.
- Reduced default upload size to 50 MiB and capped concurrent buffered uploads at two by default to reduce memory-exhaustion risk. Both are configurable with validation.
- Added an internal security review (`SECURITY-REVIEW.md`) and evidence-based validation report. Local Nginx TLS smoke test and 1,000-request health endpoint load test passed.
- Release remains not production approved: runtime validation on Node 24.15+, trusted public-certificate/renewal testing, realistic upload/download/write load tests, malware scanning, disaster-recovery exercise and independent security assessment remain release gates.


## 1.4.1 — SQLite schema v2 and operational hardening

- Raised the minimum runtime to Node.js 24.15.0, where the built-in `node:sqlite` API is a release candidate rather than experimental; no external database driver was added because package registry access was unavailable for dependency verification.
- Added transactional SQLite schema v1-to-v2 migration with nullable owner references for quarantined legacy file records.
- Added admin-only preview and batch assignment endpoints for ownerless legacy metadata; assignment requires a valid encrypted V2 envelope for the selected user's registered RSA key, checks blob integrity and path safety, revalidates inside the write transaction, and writes an audit event.
- Previous owner-role recipient entries are revoked during reassignment to prevent privilege carry-over.
- Added production startup guards for secure cookies, loopback binding and bootstrap administrator credentials.
- Added offline backup and SHA-256 verification scripts for SQLite, encrypted storage and audit log. Restore remains operator-controlled; a restore drill has not been completed.
- Added schema migration and ownership assignment regression tests.
- Release remains a candidate; independent security review, TLS validation, malware scanning, load testing and restore/disaster-recovery drills remain outstanding.

## 1.4.0 — SQLite-backed Node.js MVC release candidate

- Replaced the active JSON metadata store with SQLite using Node's built-in `node:sqlite` API.
- Added transactional persistence, foreign keys, unique email constraints, lookup indexes, WAL mode and consistent read snapshots.
- Migrated host inventory, CIS registry and last scan output into SQLite.
- Added first-run imports for v1.3.x JSON metadata and legacy host/registry/scan files while preserving source files.
- Added encrypted blob size and SHA-256 integrity verification before downloads.
- Corrected new CFS V2 envelopes to match Python reference recipient-list metadata and AES-GCM AAD; retained Python decryption support for earlier v1.3.2 Node fingerprint-map V2 files.
- Kept Node.js MVC as the only active web runtime; Flask remains legacy reference source.
- Added database persistence, migration, rollback and integrity tests.
- Retained v1.3.2 auth, ACL, RSA envelope enforcement, audit and CIS; aligned new V2 recipient-list metadata and AES-GCM AAD with Python reference crypto, while preserving decryption compatibility for earlier Node V2 fingerprint-map files.
- Production approval remains withheld; `node:sqlite` is experimental and independent deployment/security validation is outstanding.

## 1.3.2 — Native Node.js MVC release candidate

- Promoted Node MVC as the active application runtime; Flask remains reference source.
- Added registration, scrypt password hashing, sessions, CSRF enforcement and admin bootstrap.
- Added file ownership, sharing permissions, CFS V2 multi-recipient encryption and RSA envelope enforcement.
- Added audit integration and Python V1/V2 decryption compatibility.

## 1.3.1 — MVC preview

- Added standalone Node.js MVC runtime based on the reference dashboard and encryption format.
- Retained host inventory, optional Nmap discovery and CIS workflow.

## 1.3.0 — Flask/Python baseline

- Added account and sharing work in the Flask implementation, with RSA envelope requirements and audit integration.

## v1.4.2 — CMake/GitHub umbrella integration

- Added CMake validation orchestration and GitHub Actions CI workflow.
- Added C4 model JSON, Mermaid context diagram and structural validator.
- Added timeout-bounded HTTP smoke probe and `.env` template linter.
- Added tooling tests and documented validation/production boundaries.
