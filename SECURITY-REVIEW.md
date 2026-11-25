# Cloud File Server v1.4.2 — Internal Security Review

**Review type:** Internal source/configuration review by the implementation agent. This is not an independent penetration test, formal audit, certification, or guarantee of security.

## Scope reviewed

- Native Node.js MVC HTTP router, authentication/session/CSRF handling, upload/download routes, admin authorization and static-file serving.
- SQLite persistence and migration, encrypted file storage, recipient-envelope enforcement, audit output, Nmap invocation.
- Backup verification and restore scripts, Nginx reverse-proxy template and systemd unit.

## Positive controls observed

- Passwords use scrypt with per-password random salts; sessions and CSRF tokens use cryptographically random tokens.
- Session cookies are HttpOnly and SameSite=Strict; production startup requires Secure cookies and loopback binding.
- Authenticated state-changing API requests require a CSRF header; API routes require a session; administrator routes check the admin role.
- CFS V2 file access checks recipient-specific RSA envelope metadata; downloads validate encrypted blob size and SHA-256 digest.
- Static content has a restrictive CSP; responses set `nosniff`; the TLS proxy template adds HSTS and browser security headers.
- Nmap is invoked using `execFile` (not a shell command) and input is restricted to private IPv4 ranges from /22 through /32.
- Backup/restore scripts reject unsafe manifest paths, symlinks, duplicates and checksum mismatches; restore requires explicit stopped-service acknowledgement and confirmation.
- Production systemd template uses a dedicated account, restrictive filesystem settings, `NoNewPrivileges`, and a private temporary directory.

## Findings and required actions

| Severity | Finding | Current mitigation / required action |
|---|---|---|
| High | No independent security assessment or penetration test | Obtain a qualified independent review before production exposure. |
| High | No malware scanning or quarantine workflow for uploaded content | Add isolated scanning, quarantine, timeout/failure policy and operator review. |
| High | `node:sqlite` is a release-candidate API, not stable | Accept the API stability risk explicitly or migrate to a stable database driver before production. |
| Medium | Upload parsing buffers request bodies in memory | Defaults now cap uploads at 50 MiB and two concurrent uploads; move to streaming uploads and test large-file behavior before increasing limits. |
| Medium | Application rate limiting is process-local | Keep one application process; Nginx adds edge limits for login/register. A multi-process deployment needs shared rate-limit state. |
| Medium | JSONL audit is append-oriented but not tamper-evident | Restrict file permissions and ship logs to protected off-host append-only storage/SIEM. |
| Medium | Backup encryption and off-host retention are operator responsibilities | Encrypt snapshots at rest, restrict access, retain off-host copies and test restore RPO/RTO. |
| Medium | No representative authenticated upload/download or concurrent SQLite-write load test | Run the benchmark plan on target hardware with representative data and defined SLOs. |
| Medium | Public certificate issuance/renewal and external TLS scanning were not tested | Deploy a trusted certificate, validate renewal/expiry alerting and run an external TLS scan. |
| Low | Self-registration remains enabled | Disable or gate registration externally if invite-only accounts are required. |

## Architecture constraints

- The metadata adapter rewrites the small state snapshot within SQLite transactions. Treat this as a controlled single-server/single-process architecture, not a horizontally scaled service.
- Nginx must be the only externally reachable listener. Keep Node bound to loopback and firewall the Node port.
- The Nmap feature is administrator-only and limited to private ranges; apply network egress controls and scan only authorized networks.
- Revoking access blocks future server downloads but cannot recall plaintext or ciphertext copies already downloaded by a recipient.

## Decision

**Not production approved.** The local validation evidence in `VALIDATION-REPORT.txt` supports staging evaluation only. Production approval requires the high-severity items above, supported-runtime validation on Node.js 24.15+, public TLS deployment/renewal validation, representative file-transfer/write load testing, and a documented restore/disaster-recovery exercise.
