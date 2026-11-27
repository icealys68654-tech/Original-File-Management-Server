# Cloud File Server

A Node.js MVC file-management server with encrypted local file storage, operational tooling, and repository-level CI validation.

## Abstract

Cloud File Server (CFS) is organized as a small, auditable service and a deterministic validation pipeline. The application owns file handling and persistence; deployment infrastructure supplies HTTPS termination and process supervision; repository tooling validates configuration, architecture references, application behavior, and optional live health endpoints.

The project separates three concerns:

1. **Runtime** — the Node.js MVC application and its local data stores.
2. **Operations** — backup, verification, restore, load testing, Nginx, and systemd deployment assets.
3. **Validation** — Go and CMake orchestration, Node.js checks, architecture validation, and GitHub Actions.

The repository-level Go/CMake workflows orchestrate checks; they do not compile the Node.js application, provision production infrastructure, or deploy releases.

## Capability overview

- Encrypted local file blobs.
- SQLite metadata database and JSONL audit logging.
- Bounded upload concurrency and configurable upload limits.
- Offline backup, backup verification, and guarded restore tooling.
- Nginx TLS reverse-proxy and systemd deployment templates.
- C4 architecture model and diagram validation.
- Environment-template linting and HTTP health probing.
- Go and CMake validation entry points with GitHub Actions CI.

Dropbox OAuth integration is documented separately where enabled by the deployed application version. See [Dropbox integration documentation](docs/DROPBOX-INTEGRATION.md) if that file is present in your checkout.

## Abstract lexer and parser model

This section uses the requested mathematical and collection terms as a **documentation abstraction vocabulary**. It describes how to read and reason about the repository's workflow; it does not claim that the application contains a general-purpose mathematical expression interpreter.

### Lexer: recognize the input vocabulary

A lexer divides a source description into meaningful tokens before interpretation. For this project, the vocabulary can be grouped as follows:

| Token family | Examples | Documentation meaning |
|---|---|---|
| Algebra / expansion | `FOIL`, `solve for x` | Decompose a broad requirement into explicit inputs, constraints, and unknown configuration values. |
| Function | `f(x)` | Treat a validation stage as a transformation from inputs to a result. |
| Ordering | `order`, `sort` | Establish deterministic ordering for checks and release steps. |
| Collections | `vector`, `list` | Represent the planned checks as an ordered sequence and its individual entries. |

### Parser: build a valid workflow

After tokenization, the parser interprets the recognized concepts as a workflow model:

1. **Bind** — resolve the repository root and identify the application, C4 model, environment template, and test suites.
2. **Vector** — construct an ordered sequence of validation and test steps.
3. **Parse** — validate the environment template and C4 JSON, then verify diagram references.
4. **Execute** — run the sequence in order and stop at the first failing step.
5. **Probe** — optionally check an HTTP endpoint when `CFS_BASE_URL` is supplied.

In functional notation, a validation stage can be viewed as `f(x) -> result`, where `x` is the repository state and configuration input, and `result` is pass/fail plus the command output. The ordered step vector makes execution reproducible; sorting or reordering steps must not violate their dependencies.

The FOIL and “solve for x” terms are mnemonic decomposition tools in this abstract model, not implemented commands. The actual executable contract is the Go umbrella CLI described below.

## Architecture

```text
Developer change
      |
      v
GitHub Actions CI
      |
      v
Go / CMake validation umbrella
      |
      +--> environment-template lint
      +--> C4 model and diagram validation
      +--> tooling tests
      +--> Node.js syntax and regression tests
      +--> optional HTTP health probe
      |
      v
Node.js MVC application
      |
      +--> SQLite metadata database
      +--> encrypted local file blobs
      +--> JSONL audit log
```

For network deployment, keep the Node.js service bound to loopback and place Nginx in front of it:

```text
Internet -> Nginx HTTPS (443) -> Node.js (127.0.0.1:5080)
```

Expose only the required public web ports (normally 80/443). Do not expose the Node.js application port directly to the internet.

## Requirements

- Node.js 24.15.0 or newer for the active MVC application.
- Go 1.23+ for the Go umbrella workflow.
- CMake 3.20+ for the optional CMake workflow.
- Linux, Nginx, and systemd for the repository's example VPS deployment.

The active runtime is the native Node.js MVC server. Flask is not part of the active application runtime.

## Run the application locally

From the repository root:

```sh
cd mvc
node --test
CIS_HOST=127.0.0.1 CIS_PORT=5080 node server.mjs
```

Set a unique administrator credential through the environment before starting the server. For PowerShell:

```powershell
$env:CIS_HOST = "127.0.0.1"
$env:CIS_PORT = "5080"
$env:CFS_ADMIN_EMAIL = "admin@example.com"
$env:CFS_ADMIN_PASSWORD = "replace-with-a-unique-random-password"
node server.mjs
```

The default upload limit is 50 MiB with at most two simultaneous uploads. Change these limits only after representative memory and load testing.

## Data and operations

| Resource | Default location / command |
|---|---|
| SQLite database | `mvc/data/cfs.sqlite` |
| Encrypted file blobs | `storage/` |
| JSONL audit log | `audit.jsonl` |
| Backup | Stop the service, set `CFS_BACKUP_QUIESCED=1` and `CFS_BACKUP_DIR`, then run `node mvc/scripts/backup.mjs` |
| Backup verification | `node mvc/scripts/verify-backup.mjs <backup-directory>` |
| Restore drill | Set `CFS_RESTORE_QUIESCED=1` and `CFS_RESTORE_CONFIRM=RESTORE`, then run `node mvc/scripts/restore.mjs <backup-directory> --target-root <empty-recovery-directory>` |
| Load test | `node mvc/scripts/benchmark.mjs https://staging.example.com 1000 25 /health` |

Perform restore drills against an isolated recovery directory. Protect backups and encryption keys; a backup that cannot be decrypted during recovery is not a usable backup.

## CI and validation

### Go umbrella

The Go command provides a single repository-level entry point and delegates to the existing focused Node.js checks:

```sh
go test ./...
go run ./cmd/umbrella validate
go run ./cmd/umbrella test
go run ./cmd/umbrella smoke
go run ./cmd/umbrella full
CFS_BASE_URL=https://staging.example.com go run ./cmd/umbrella full
```

| Command | What it does |
|---|---|
| `validate` | Lints the deployment environment example and validates the C4 model/diagram references. |
| `test` | Runs umbrella tooling tests, application syntax validation, and MVC regression tests. |
| `smoke` | Probes the configured `CFS_BASE_URL`; defaults to the local health endpoint. |
| `full` | Runs validation and tests; adds the HTTP probe when `CFS_BASE_URL` is set. |

The workflow is sequential and fail-fast. It preserves child-process output and exit status. It does not deploy, mutate production data, or provision secrets.

### CMake alternative

```sh
cmake -S . -B build
cmake --build build --target ci-validate
cmake --build build --target full-check
CFS_BASE_URL=https://staging.example.com cmake --build build --target smoke-probe
```

Go and CMake are alternative orchestration entry points for repository checks; neither replaces the Node.js MVC application.

### GitHub Actions

The repository workflow is defined in `.github/workflows/ci.yml`. It runs the umbrella and application regression checks, starts the application, and probes `/health`.

A successful CI run means the configured workflow passed. It is not proof of production readiness, a complete end-to-end user journey, or an independent security certification.

## Deployment

The repository includes deployment examples:

- `deploy/nginx/cfs.conf` — Nginx TLS reverse proxy.
- `deploy/README.md` — deployment instructions.
- `deploy/systemd/` — service and environment templates.

For a VPS deployment, configure the application to listen on `127.0.0.1:5080`, configure Nginx to terminate HTTPS, and run the Node.js process under a dedicated unprivileged service account. Keep production secrets outside version control and use the host's secret-management mechanism.

## Release status

The current v1.4.2 release is an **operational-validation release candidate, not production approved**.

The recorded validation included a guarded restore utility, local TLS termination, and a small health-endpoint load test. Important limits remain:

- The available environment used Node.js 22.16.0, below the required Node.js 24.15.0 runtime. The HTTP smoke test used a temporary local-only runtime-gate bypass.
- TLS testing used a temporary self-signed certificate.
- Load testing did not exercise uploads, downloads, or SQLite writes.
- The security review was internal, not an independent assessment.
- Malware scanning and a third-party security assessment remain required before public production exposure.

Do not interpret a green CI badge as production approval.

## Production-readiness checklist

- [ ] Validate on the supported Node.js 24.15.0+ runtime without bypasses.
- [ ] Complete malware scanning for uploaded content.
- [ ] Configure encrypted, off-host backups and test restoration.
- [ ] Complete an independent third-party security assessment.
- [ ] Verify TLS with valid production certificates.
- [ ] Test upload/download paths and SQLite writes under representative load.
- [ ] Review authentication, authorization, CSRF protections, cookie settings, and rate limits.
- [ ] Confirm service-account and filesystem permissions.
- [ ] Configure log retention, monitoring, alerting, and incident response.
- [ ] Document rollback and recovery procedures.

## Repository map

- `mvc/` — active Node.js MVC application and regression tests.
- `cmd/umbrella/` — Go validation orchestrator.
- `tools/` — environment guard, C4 validator, smoke probe, and tooling tests.
- `architecture/` — C4 model, context diagram, and bind/vector/parse workflow.
- `deploy/` — Nginx and systemd deployment assets.
- `CMakeLists.txt` — CMake validation targets.
- `.github/workflows/ci.yml` — GitHub Actions CI workflow.
- `GO-UMBRELLA.md` — Go workflow reference.
- `SECURITY-REVIEW.md` — internal security review and known limitations.

## Further documentation

- [Go umbrella workflow](GO-UMBRELLA.md)
- [Bind / vector / parse phase](architecture/bind-vector-parse-phase.md)
- [Umbrella tooling](tools/README.md)
- [Deployment guide](deploy/README.md)
- [Security review](SECURITY-REVIEW.md)
