# Cloud File Server v1.4.2 — CMake/GitHub umbrella integration

## Scope

This is an additive repository/workflow layer over the supplied v1.4.2 source archive. The active application remains the existing native Node.js MVC server. CMake is an orchestration umbrella; it does not compile or replace the Node application.

## Added artifacts

- `CMakeLists.txt`: CMake 3.20+ targets `env-guard`, `c4-validate`, `smoke-probe`, `ci-validate`, and `full-check`.
- `architecture/c4-model.json`: machine-readable C4 model with 8 elements and 7 relationships.
- `architecture/c4-context.mmd`: Mermaid C4 context diagram intended for GitHub rendering.
- `tools/c4-validate.mjs`: validates JSON, unique element IDs, relationship endpoints/labels and diagram element references.
- `tools/smoke-probe.mjs`: timeout-bounded HTTP health probe; checks HTTP success and `/health` JSON status.
- `tools/env-guard.mjs`: conservative KEY=VALUE linter for syntax, duplicate keys and placeholder/weak password values; it is not a shell parser or secrets scanner.
- `.env.example`: non-secret local template; `.gitignore` protects local `.env` files.
- `.github/workflows/ci.yml`: GitHub Actions validation, application regression tests, startup and smoke probe on Node 24.15.0.
- `tools/test/tooling.test.mjs`: tooling regression tests.

## Validation executed in the build environment

| Check | Result |
|---|---|
| CMake configure | Passed |
| CMake `ci-validate` | Passed |
| CMake `full-check` | Passed |
| C4 model | 8 elements / 7 relationships validated |
| Deployment env template lint | Passed (7 configured keys) |
| Tooling tests | 3 passed |
| Existing Node application tests | 20 passed |
| Python encryption tests | 9 passed |
| Smoke probe against local HTTP health fixture | Passed |
| ZIP integrity | Passed |

The available local runtime was Node.js 22.16.0. The application requires Node.js 24.15.0 or newer. Therefore, the unmodified app was not started locally for an end-to-end live smoke test; the GitHub workflow is configured to start it and probe it on Node 24.15.0. The smoke-probe utility itself was tested against a local HTTP fixture and verified to fail for an unreachable endpoint.

## Operational boundaries

- The C4 model is a context-level view, not a full Level 2/3 decomposition or compliance certification.
- The smoke probe checks `/health` by default; it is not a full browser, authentication, upload, download or sharing E2E test.
- `env-guard` does not execute shell syntax, expand variables, read secrets managers, or prove secret entropy.
- CI success is not equivalent to production approval. Existing v1.4.2 production gates remain: supported-runtime production deployment, public trusted TLS/DNS, representative file-transfer and database load, malware scanning/quarantine, production-sized DR with measured RPO/RTO, and independent security assessment.
- Existing `node:sqlite` release-candidate API and single-server architecture limitations remain unchanged.

## Run locally

```sh
cmake -S . -B build
cmake --build build --target ci-validate
cmake --build build --target full-check
CFS_BASE_URL=https://staging.example.com cmake --build build --target smoke-probe
node tools/env-guard.mjs --file .env
```

Use `deploy/systemd/cfs.env.example` or `.env.example` as templates only. Never commit real credentials.
