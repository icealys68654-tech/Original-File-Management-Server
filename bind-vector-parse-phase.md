# Abstract codebase bind / vector / parse phase

This document describes the repository's umbrella validation flow. It is an orchestration contract, not a claim that the application performs vector-database indexing or embedding generation.

1. **Bind** — resolve the repository root and bind the workflow to the checked-in C4 model, environment template, Node.js application, and test suites.
2. **Vector** — assemble a deterministic ordered list of validation and test steps. The step vector is inspectable in `cmd/umbrella/main.go` through `plan`.
3. **Parse** — parse and validate the environment template and machine-readable C4 JSON; verify diagram references before running application tests.
4. **Execute** — run each step sequentially, stop on the first non-zero exit, and preserve child-process output and exit status.
5. **Probe** — when `CFS_BASE_URL` is supplied, run the HTTP health probe after validation and tests.

## Command contract

| Command | Behavior |
|---|---|
| `go run ./cmd/umbrella validate` | Environment template lint + C4 model/diagram validation |
| `go run ./cmd/umbrella test` | Umbrella tooling tests + application syntax and regression tests |
| `go run ./cmd/umbrella smoke` | Probe `CFS_BASE_URL`, defaulting to localhost |
| `CFS_BASE_URL=https://staging.example.test go run ./cmd/umbrella full` | Validate, test, then probe the supplied endpoint |

The workflow is fail-fast and does not deploy, mutate production data, or provision secrets. The existing CMake targets remain available as an alternative orchestration entry point.
