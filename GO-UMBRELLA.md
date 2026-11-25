# Go umbrella workflow

The Go command is the repository-level entry point for sequential validation. It delegates the existing focused Node.js checks rather than duplicating their rules.

## Requirements

- Go 1.23+
- Node.js 24.15+ (matches `mvc/package.json`)
- CMake 3.20+ for the optional CMake workflow

## Run

```sh
go test ./...
go run ./cmd/umbrella validate
go run ./cmd/umbrella test
go run ./cmd/umbrella smoke
go run ./cmd/umbrella full
CFS_BASE_URL=https://staging.example.com go run ./cmd/umbrella full
```

`full` includes the endpoint smoke probe only when `CFS_BASE_URL` is set. Without it, `full` performs static validation and regression tests and does not assume a service is already running.

## Existing CMake workflow

```sh
cmake -S . -B build
cmake --build build --target ci-validate
cmake --build build --target full-check
CFS_BASE_URL=https://staging.example.com cmake --build build --target smoke-probe
```

The Go umbrella does not replace CMake. Both are supported entry points for the same repository gates.
