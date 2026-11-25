# Umbrella tooling

From the repository root:

```sh
node tools/env-guard.mjs --file deploy/systemd/cfs.env.example --example
node tools/env-guard.mjs --file .env
node tools/c4-validate.mjs
CFS_BASE_URL=https://staging.example.com node tools/smoke-probe.mjs
node --test tools/test
cmake -S . -B build
cmake --build build --target ci-validate
CFS_BASE_URL=https://staging.example.com cmake --build build --target smoke-probe
```

`env-guard` is a conservative KEY=VALUE linter, not a shell interpreter or secrets scanner. Do not commit `.env`; use `.env.example` for non-secret templates. `smoke-probe` checks `/health` by default and accepts comma-separated `SMOKE_PATHS`. The app's `/health` endpoint is intentionally unauthenticated.
