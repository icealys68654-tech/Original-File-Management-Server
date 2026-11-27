# Render Web Service Deployment

This guide configures the existing Node.js MVC application as a single Render Web Service. It is a deployment recipe, not a production security approval.

## 1. Repository and service settings

Connect this repository in the Render Dashboard:

`https://github.com/icealys68654-tech/Original-File-Management-Server`

Use these settings:

| Render field | Value |
|---|---|
| Service type | Web Service |
| Runtime | Node |
| Branch | `main` (or the approved release branch) |
| Root Directory | `mvc` |
| Build Command | `npm install` |
| Start Command | `node server.mjs` |
| Health Check Path | `/health` |

The MVC package declares Node.js `>=24.15.0` and uses the built-in `node:sqlite` API. Pin `NODE_VERSION=24.22.1` in the Render environment (or another explicitly tested Node 24.x patch at least 24.15.0). Do not rely on an old service's inherited Node default.

There are no third-party npm dependencies in `mvc/package.json`; `npm install` is retained as the requested build command. The package also provides `npm test` for the built-in Node test suite.

## 2. Persistent disk

Attach a **paid-plan** persistent disk to this Web Service:

- Mount path: `/var/data`
- Configure the disk size for expected file growth and leave room for SQLite, audit records, and Dropbox token data.

Without a persistent disk, Render's filesystem is ephemeral. Uploaded blobs, the SQLite database, audit log, and Dropbox token file would be lost on restart or redeploy if stored only on the service filesystem.

Only files beneath `/var/data` are persistent. Set every application data path accordingly. A Render disk is attached to one service instance; it cannot be shared across instances, and attaching it disables zero-downtime deploys. This application should remain a single-instance service.

## 3. Environment variables

Set these under **Render Dashboard → your Web Service → Environment**.

### Required application settings

| Key | Value |
|---|---|
| `NODE_VERSION` | `24.22.1` |
| `CFS_ENV` | `production` |
| `CFS_RENDER_PROXY` | `1` |
| `CFS_COOKIE_SECURE` | `1` |
| `CIS_HOST` | `0.0.0.0` |
| `CFS_ADMIN_EMAIL` | Your administrator email |
| `CFS_ADMIN_PASSWORD` | A unique, randomly generated password of at least 16 characters |
| `CFS_STORAGE_PATH` | `/var/data/storage` |
| `CFS_DB_PATH` | `/var/data/cfs.sqlite` |
| `CFS_AUDIT_PATH` | `/var/data/audit.jsonl` |
| `CFS_DROPBOX_TOKEN_PATH` | `/var/data/dropbox-tokens.enc` |

**Do not set `CIS_PORT`.** Render supplies `PORT` at runtime; the application prefers `process.env.PORT` and falls back to `CIS_PORT` only for local use.

Generate secrets locally, for example:

```bash
openssl rand -base64 48
```

Generate a different value for the administrator password and each cryptographic key. Do not paste secrets into GitHub, this README, issue comments, or logs. Enter them directly into Render's secret environment-variable fields.

The bootstrap administrator is created only when no administrator exists yet. Changing `CFS_ADMIN_PASSWORD` after bootstrap does not rotate an existing account's password; use the application's supported account/password process rather than assuming an environment edit resets it.

### Optional Dropbox settings

Only add these if Dropbox integration is being enabled:

| Key | Value |
|---|---|
| `CFS_DROPBOX_CLIENT_ID` | Dropbox app client ID |
| `CFS_DROPBOX_CLIENT_SECRET` | Dropbox app client secret |
| `CFS_DROPBOX_REDIRECT_URI` | `https://YOUR-SERVICE.onrender.com/api/dropbox/oauth/callback` |
| `CFS_DROPBOX_ENCRYPTION_KEY` | A long random secret used to encrypt token storage |

Replace `YOUR-SERVICE` with the exact Render service subdomain. Register the exact same redirect URI in the Dropbox Developer Console. Keep the token file path under `/var/data` and retain a secure backup of the encryption key; losing or changing the key makes the existing token store unreadable.

After the first successful deploy, use the service URL plus `/api/dropbox/connect` to start the OAuth flow while signed in.

## 4. HTTPS and service URL

Render provisions HTTPS for the service's `onrender.com` hostname. The URL will resemble:

`https://YOUR-SERVICE.onrender.com`

Use the actual URL shown in the Render Dashboard. Do not expose the Node port directly; clients should use the HTTPS hostname.

The application already supports Render's proxy pattern: `CFS_RENDER_PROXY=1` permits the `0.0.0.0` bind expected behind Render's HTTPS proxy, and the server listens on Render's injected `PORT`.

## 5. Health check and first verification

Set the health check path to `/health`. The route currently returns HTTP 200 and a JSON document with `status: "ok"` after the server starts.

After deployment, verify:

```bash
curl -i https://YOUR-SERVICE.onrender.com/health
```

Then run the application checks in the Render Shell or a matching Node 24.x environment:

```bash
npm test
```

The current health route is a lightweight process/readiness response; it is not a full disk-integrity, backup, malware-scanning, or security test.

## 6. Single-instance and OAuth constraints

Keep the service at one instance:

- The app stores encrypted file blobs and SQLite metadata on a local persistent disk.
- Render persistent disks are attached to one service instance and prevent horizontal scaling.
- Dropbox OAuth `state` values are held in an in-memory `Map`. The callback must reach the same live process that initiated authorization; multiple instances or restarts during an OAuth attempt can invalidate the pending state.
- The SQLite adapter is intended for controlled single-server use, not a multi-node/high-throughput cluster.

Do not add multiple instances or move the OAuth callback behind a load-balanced multi-instance topology without first redesigning these components.

## 7. GitHub Pages compatibility

The repository's current web UI is served from `mvc/public` by the Node server. Its JavaScript uses relative API URLs (for example `/api/auth/me`) and `credentials: 'same-origin'`; the server uses `SameSite=Strict` session cookies and CSRF tokens.

Therefore, publishing the current UI unchanged to GitHub Pages will not make it work with a separate Render API. Cross-site Pages-to-Render use needs a deliberate architecture change, including:

- A configurable backend API origin in the frontend.
- Exact-origin CORS allowlisting and credentialed requests.
- A compatible cross-site cookie strategy (typically `SameSite=None; Secure`) or a different token/session design.
- CSRF and origin validation appropriate to that cross-origin design.
- Dropbox OAuth callback completion/return navigation to the Pages frontend.
- End-to-end tests in real browsers.

Do not solve this by using wildcard CORS with credentials or by weakening CSRF checks. Until this work is implemented and tested, use the UI served by the Render Node service itself.

## 8. Staging test plan

Create a separate staging service (for example `cfs-staging`) with its own persistent disk, administrator password, Dropbox app or sandbox account, and token encryption key. Do not reuse production data or secrets.

1. Confirm the deployed Node version is 24.15.0 or newer.
2. Confirm `GET /health` returns 200.
3. Register a non-admin test account and verify login/logout.
4. Upload, list, download, share, revoke, and delete harmless test files.
5. Restart/redeploy staging and confirm files, SQLite metadata, audit records, and Dropbox tokens remain available.
6. Connect Dropbox using the exact staging callback URL; test status, list, upload, download, and disconnect.
7. Verify one user cannot access another user's files without explicit permission.
8. Exercise invalid paths, oversized uploads, missing/invalid CSRF tokens, and repeated failed logins.
9. Inspect audit events without disclosing tokens, credentials, or private file contents.
10. Create an encrypted off-host backup, verify it, and complete a restore drill in an isolated recovery environment.
11. Run representative upload/download/SQLite load tests against staging only.

## 9. Production gate

The repository's v1.4.2 release remains an **operational-validation release candidate, not production approved**. Before public production exposure, complete all of the following:

- [ ] Malware scanning and quarantine for uploaded files.
- [ ] Encrypted off-host backups, retention policy, and tested restore procedure.
- [ ] Independent security assessment and remediation of findings.
- [ ] Authentication, authorization, CSRF, cookie, path traversal, rate-limit, and upload-limit review.
- [ ] Realistic upload/download/SQLite performance and concurrency testing.
- [ ] Monitoring, alerting, log retention, incident response, and rollback runbooks.
- [ ] Secure backup and recovery of the Dropbox encryption key.
- [ ] A tested plan for the in-memory OAuth state limitation.
- [ ] Explicit decision on whether the UI remains served by Node or is redesigned for GitHub Pages.

A green CI run or successful `/health` response is not production approval.

## References

- [Render Web Services](https://render.com/docs/web-services)
- [Render Node.js version selection](https://render.com/docs/node-version)
- [Render persistent disks](https://render.com/docs/disks)
- [Render health checks](https://render.com/docs/health-checks)
- [Render environment variables and secrets](https://render.com/docs/configure-environment-variables)
- [Dropbox integration notes](DROPBOX-INTEGRATION.md)
- [Internal security review](../SECURITY-REVIEW.md)
