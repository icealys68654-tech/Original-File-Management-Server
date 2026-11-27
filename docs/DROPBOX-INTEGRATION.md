# Dropbox integration

The native Node.js MVC dashboard provides a per-user Dropbox connection using Dropbox OAuth authorization-code flow with offline refresh tokens. Requested scopes are limited to account metadata and file read/write.

## Setup

1. Create an app in the [Dropbox App Console](https://www.dropbox.com/developers/apps), using scoped access.
2. Enable `account_info.read`, `files.metadata.read`, `files.content.read`, and `files.content.write`.
3. Register the exact HTTPS redirect URI `https://YOUR-HOST/api/dropbox/oauth/callback`.
4. Set these environment variables on the server:
   - `CFS_DROPBOX_CLIENT_ID`: Dropbox app key.
   - `CFS_DROPBOX_CLIENT_SECRET`: Dropbox app secret.
   - `CFS_DROPBOX_REDIRECT_URI`: exact registered callback URL.
   - `CFS_DROPBOX_ENCRYPTION_KEY`: long random secret used for AES-256-GCM token-store encryption. Keep it stable and back it up securely; changing it makes saved tokens unreadable.
   - Optional `CFS_DROPBOX_TOKEN_PATH`: encrypted token store path (default `mvc/data/dropbox-tokens.enc`).
5. Restart the service, sign in, and use the Dropbox panel on the dashboard.

## Behavior and limits

- Each application user authorizes their own Dropbox account. Access/refresh tokens are stored encrypted at rest, with file permissions set to owner-only where supported.
- OAuth state is random, bound to the initiating user, expires after 10 minutes, and is held in process memory. Run a single application instance unless OAuth state is moved to shared storage.
- The dashboard supports listing the Dropbox root, uploading, downloading, and disconnecting. Upload/download are limited to 9 MiB per file.
- Dropbox storage is separate from the server's encrypted vault; no automatic synchronization occurs.
- Disconnect removes this application's saved tokens. To revoke the app grant entirely, also remove it from Dropbox account settings.
- Keep app credentials and the encryption key out of source control and browser code. Back up the encryption key alongside operational secrets.
