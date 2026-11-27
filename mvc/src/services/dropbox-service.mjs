import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

/** Per-user Dropbox OAuth and API client. Tokens are encrypted at rest with CFS_DROPBOX_ENCRYPTION_KEY. */
export class DropboxService {
  constructor({ clientId, clientSecret, redirectUri, tokenPath, encryptionKey, audit }) {
    this.clientId = clientId; this.clientSecret = clientSecret; this.redirectUri = redirectUri;
    this.tokenPath = tokenPath; this.key = createHash('sha256').update(encryptionKey).digest();
    this.audit = audit; this.pending = new Map();
  }
  configured() { return Boolean(this.clientId && this.clientSecret && this.redirectUri); }
  async readTokens() {
    try {
      const doc = JSON.parse(await readFile(this.tokenPath, 'utf8'));
      const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(doc.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(doc.tag, 'base64'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(doc.data, 'base64')), decipher.final()]).toString('utf8'));
    } catch (e) { if (e.code === 'ENOENT') return {}; if (e.message?.includes('Unsupported state')) throw e; throw Object.assign(new Error('Dropbox token store could not be decrypted; check CFS_DROPBOX_ENCRYPTION_KEY.'), { status: 500 }); }
  }
  async writeTokens(tokens) {
    await mkdir(dirname(this.tokenPath), { recursive: true });
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(tokens)), cipher.final()]);
    const doc = { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
    await writeFile(this.tokenPath, JSON.stringify(doc), { mode: 0o600 });
  }
  async connectUrl(userId) {
    if (!this.configured()) throw Object.assign(new Error('Dropbox OAuth is not configured.'), { status: 503 });
    const state = randomBytes(32).toString('base64url');
    for (const [key, value] of this.pending) if (value.expires < Date.now()) this.pending.delete(key);
    this.pending.set(state, { userId, expires: Date.now() + 10 * 60_000 });
    const u = new URL('https://www.dropbox.com/oauth2/authorize');
    Object.entries({ client_id: this.clientId, response_type: 'code', token_access_type: 'offline', redirect_uri: this.redirectUri, state, scope: 'account_info.read files.metadata.read files.content.read files.content.write' }).forEach(([k,v]) => u.searchParams.set(k,v));
    return u.toString();
  }
  async callback(code, state) {
    const pending = this.pending.get(state); this.pending.delete(state);
    if (!pending || pending.expires < Date.now()) throw Object.assign(new Error('Dropbox authorization state is invalid or expired.'), { status: 400 });
    const body = new URLSearchParams({ code, grant_type: 'authorization_code', redirect_uri: this.redirectUri, client_id: this.clientId, client_secret: this.clientSecret });
    const response = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    const result = await response.json();
    if (!response.ok || !result.access_token) throw Object.assign(new Error('Dropbox authorization failed.'), { status: 502 });
    const tokens = await this.readTokens();
    tokens[pending.userId] = { access_token: result.access_token, refresh_token: result.refresh_token || tokens[pending.userId]?.refresh_token || null, expires_at: Date.now() + Number(result.expires_in || 14400) * 1000 };
    await this.writeTokens(tokens); await this.audit('dropbox.connected', { user_id: pending.userId });
    return pending.userId;
  }
  async accessToken(userId) {
    const tokens = await this.readTokens(), saved = tokens[userId];
    if (!saved) throw Object.assign(new Error('Dropbox is not connected.'), { status: 409 });
    if (saved.expires_at > Date.now() + 60_000) return saved.access_token;
    if (!saved.refresh_token) throw Object.assign(new Error('Dropbox session expired; reconnect Dropbox.'), { status: 401 });
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: saved.refresh_token, client_id: this.clientId, client_secret: this.clientSecret });
    const response = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    const result = await response.json();
    if (!response.ok || !result.access_token) throw Object.assign(new Error('Could not refresh Dropbox authorization; reconnect Dropbox.'), { status: 401 });
    tokens[userId] = { ...saved, access_token: result.access_token, expires_at: Date.now() + Number(result.expires_in || 14400) * 1000 };
    await this.writeTokens(tokens); return result.access_token;
  }
  async request(userId, endpoint, args = {}, data = null) {
    const access = await this.accessToken(userId);
    const headers = { authorization: `Bearer ${access}` };
    let response;
    if (endpoint === 'upload') {
      headers['content-type'] = 'application/octet-stream'; headers['dropbox-api-arg'] = JSON.stringify(args);
      response = await fetch('https://content.dropboxapi.com/2/files/upload', { method: 'POST', headers, body: data });
    } else {
      headers['content-type'] = 'application/json';
      response = await fetch(`https://api.dropboxapi.com/2/${endpoint}`, { method: 'POST', headers, body: JSON.stringify(args) });
    }
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error('Dropbox API request failed.'), { status: response.status === 401 ? 401 : 502 });
    return result;
  }
  async status(userId) {
    const tokens = await this.readTokens();
    if (!tokens[userId]) return { configured: this.configured(), connected: false };
    const account = await this.request(userId, 'users/get_current_account');
    return { configured: this.configured(), connected: true, account: { name: account.name?.display_name, email: account.email } };
  }
  async list(userId, path = '') {
    const result = await this.request(userId, 'files/list_folder', { path, recursive: false, include_deleted: false, limit: 200 });
    return { entries: (result.entries || []).map(x => ({ id: x.id, name: x.name, path: x.path_display, type: x['.tag'], size: x.size || 0, modified: x.server_modified || null })), has_more: result.has_more };
  }
  async upload(userId, path, content) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.length > 1024 || path.includes('\\0')) throw Object.assign(new Error('A valid Dropbox destination path is required.'), { status: 400 });
    if (typeof content !== 'string' || content.length > 12 * 1024 * 1024) throw Object.assign(new Error('File content must be base64 and no larger than 9 MiB.'), { status: 413 });
    const data = Buffer.from(content, 'base64');
    if (data.length > 9 * 1024 * 1024) throw Object.assign(new Error('Dropbox upload limit for this endpoint is 9 MiB.'), { status: 413 });
    return this.request(userId, 'upload', { path, mode: 'add', autorename: true, mute: false, strict_conflict: false }, data);
  }
  async download(userId, path) {
    if (typeof path !== 'string' || !path.startsWith('/')) throw Object.assign(new Error('A valid Dropbox file path is required.'), { status: 400 });
    const access = await this.accessToken(userId);
    const response = await fetch('https://content.dropboxapi.com/2/files/download', { method: 'POST', headers: { authorization: `Bearer ${access}`, 'dropbox-api-arg': JSON.stringify({ path }) } });
    if (!response.ok) throw Object.assign(new Error('Dropbox download failed.'), { status: 502 });
    const data = Buffer.from(await response.arrayBuffer());
    if (data.length > 9 * 1024 * 1024) throw Object.assign(new Error('Dropbox download exceeds the 9 MiB API limit.'), { status: 413 });
    return { content: data.toString('base64'), name: path.split('/').pop(), size: data.length };
  }
  async disconnect(userId) {
    const tokens = await this.readTokens(); delete tokens[userId]; await this.writeTokens(tokens);
    await this.audit('dropbox.disconnected', { user_id: userId }); return { disconnected: true };
  }
}
