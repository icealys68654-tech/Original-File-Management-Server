import { mkdir, readFile } from 'node:fs/promises';
import { dirname, extname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const EMPTY = { users: [], sessions: [], files: [], permissions: [], hosts: [], registry: [], last_scan: '' };
const clone = value => structuredClone(value);

/** SQLite-backed metadata store. Controllers retain the state/transaction API. */
export class Database {
  constructor(path, { legacyPath = null } = {}) {
    this.path = path;
    this.legacyPath = legacyPath;
    this.state = null;
    this.queue = Promise.resolve();
    this.sqlite = null;
  }

  async load() {
    if (this.state) return this.state;
    await mkdir(dirname(this.path), { recursive: true });
    this.sqlite = new DatabaseSync(this.path);
    this.sqlite.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
        payload TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY, owner_id TEXT, payload TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS files_owner_idx ON files(owner_id);
      CREATE TABLE IF NOT EXISTS permissions (
        file_id TEXT NOT NULL, user_id TEXT NOT NULL, active INTEGER NOT NULL,
        payload TEXT NOT NULL, PRIMARY KEY(file_id,user_id),
        FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
      CREATE INDEX IF NOT EXISTS permissions_user_idx ON permissions(user_id,active);
      CREATE TABLE IF NOT EXISTS app_data (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    `);
    const dbVersion = this.sqlite.prepare('PRAGMA user_version').get().user_version;
    if (dbVersion > 2) throw new Error(`Database schema version ${dbVersion} is newer than this application supports.`);
    if (dbVersion < 2) this.migrateToV2();
    this.sqlite.exec('PRAGMA user_version = 2');
    this.state = this.readState();
    const appData = this.sqlite.prepare('SELECT key,payload FROM app_data').all();
    const legacyHosts = process.env.CFS_LEGACY_HOSTS_PATH || `${dirname(this.path)}/../../hosts.json`;
    const legacyRegistry = process.env.CFS_LEGACY_REGISTRY_PATH || process.env.CIS_REGISTRY_PATH || `${dirname(this.path)}/registry.json`;
    const legacyScan = process.env.CFS_LEGACY_SCAN_PATH || `${dirname(this.path)}/../../last_scan.txt`;
    const appDataMigrated = this.sqlite.prepare("SELECT value FROM schema_meta WHERE key='legacy_appdata_import'").get();
    if (!appData.length && !appDataMigrated) {
      let foundLegacyAppData = false;
      try { this.state.hosts = JSON.parse(await readFile(legacyHosts, 'utf8')); foundLegacyAppData = true; } catch (e) { if (e.code !== 'ENOENT') throw new Error(`Legacy host inventory migration failed: ${e.message}`); }
      try { const doc = JSON.parse(await readFile(legacyRegistry, 'utf8')); this.state.registry = Array.isArray(doc.entries) ? doc.entries : []; foundLegacyAppData = true; } catch (e) { if (e.code !== 'ENOENT') throw new Error(`Legacy CIS registry migration failed: ${e.message}`); }
      try { this.state.last_scan = await readFile(legacyScan, 'utf8'); foundLegacyAppData = true; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (foundLegacyAppData) {
        await this.writeState(this.state);
        this.sqlite.prepare("INSERT OR REPLACE INTO schema_meta(key,value) VALUES('legacy_appdata_import','complete')").run();
      }
    }
    const empty = !this.state.users.length && !this.state.files.length;
    const legacy = this.legacyPath || (extname(this.path) === '.sqlite' ? `${dirname(this.path)}/cfs-db.json` : null);
    const legacyMigrated = this.sqlite.prepare("SELECT value FROM schema_meta WHERE key='legacy_json_import'").get();
    if (empty && legacy && legacy !== this.path && !legacyMigrated) {
      try {
        const imported = { ...this.state, ...JSON.parse(await readFile(legacy, 'utf8')) };
        await this.writeState(imported);
        this.state = imported;
        this.sqlite.prepare("INSERT OR REPLACE INTO schema_meta(key,value) VALUES('legacy_json_import','complete')").run();
      } catch (error) {
        if (error.code !== 'ENOENT') throw new Error(`Legacy JSON database migration failed: ${error.message}`);
      }
    }
    return this.state;
  }

  migrateToV2() {
    // v2 permits owner_id=NULL only for quarantined legacy records awaiting
    // an explicit, envelope-verified administrator ownership assignment.
    this.sqlite.exec('PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE');
    try {
      this.sqlite.exec(`
        DROP INDEX IF EXISTS files_owner_idx;
        DROP INDEX IF EXISTS permissions_user_idx;
        ALTER TABLE permissions RENAME TO permissions_v1;
        ALTER TABLE files RENAME TO files_v1;
        CREATE TABLE files (
          id TEXT PRIMARY KEY, owner_id TEXT, payload TEXT NOT NULL,
          FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE SET NULL
        );
        INSERT INTO files(id,owner_id,payload) SELECT id,owner_id,payload FROM files_v1;
        CREATE INDEX files_owner_idx ON files(owner_id);
        CREATE TABLE permissions (
          file_id TEXT NOT NULL, user_id TEXT NOT NULL, active INTEGER NOT NULL,
          payload TEXT NOT NULL, PRIMARY KEY(file_id,user_id),
          FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        INSERT INTO permissions(file_id,user_id,active,payload)
          SELECT file_id,user_id,active,payload FROM permissions_v1;
        CREATE INDEX permissions_user_idx ON permissions(user_id,active);
        DROP TABLE permissions_v1; DROP TABLE files_v1;
      `);
      this.sqlite.exec('COMMIT');
    } catch (error) {
      this.sqlite.exec('ROLLBACK');
      throw error;
    } finally { this.sqlite.exec('PRAGMA foreign_keys = ON'); }
  }

  readState() {
    const read = table => this.sqlite.prepare(`SELECT payload FROM ${table}`).all().map(row => JSON.parse(row.payload));
    const app = Object.fromEntries(this.sqlite.prepare('SELECT key,payload FROM app_data').all().map(row => [row.key, JSON.parse(row.payload)]));
    return { ...EMPTY, users: read('users'), sessions: read('sessions'), files: read('files'), permissions: read('permissions'), ...app };
  }

  replaceState(state) {
    const db = this.sqlite;
      db.exec('DELETE FROM permissions; DELETE FROM sessions; DELETE FROM files; DELETE FROM users; DELETE FROM app_data;');
      const user = db.prepare('INSERT INTO users(id,email,payload) VALUES(?,?,?)');
      for (const x of state.users) user.run(x.id, x.email, JSON.stringify(x));
      const file = db.prepare('INSERT INTO files(id,owner_id,payload) VALUES(?,?,?)');
      for (const x of state.files) file.run(x.id, x.owner_id ?? null, JSON.stringify({ ...x, owner_id: x.owner_id ?? null }));
      const session = db.prepare('INSERT INTO sessions(id,user_id,expires_at,payload) VALUES(?,?,?,?)');
      for (const x of state.sessions) session.run(x.id, x.user_id, x.expires_at, JSON.stringify(x));
      const permission = db.prepare('INSERT INTO permissions(file_id,user_id,active,payload) VALUES(?,?,?,?)');
      for (const x of state.permissions) permission.run(x.file_id, x.user_id, x.active ? 1 : 0, JSON.stringify(x));
      const app = db.prepare('INSERT INTO app_data(key,payload) VALUES(?,?)');
      for (const key of ['hosts','registry','last_scan']) app.run(key, JSON.stringify(state[key] ?? (key === 'last_scan' ? '' : [])));
  }

  async writeState(state) {
    this.sqlite.exec('BEGIN IMMEDIATE');
    try { this.replaceState(state); this.sqlite.exec('COMMIT'); }
    catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
  }

  async transaction(fn) {
    const run = this.queue.then(async () => {
      await this.load();
      this.sqlite.exec('BEGIN IMMEDIATE');
      this.state = this.readState();
      const before = clone(this.state);
      try {
        const result = fn(this.state);
        if (result && typeof result.then === 'function') throw new TypeError('SQLite transaction callbacks must be synchronous.');
        this.replaceState(this.state);
        this.sqlite.exec('COMMIT');
        return result;
      } catch (error) {
        this.sqlite.exec('ROLLBACK');
        this.state = before;
        throw error;
      }
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async view(fn) {
    await this.load();
    // Read a consistent snapshot and observe commits from other processes.
    this.sqlite.exec('BEGIN');
    try { this.state = this.readState(); this.sqlite.exec('COMMIT'); }
    catch (error) { this.sqlite.exec('ROLLBACK'); throw error; }
    return fn(this.state);
  }

  close() {
    if (this.sqlite) { this.sqlite.close(); this.sqlite = null; this.state = null; }
  }
}
