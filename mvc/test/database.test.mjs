import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Database } from '../src/models/database-model.mjs';

test('SQLite persists relational metadata across reopen and enforces unique emails', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-sqlite-'));
  const path = join(dir, 'cfs.sqlite');
  try {
    const db = new Database(path);
    await db.transaction(s => s.users.push({ id: 'u1', email: 'one@example.test', role: 'user' }));
    await db.transaction(s => s.files.push({ id: 'f1', owner_id: 'u1', name: 'private.cfs' }));
    await db.transaction(s => s.sessions.push({ id: 's1', user_id: 'u1', expires_at: 9999999999999 }));
    await db.transaction(s => s.permissions.push({ file_id: 'f1', user_id: 'u1', active: true }));
    db.close();
    const reopened = new Database(path);
    assert.equal((await reopened.view(s => s.users))[0].email, 'one@example.test');
    assert.equal((await reopened.view(s => s.files))[0].name, 'private.cfs');
    assert.equal((await reopened.view(s => s.sessions)).length, 1);
    assert.equal((await reopened.view(s => s.permissions)).length, 1);
    await assert.rejects(() => reopened.transaction(s => s.users.push({ id: 'u2', email: 'one@example.test' })));
    assert.equal((await reopened.view(s => s.users)).length, 1);
    reopened.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('legacy JSON metadata is imported once and the source is preserved', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-migrate-'));
  const legacy = join(dir, 'cfs-db.json'), sqlite = join(dir, 'cfs.sqlite');
  const fixture = { users: [{ id: 'u1', email: 'legacy@example.test', role: 'user' }], sessions: [], files: [{ id: 'orphan1', name: 'unowned.cfs', stored_name: 'orphan1.cfs', recipients: [] }], permissions: [] };
  try {
    await writeFile(legacy, JSON.stringify(fixture));
    const db = new Database(sqlite, { legacyPath: legacy });
    assert.equal((await db.view(s => s.users))[0].email, 'legacy@example.test');
    assert.equal((await db.view(s => s.files))[0].owner_id, null);
    db.close();
    const again = new Database(sqlite, { legacyPath: legacy });
    assert.equal((await again.view(s => s.users)).length, 1);
    assert.equal((await again.view(s => s.files))[0].owner_id, null);
    assert.deepEqual(JSON.parse(await readFile(legacy, 'utf8')), fixture);
    again.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('failed transaction rolls back without corrupting committed state', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-rollback-'));
  try {
    const db = new Database(join(dir, 'cfs.sqlite'));
    await db.transaction(s => s.users.push({ id: 'u1', email: 'ok@example.test' }));
    await assert.rejects(() => db.transaction(s => { s.users.push({ id: 'u2', email: 'ok@example.test' }); }));
    assert.deepEqual((await db.view(s => s.users)).map(x => x.id), ['u1']);
    db.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('legacy CIS hosts and registry data migrate into SQLite app metadata', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-cis-migrate-'));
  const dbPath = join(dir, 'data', 'cfs.sqlite');
  const hostsPath = join(dir, 'hosts.json');
  const registryPath = join(dir, 'registry.json');
  try {
    await (await import('node:fs/promises')).mkdir(join(dir, 'data'), { recursive: true });
    await writeFile(hostsPath, JSON.stringify([{ host: '10.0.0.1', notes: 'gateway', added: '2026-01-01' }]));
    await writeFile(registryPath, JSON.stringify({ entries: [{ id: 'r1', name: 'Saved config', config: {}, updatedAt: '2026-01-01' }] }));
    const db = new Database(dbPath, { legacyPath: join(dir, 'missing.json') });
    // Override legacy discovery paths for this isolated fixture.
    db.close();
    process.env.CFS_LEGACY_HOSTS_PATH = hostsPath;
    process.env.CFS_LEGACY_REGISTRY_PATH = registryPath;
    const migrated = new Database(dbPath, { legacyPath: join(dir, 'missing.json') });
    assert.equal((await migrated.view(s => s.hosts))[0].host, '10.0.0.1');
    assert.equal((await migrated.view(s => s.registry))[0].id, 'r1');
    migrated.close();
  } finally {
    delete process.env.CFS_LEGACY_HOSTS_PATH;
    delete process.env.CFS_LEGACY_REGISTRY_PATH;
    await rm(dir, { recursive: true, force: true });
  }
});

test('host inventory persists in SQLite and rejects duplicate hosts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-hosts-'));
  try {
    const { HostController } = await import('../src/controllers/host-controller.mjs');
    const path = join(dir, 'cfs.sqlite');
    const db = new Database(path);
    const hosts = new HostController(db);
    await hosts.add('10.20.0.1', 'gateway');
    await assert.rejects(() => hosts.add('10.20.0.1', 'duplicate'), { status: 409 });
    db.close();
    const reopened = new Database(path);
    assert.equal((await new HostController(reopened).list())[0].notes, 'gateway');
    reopened.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('schema v1 migrates to nullable-owner quarantine without losing existing ACL rows', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cfs-schema-v1-'));
  const path = join(dir, 'cfs.sqlite');
  try {
    const { DatabaseSync } = await import('node:sqlite');
    const raw = new DatabaseSync(path);
    raw.exec(`
      PRAGMA foreign_keys=ON;
      CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,payload TEXT NOT NULL);
      CREATE TABLE sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
      CREATE INDEX sessions_user_idx ON sessions(user_id);
      CREATE TABLE files(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(owner_id) REFERENCES users(id));
      CREATE INDEX files_owner_idx ON files(owner_id);
      CREATE TABLE permissions(file_id TEXT NOT NULL,user_id TEXT NOT NULL,active INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(file_id,user_id),FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,FOREIGN KEY(user_id) REFERENCES users(id));
      CREATE INDEX permissions_user_idx ON permissions(user_id,active);
      CREATE TABLE app_data(key TEXT PRIMARY KEY,payload TEXT NOT NULL);
      CREATE TABLE schema_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      INSERT INTO users VALUES('u1','owner@example.test','{"id":"u1","email":"owner@example.test"}');
      INSERT INTO files VALUES('f1','u1','{"id":"f1","owner_id":"u1","name":"kept.cfs"}');
      INSERT INTO permissions VALUES('f1','u1',1,'{"file_id":"f1","user_id":"u1","active":true}');
      PRAGMA user_version=1;
    `);
    raw.close();
    const db = new Database(path, { legacyPath: join(dir, 'missing.json') });
    assert.equal((await db.view(s => s.files))[0].name, 'kept.cfs');
    await db.transaction(s => s.files.push({ id: 'orphan1', owner_id: null, name: 'quarantined.cfs', recipients: [] }));
    assert.equal((await db.view(s => s.files.find(f => f.id === 'orphan1'))).owner_id, null);
    assert.equal((await db.view(s => s.permissions)).length, 1);
    db.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});
