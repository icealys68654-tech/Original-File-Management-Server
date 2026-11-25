import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { Database } from '../src/models/database-model.mjs';

const mvc = resolve(new URL('..', import.meta.url).pathname);
test('offline backup restores SQLite metadata, encrypted blobs and audit log into isolated target', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'cfs-restore-drill-'));
  const source = join(temp, 'source'), dbPath = join(source, 'data', 'cfs.sqlite');
  const storage = join(source, 'storage'), audit = join(source, 'audit.jsonl');
  const backup = join(temp, 'backup'), target = join(temp, 'restored');
  try {
    await mkdir(join(source, 'data'), { recursive: true });
    await mkdir(storage, { recursive: true });
    const db = new Database(dbPath);
    await db.transaction(s => s.users.push({ id: 'restore-user', email: 'restore@example.test', role: 'user' }));
    await db.transaction(s => s.files.push({ id: 'restore-file', owner_id: 'restore-user', name: 'sample.cfs' }));
    db.close();
    await writeFile(join(storage, 'sample.enc'), Buffer.from('encrypted-fixture-data'));
    await writeFile(audit, '{"event":"restore-drill-fixture"}\n');
    const backupRun = spawnSync(process.execPath, [join(mvc, 'scripts/backup.mjs')], { encoding: 'utf8', env: { ...process.env, CFS_BACKUP_QUIESCED: '1', CFS_BACKUP_DIR: backup, CFS_DB_PATH: dbPath, CFS_STORAGE_PATH: storage, CFS_AUDIT_PATH: audit } });
    assert.equal(backupRun.status, 0, backupRun.stderr);
    const restoreRun = spawnSync(process.execPath, [join(mvc, 'scripts/restore.mjs'), backup, '--target-root', target], { encoding: 'utf8', env: { ...process.env, CFS_RESTORE_QUIESCED: '1', CFS_RESTORE_CONFIRM: 'RESTORE' } });
    assert.equal(restoreRun.status, 0, restoreRun.stderr);
    const restored = new Database(join(target, 'mvc', 'data', 'cfs.sqlite'));
    assert.equal((await restored.view(s => s.users.find(u => u.id === 'restore-user'))).email, 'restore@example.test');
    assert.equal((await restored.view(s => s.files.find(f => f.id === 'restore-file'))).name, 'sample.cfs');
    restored.close();
    assert.equal(await readFile(join(target, 'storage', 'sample.enc'), 'utf8'), 'encrypted-fixture-data');
    assert.match(await readFile(join(target, 'audit.jsonl'), 'utf8'), /restore-drill-fixture/);
    const verifyScript = join(mvc, 'scripts/verify-backup.mjs');
    const goodVerify = spawnSync(process.execPath, [verifyScript, backup], { encoding: 'utf8' });
    assert.equal(goodVerify.status, 0, goodVerify.stderr);
    await writeFile(join(backup, 'storage', 'sample.enc'), 'tampered');
    const badVerify = spawnSync(process.execPath, [verifyScript, backup], { encoding: 'utf8' });
    assert.notEqual(badVerify.status, 0, 'tampered backup must fail verification');
    const badRestore = spawnSync(process.execPath, [join(mvc, 'scripts/restore.mjs'), backup, '--target-root', join(temp, 'bad-restore')], { encoding: 'utf8', env: { ...process.env, CFS_RESTORE_QUIESCED: '1', CFS_RESTORE_CONFIRM: 'RESTORE' } });
    assert.notEqual(badRestore.status, 0, 'tampered backup must not restore');
  } finally { await rm(temp, { recursive: true, force: true }); }
});
