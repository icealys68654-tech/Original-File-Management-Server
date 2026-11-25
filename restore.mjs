import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';

const backup = resolve(process.argv[2] || '');
const targetArg = process.argv.indexOf('--target-root');
const targetRoot = targetArg >= 0 ? resolve(process.argv[targetArg + 1] || '') : '';
const replace = process.argv.includes('--replace');
if (!process.argv[2] || !targetRoot || targetRoot === resolve('.')) throw new Error('Usage: node scripts/restore.mjs <backup-directory> --target-root <empty-target-directory> [--replace]');
if (process.env.CFS_RESTORE_QUIESCED !== '1') throw new Error('Set CFS_RESTORE_QUIESCED=1 only after stopping all CFS processes.');
if (process.env.CFS_RESTORE_CONFIRM !== 'RESTORE') throw new Error('Set CFS_RESTORE_CONFIRM=RESTORE to confirm the destructive restore operation.');
if (targetRoot === backup || targetRoot.startsWith(backup + sep) || backup.startsWith(targetRoot + sep)) throw new Error('Backup and target directories must not overlap.');
const manifest = JSON.parse(await readFile(join(backup, 'manifest.json'), 'utf8'));
if (manifest.format !== 'cfs-backup-v1' || !Array.isArray(manifest.files)) throw new Error('Unsupported or malformed backup manifest.');
const listed = new Set();
async function safeBackupFile(relativePath) {
  if (typeof relativePath !== 'string' || relativePath.startsWith('/') || relativePath.split('/').some(x => !x || x === '.' || x === '..')) throw new Error(`Unsafe manifest path: ${relativePath}`);
  let current = backup;
  const parts = relativePath.split('/');
  for (let i = 0; i < parts.length; i++) {
    current = join(current, parts[i]);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error(`Refusing symlink in backup: ${relativePath}`);
    if (i < parts.length - 1 && !info.isDirectory()) throw new Error(`Non-directory path component: ${relativePath}`);
    if (i === parts.length - 1 && !info.isFile()) throw new Error(`Backup entry is not a regular file: ${relativePath}`);
  }
  return current;
}
for (const item of manifest.files) {
  if (listed.has(item.path)) throw new Error(`Duplicate manifest path: ${item.path}`);
  listed.add(item.path);
  const path = await safeBackupFile(item.path);
  const bytes = await readFile(path), digest = createHash('sha256').update(bytes).digest('hex');
  if (bytes.length !== item.size || digest !== item.sha256) throw new Error(`Backup checksum/size mismatch: ${item.path}`);
}
if (!listed.has('database/cfs.sqlite')) throw new Error('Backup is missing database/cfs.sqlite.');
const existing = await readdir(targetRoot).catch(e => e.code === 'ENOENT' ? null : Promise.reject(e));
if (existing?.length && !replace) throw new Error('Target directory is not empty; use --replace only after taking a rollback copy.');
if (existing?.length && replace) {
  for (const name of ['mvc/data/cfs.sqlite', 'storage', 'audit.jsonl']) await rm(join(targetRoot, name), { recursive: true, force: true });
}
const dbTarget = join(targetRoot, 'mvc', 'data', 'cfs.sqlite');
await mkdir(dirname(dbTarget), { recursive: true });
await cp(await safeBackupFile('database/cfs.sqlite'), dbTarget);
await mkdir(join(targetRoot, 'storage'), { recursive: true });
for (const item of manifest.files.filter(x => x.path.startsWith('storage/'))) {
  const relativePath = item.path.slice('storage/'.length);
  const destination = join(targetRoot, 'storage', ...relativePath.split('/'));
  await mkdir(dirname(destination), { recursive: true });
  await cp(await safeBackupFile(item.path), destination);
}
if (listed.has('audit/audit.jsonl')) {
  await mkdir(targetRoot, { recursive: true });
  await cp(await safeBackupFile('audit/audit.jsonl'), join(targetRoot, 'audit.jsonl'));
}
console.log(JSON.stringify({ restored: true, target_root: targetRoot, database: dbTarget, storage: join(targetRoot, 'storage'), audit: listed.has('audit/audit.jsonl'), verified_files: listed.size }, null, 2));
