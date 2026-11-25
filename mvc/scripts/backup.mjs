import { DatabaseSync } from 'node:sqlite';
import { cp, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const mvc = resolve(here, '..');
const root = resolve(mvc, '..');
const dbPath = resolve(process.env.CFS_DB_PATH || join(mvc, 'data', 'cfs.sqlite'));
const storagePath = resolve(process.env.CFS_STORAGE_PATH || join(root, 'storage'));
const auditPath = resolve(process.env.CFS_AUDIT_PATH || join(root, 'audit.jsonl'));
const destination = resolve(process.env.CFS_BACKUP_DIR || join(root, '..', `cfs-backup-${new Date().toISOString().replace(/[:.]/g, '-')}`));

if (process.env.CFS_BACKUP_QUIESCED !== '1') throw new Error('Stop the Cloud File Server and set CFS_BACKUP_QUIESCED=1 before creating a consistent backup.');
if (destination === root || destination.startsWith(root + sep) || root.startsWith(destination + sep)) throw new Error('Backup destination must be outside the project directory and must not contain the project directory.');
for (const source of [dbPath, storagePath, auditPath]) { if (destination === source || destination.startsWith(source + sep) || source.startsWith(destination + sep)) throw new Error(`Backup destination overlaps a source path: ${source}`); }
if (!(await stat(dbPath).catch(() => null)) || !(await stat(dbPath)).isFile()) throw new Error(`SQLite database not found: ${dbPath}`);

const sqlite = new DatabaseSync(dbPath);
try {
  const checkpoint = sqlite.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
  if (checkpoint?.busy) throw new Error('SQLite WAL checkpoint is busy; ensure all application processes are stopped.');
} finally { sqlite.close(); }

await mkdir(dirname(destination), { recursive: true });
await mkdir(destination, { recursive: false });
await mkdir(join(destination, 'database'), { recursive: true });
await mkdir(join(destination, 'storage'), { recursive: true });
await cp(dbPath, join(destination, 'database', 'cfs.sqlite'));

async function copyTree(source, target) {
  await mkdir(target, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true }).catch(e => e.code === 'ENOENT' ? [] : Promise.reject(e))) {
    const from = join(source, entry.name), to = join(target, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Refusing to back up symlink: ${from}`);
    if (entry.isDirectory()) await copyTree(from, to);
    else if (entry.isFile()) await cp(from, to);
  }
}
await copyTree(storagePath, join(destination, 'storage'));
if (await stat(auditPath).catch(() => null)) {
  await mkdir(join(destination, 'audit'), { recursive: true });
  await cp(auditPath, join(destination, 'audit', 'audit.jsonl'));
}

async function inventory(dir, base = dir) {
  const rows = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Unexpected symlink in backup: ${path}`);
    if (entry.isDirectory()) rows.push(...await inventory(path, base));
    else if (entry.isFile()) {
      const bytes = await readFile(path);
      rows.push({ path: relative(base, path).split(sep).join('/'), size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
    }
  }
  return rows;
}
const files = await inventory(destination);
const manifest = { format: 'cfs-backup-v1', created_at: new Date().toISOString(), database_source: dbPath, storage_source: storagePath, audit_source: auditPath, files };
await writeFile(join(destination, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log(JSON.stringify({ backup: destination, files: files.length, manifest: 'manifest.json' }, null, 2));
