import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const backup = resolve(process.argv[2] || process.env.CFS_BACKUP_DIR || '');
if (!process.argv[2] && !process.env.CFS_BACKUP_DIR) throw new Error('Usage: node scripts/verify-backup.mjs <backup-directory>');
const manifest = JSON.parse(await readFile(join(backup, 'manifest.json'), 'utf8'));
if (manifest.format !== 'cfs-backup-v1' || !Array.isArray(manifest.files)) throw new Error('Unsupported or malformed backup manifest.');
const errors = [], seen = new Set();
for (const item of manifest.files) {
  if (typeof item.path !== 'string' || item.path.startsWith('/') || item.path.split('/').some(x => !x || x === '.' || x === '..') || seen.has(item.path)) { errors.push(`Unsafe or duplicate manifest path: ${item.path}`); continue; }
  seen.add(item.path);
  let path = backup, info;
  try {
    const parts = item.path.split('/');
    for (let i = 0; i < parts.length; i++) {
      path = join(path, parts[i]); info = await lstat(path);
      if (info.isSymbolicLink()) throw new Error('symlink');
      if (i < parts.length - 1 && !info.isDirectory()) throw new Error('not a directory');
    }
    const bytes = await readFile(path), digest = createHash('sha256').update(bytes).digest('hex');
    if (!info.isFile() || bytes.length !== item.size || digest !== item.sha256) errors.push(`Checksum/size mismatch: ${item.path}`);
  } catch { errors.push(`Missing, unsafe or unreadable backup file: ${item.path}`); }
}
if (!seen.has('database/cfs.sqlite')) errors.push('Missing required database/cfs.sqlite entry.');
if (errors.length) { console.error(errors.join('\n')); process.exitCode = 1; }
else console.log(`Backup verified: ${manifest.files.length} files; created ${manifest.created_at}`);
