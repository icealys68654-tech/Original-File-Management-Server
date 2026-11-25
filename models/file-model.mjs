import { readdir, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
export function safeName(value) {
  const name = basename(String(value || '')).replace(/[\\/\0]/g, '').trim();
  if (!name || name === '.' || name === '..' || name.length > 240 || name.startsWith('.')) throw Object.assign(new Error('Invalid filename'), { status: 400 });
  return name;
}
export async function listFiles(storage) {
  const names = await readdir(storage);
  const rows = [];
  for (const name of names) { const s = await stat(join(storage, name)); if (s.isFile()) rows.push({ name, size: s.size, modified: s.mtime.toISOString() }); }
  return rows.sort((a,b) => a.name.localeCompare(b.name));
}
