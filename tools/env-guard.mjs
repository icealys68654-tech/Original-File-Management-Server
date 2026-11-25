#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const args=process.argv.slice(2);
const val=(flag)=>{const i=args.indexOf(flag);return i>=0?args[i+1]:undefined;};
const file=val('--file')||'.env';
const example=args.includes('--example');
const errors=[], warnings=[];
let source;
try { source=await readFile(resolve(file),'utf8'); }
catch { console.error(`env-guard: cannot read ${file}`); process.exit(2); }
const seen=new Set();
for (const [index,raw] of source.split(/\r?\n/).entries()) {
  const line=raw.trim();
  if (!line || line.startsWith('#')) continue;
  const m=line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
  if (!m) { errors.push(`line ${index+1}: expected KEY=VALUE`); continue; }
  const [,key,rawValue]=m;
  if (seen.has(key)) errors.push(`line ${index+1}: duplicate key ${key}`);
  seen.add(key);
  let value=rawValue.trim();
  if ((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'"))) value=value.slice(1,-1);
  if (/\$\{[^}]+\}/.test(value)) warnings.push(`line ${index+1}: ${key} uses interpolation; this linter does not expand it`);
  if (!example && /^(?:change_me|changeme|replace_me|replace_with|your[-_ ]|example)$/i.test(value)) errors.push(`${key} still has a placeholder value`);
  if (!example && /REPLACE_WITH|TODO|CHANGEME/i.test(value)) errors.push(`${key} still has a placeholder value`);
  if (key.toLowerCase().includes('password') && !example && value.length<16) errors.push(`${key} must contain at least 16 characters`);
  if (key==='CFS_COOKIE_SECURE' && value!=='1' && process.env.CFS_ENV==='production') errors.push('CFS_COOKIE_SECURE must be 1 in production');
  if (key==='CIS_HOST' && !example && process.env.CFS_ENV==='production' && !['127.0.0.1','::1','localhost'].includes(value)) errors.push('CIS_HOST must bind to loopback in production');
}
if (!example) {
  for (const key of ['CFS_ADMIN_EMAIL','CFS_ADMIN_PASSWORD']) if (!seen.has(key)) errors.push(`missing required key ${key}`);
}
for (const w of warnings) console.warn(`WARN ${w}`);
if (errors.length) { for (const e of errors) console.error(`ERROR ${e}`); console.error(`env-guard: ${errors.length} error(s)`); process.exit(1); }
console.log(`env-guard: ${file} passed (${seen.size} keys${example?', template mode':''})`);
