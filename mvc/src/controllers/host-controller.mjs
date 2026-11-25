import { isIP } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const run = promisify(execFile);

export class HostController {
  constructor(db) { this.db = db; }
  async list() { return this.db.view(s => s.hosts); }
  async add(host, notes = '') {
    host = String(host || '').trim(); notes = String(notes || '').slice(0, 500);
    if (!host || host.length > 253) throw Object.assign(new Error('Enter a host label or IP.'), { status: 400 });
    const entry = { host, notes, added: new Date().toISOString() };
    await this.db.transaction(s => {
      if (s.hosts.some(x => x.host.toLowerCase() === host.toLowerCase())) throw Object.assign(new Error('Host already exists.'), { status: 409 });
      s.hosts.push(entry);
    });
    return entry;
  }
  async scan(cidr) {
    const m = String(cidr || '').match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m || isIP(m[1]) !== 4 || Number(m[2]) < 22 || Number(m[2]) > 32) throw Object.assign(new Error('Use a private IPv4 range /22 through /32 (maximum 1,024 addresses).'), { status: 400 });
    const oct = m[1].split('.').map(Number);
    if (oct.some(x => x > 255) || !(oct[0] === 10 || (oct[0] === 172 && oct[1] >= 16 && oct[1] <= 31) || (oct[0] === 192 && oct[1] === 168))) throw Object.assign(new Error('Only private IPv4 ranges are allowed.'), { status: 400 });
    try {
      const { stdout, stderr } = await run('nmap', ['-sn', '-n', cidr], { timeout: 120000, maxBuffer: 1024 * 1024 });
      const output = (stdout || stderr || 'No output').slice(-12000);
      await this.db.transaction(s => { s.last_scan = output; });
      return { output };
    } catch (e) {
      if (e.code === 'ENOENT') throw Object.assign(new Error('Nmap is not installed or not on PATH.'), { status: 501 });
      if (e.killed) throw Object.assign(new Error('Nmap scan timed out.'), { status: 504 });
      throw e;
    }
  }
  async lastScan() { return this.db.view(s => s.last_scan || ''); }
}
