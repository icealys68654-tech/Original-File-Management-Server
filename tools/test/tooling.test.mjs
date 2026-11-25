import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(fileURLToPath(new URL('../..',import.meta.url)));
function run(script,args=[]){return spawnSync(process.execPath,[resolve(root,script),...args],{cwd:root,encoding:'utf8'});}
test('C4 model and diagram validate',()=>{const r=run('tools/c4-validate.mjs');assert.equal(r.status,0,r.stderr);});
test('deployment env template passes lint',()=>{const r=run('tools/env-guard.mjs',['--file','deploy/systemd/cfs.env.example','--example']);assert.equal(r.status,0,r.stderr);});
test('smoke probe fails closed for unreachable endpoint',()=>{const r=run('tools/smoke-probe.mjs',['http://127.0.0.1:1']);assert.equal(r.status,1);});
