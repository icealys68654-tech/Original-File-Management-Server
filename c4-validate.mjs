#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
const modelPath=resolve('architecture/c4-model.json'), diagramPath=resolve('architecture/c4-context.mmd');
const fail=[];
let model;
try{model=JSON.parse(await readFile(modelPath,'utf8'));}catch(e){console.error(`C4: invalid model JSON: ${e.message}`);process.exit(1);}
const ids=new Set();
for(const [i,item] of (model.elements||[]).entries()){
 if(!item.id||!item.name||!item.type)fail.push(`elements[${i}] requires id, name, type`);
 if(ids.has(item.id))fail.push(`duplicate element id ${item.id}`);
 ids.add(item.id);
}
for(const [i,rel] of (model.relationships||[]).entries()){
 if(!ids.has(rel.from))fail.push(`relationships[${i}] unknown from=${rel.from}`);
 if(!ids.has(rel.to))fail.push(`relationships[${i}] unknown to=${rel.to}`);
 if(!rel.label)fail.push(`relationships[${i}] missing label`);
}
const diagram=await readFile(diagramPath,'utf8');
for(const id of ids) if(!diagram.includes(id))fail.push(`diagram does not reference ${id}`);
if(!diagram.includes('C4Context'))fail.push('diagram missing C4Context marker');
if(fail.length){for(const e of fail)console.error(`ERROR ${e}`);process.exit(1);}
console.log(`C4: valid (${ids.size} elements, ${(model.relationships||[]).length} relationships); diagram references all elements`);
