#!/usr/bin/env node
const base=(process.argv[2]||process.env.CFS_BASE_URL||'http://127.0.0.1:5080').replace(/\/+$/,'');
const timeout=Number(process.env.SMOKE_TIMEOUT_MS||5000);
const paths=(process.env.SMOKE_PATHS||'/health').split(',').map(x=>x.trim()).filter(Boolean);
let failed=0;
for (const path of paths) {
  const url=new URL(path.startsWith('/')?path:`/${path}`,base);
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try {
    const response=await fetch(url,{signal:controller.signal,headers:{accept:'application/json'}});
    const body=await response.text();
    let parsed; try{parsed=JSON.parse(body);}catch{}
    const ok=response.ok && (path==='/health' ? parsed?.status==='ok' : true);
    console.log(`${ok?'PASS':'FAIL'} ${response.status} ${url.pathname}${path==='/health'&&parsed?.version?` version=${parsed.version}`:''}`);
    if(!ok) failed++;
  } catch(e) { console.error(`FAIL ${url.pathname}: ${e.name==='AbortError'?'timeout':e.message}`); failed++; }
  finally {clearTimeout(timer);}
}
if(failed){console.error(`smoke-probe: ${failed}/${paths.length} probe(s) failed`);process.exit(1);}
console.log(`smoke-probe: ${paths.length} probe(s) passed`);
