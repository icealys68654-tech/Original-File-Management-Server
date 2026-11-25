const $=id=>document.getElementById(id);
const fail=message=>{$('status').textContent=message;$('status').classList.add('error');};
const b64u=s=>{const p=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(p+'='.repeat((4-p.length%4)%4)),c=>c.charCodeAt(0));};
const fromB64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const ext=name=>(name.split('.').pop()||'').toLowerCase();
async function main(){
 if(!globalThis.isSecureContext||!crypto?.subtle)throw Error('This browser does not support secure local decryption. Open the link over HTTPS in a modern browser.');
 const token=location.pathname.split('/').pop(),params=new URLSearchParams(location.hash.slice(1)),keyText=params.get('key');
 if(!/^[A-Za-z0-9_-]{43}$/.test(token)||!keyText)throw Error('The preview link is incomplete. Use the full link, including everything after the # character.');
 const response=await fetch('/api/public-preview/'+token,{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
 if(!response.ok)throw Error(response.status===404?'This preview link is invalid, expired, or revoked.':'Unable to retrieve the encrypted file.');
 const bytes=new Uint8Array(await response.arrayBuffer()),v2='CFS-HYBRID-ENCRYPTED-V2\n',v1='CFS-HYBRID-ENCRYPTED-V1\n';
 const decoder=new TextDecoder(),prefix=decoder.decode(bytes.subarray(0,Math.max(v1.length,v2.length)));
 let version,magic;if(prefix.startsWith(v2)){version=2;magic=v2;}else if(prefix.startsWith(v1)){version=1;magic=v1;}else throw Error('This is not a supported CFS encrypted file.');
 const envelope=JSON.parse(decoder.decode(bytes.subarray(magic.length)));
 if(envelope.version!==version||envelope.algorithm!=='AES-256-GCM + RSA-OAEP-SHA256')throw Error('Unsupported encrypted file format.');
 const rawKey=b64u(keyText);if(rawKey.length!==32)throw Error('The preview key is invalid.');
 const aes=await crypto.subtle.importKey('raw',rawKey,{name:'AES-GCM'},false,['decrypt']);
 const iv=fromB64(envelope.nonce),ciphertext=fromB64(envelope.ciphertext);
 const options={name:'AES-GCM',iv,tagLength:128};
 if(version===2){
  if(!Array.isArray(envelope.recipients)||!envelope.filename)throw Error('Malformed encrypted file envelope.');
  options.additionalData=new TextEncoder().encode(JSON.stringify({filename:envelope.filename,recipients:envelope.recipients.map(r=>({fingerprint:r.fingerprint,user_id:String(r.user_id)}))}));
 }
 const plaintext=await crypto.subtle.decrypt(options,aes,ciphertext);
 const name=String(envelope.filename||'Shared file'),kind=ext(name);$('title').textContent=name;document.title=name+' · Secure preview';$('status').textContent='Decrypted locally. No download or edit controls are provided.';
 const blobType=({png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',avif:'image/avif',txt:'text/plain',csv:'text/csv',log:'text/plain',json:'application/json',md:'text/plain'})[kind]||'application/octet-stream';
 const blob=new Blob([plaintext],{type:blobType}),url=URL.createObjectURL(blob),container=$('content');
 if(blobType.startsWith('image/')){const img=document.createElement('img');img.className='preview-image';img.alt='Shared image preview';img.src=url;container.append(img);}
 else if(['txt','csv','log','json','md'].includes(kind)){const pre=document.createElement('pre');pre.className='preview-text';pre.textContent=new TextDecoder('utf-8',{fatal:false}).decode(plaintext);container.append(pre);}
 else {URL.revokeObjectURL(url);$('status').textContent='The encrypted file was retrieved and decrypted in this browser, but this file type is not supported for inline preview. No download is offered.';}
}
main().catch(e=>fail(e.message||'Unable to display this preview.'));
