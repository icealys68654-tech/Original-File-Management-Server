import { readFile, writeFile, unlink, mkdir, stat } from 'node:fs/promises';
import { join, basename, resolve, sep } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { safeName } from '../models/file-model.mjs';
import { encryptEnvelopeV2, fingerprint, validateRecipientKey, inspectEnvelope } from '../services/encryption-service.mjs';
import { id, token } from '../services/security-service.mjs';
export class SecureFileController {
 constructor({storage,db,audit}){this.storage=storage;this.db=db;this.audit=audit;}
 async setPublicKey(userId,pem){validateRecipientKey(pem);const fp=fingerprint(pem);const current=await this.db.view(s=>s.users.find(x=>x.id===userId));if(current?.key_fingerprint&&current.key_fingerprint!==fp)throw Object.assign(new Error('RSA key rotation is not automatic. Keep the existing key or create a new account and re-encrypt files for the new key.'),{status:409});await this.db.transaction(s=>{const u=s.users.find(x=>x.id===userId);u.public_key=String(pem);u.key_fingerprint=fp;});await this.audit('key.public_key_registered',{user_id:userId,fingerprint:fp});return {fingerprint:fp};}
 async upload(userId,name,data,recipientIds=[]){name=safeName(name);const users=await this.db.view(s=>s.users.filter(u=>u.id===userId||recipientIds.includes(u.id)));const owner=users.find(u=>u.id===userId);if(!owner?.public_key)throw Object.assign(new Error('Register your RSA public key before uploading.'),{status:409});if(users.length!==new Set([userId,...recipientIds]).size)throw Object.assign(new Error('One or more recipients do not exist.'),{status:400});for(const u of users)if(!u.public_key)throw Object.assign(new Error(`Recipient ${u.email} has not registered an RSA public key.`),{status:409});const encrypted=encryptEnvelopeV2(data,name,users.map(u=>({pem:u.public_key,user_id:u.id})));const {envelope}=inspectEnvelope(encrypted);const fileId=id(),stored=`${fileId}.cfs`,target=join(this.storage,stored);await mkdir(this.storage,{recursive:true});await writeFile(target,encrypted,{flag:'wx',mode:0o600});const recipients=users.map(u=>({user_id:u.id,fingerprint:u.key_fingerprint,permission:u.id===userId?'owner':'viewer',granted_at:new Date().toISOString()}));const record={id:fileId,owner_id:userId,name,stored_name:stored,size:data.length,encrypted_size:encrypted.length,encrypted_sha256:createHash('sha256').update(encrypted).digest('hex'),sha256:createHash('sha256').update(data).digest('hex'),envelope_version:envelope.version,recipients,created_at:new Date().toISOString()};await this.db.transaction(s=>{s.files.push(record);for(const r of recipients)if(r.user_id!==userId)s.permissions.push({file_id:fileId,user_id:r.user_id,permission:'viewer',active:true,created_at:r.granted_at});});await this.audit('file.upload',{file_id:fileId,owner_id:userId,recipient_ids:recipients.map(r=>r.user_id),bytes:data.length,envelope_version:2});return {id:fileId,name,size:data.length,encrypted:true,envelope_version:2,recipients:recipients.length};}
 async list(user){
  return this.db.view(s=>s.files
   .filter(f=>f.owner_id===user.id||f.recipients.some(r=>r.user_id===user.id&&r.permission!=='revoked'))
   .map(f=>({id:f.id,name:f.name,size:f.size,created_at:f.created_at,owner:f.owner_id===user.id,permission:f.owner_id===user.id?'owner':(f.recipients.find(r=>r.user_id===user.id)?.permission||'viewer'),envelope_version:f.envelope_version,recipients:f.owner_id===user.id?f.recipients.filter(r=>r.user_id!==user.id&&r.permission!=='revoked').map(r=>({user_id:r.user_id,email:s.users.find(u=>u.id===r.user_id)?.email||'Unknown recipient',permission:r.permission})):[],preview_links:f.owner_id===user.id?(s.share_links||[]).filter(l=>l.file_id===f.id).map(l=>({id:l.id,created_at:l.created_at,expires_at:l.expires_at,revoked:Boolean(l.revoked)})):[]})));
 }

 async listUnassignedLegacy(){
  return this.db.view(s=>s.files.filter(f=>!f.owner_id).map(f=>({id:f.id,name:f.name||'Unnamed legacy file',size:Number(f.size)||0,created_at:f.created_at||null,stored_name:f.stored_name||null})));
 }
 async assignLegacyOwnership(adminId,assignments){
  if(!Array.isArray(assignments)||assignments.length<1||assignments.length>100)throw Object.assign(new Error('Provide between 1 and 100 ownership assignments.'),{status:400});
  const ids=assignments.map(x=>x?.file_id);if(ids.some(x=>typeof x!=='string'||!/^[a-f0-9]{32}$/.test(x))||new Set(ids).size!==ids.length)throw Object.assign(new Error('Each assignment must contain a unique valid file_id.'),{status:400});
  const candidates=await this.db.view(s=>assignments.map(a=>({file:s.files.find(f=>f.id===a.file_id),user:s.users.find(u=>u.id===a.owner_id)})));
  const verified=[];
  for(let i=0;i<assignments.length;i++){
   const {file,user}=candidates[i],assignment=assignments[i];
   if(!file||file.owner_id)throw Object.assign(new Error(`File ${assignment.file_id} is missing or already has an owner.`),{status:409});
   if(!user||!user.key_fingerprint)throw Object.assign(new Error(`Target owner for file ${assignment.file_id} must exist and have a registered RSA key.`),{status:409});
   const stored=String(file.stored_name||'');
   if(!stored||basename(stored)!==stored||stored==='.'||stored==='..')throw Object.assign(new Error(`File ${assignment.file_id} has an unsafe storage reference.`),{status:409});
   const target=resolve(this.storage,stored);if(!target.startsWith(resolve(this.storage)+sep))throw Object.assign(new Error(`File ${assignment.file_id} resolves outside storage.`),{status:409});
   let raw;try{raw=await readFile(target);}catch{throw Object.assign(new Error(`Encrypted blob for file ${assignment.file_id} is missing or unreadable.`),{status:409});}
   if(file.encrypted_size!==undefined&&raw.length!==file.encrypted_size)throw Object.assign(new Error(`Encrypted blob size mismatch for file ${assignment.file_id}.`),{status:409});
   if(file.encrypted_sha256&&createHash('sha256').update(raw).digest('hex')!==file.encrypted_sha256)throw Object.assign(new Error(`Encrypted blob checksum mismatch for file ${assignment.file_id}.`),{status:409});
   let envelope;try{envelope=inspectEnvelope(raw).envelope;}catch{throw Object.assign(new Error(`File ${assignment.file_id} is not a recognized encrypted CFS envelope.`),{status:409});}
   const hasKey=Array.isArray(envelope.recipients)?envelope.recipients.some(r=>r.user_id===user.id&&r.fingerprint===user.key_fingerprint&&typeof r.wrapped_key==='string'):Boolean(envelope.wrapped_keys?.[user.key_fingerprint]);
   if(!hasKey)throw Object.assign(new Error(`File ${assignment.file_id} has no RSA envelope for the selected owner's current key; ownership was not assigned.`),{status:409});
   verified.push({file_id:file.id,owner_id:user.id,fingerprint:user.key_fingerprint});
  }
  await this.db.transaction(s=>{
   for(const item of verified){const f=s.files.find(x=>x.id===item.file_id),u=s.users.find(x=>x.id===item.owner_id);if(!f||f.owner_id||!u||u.key_fingerprint!==item.fingerprint)throw Object.assign(new Error(`Ownership assignment for ${item.file_id} changed during validation; retry preview.`),{status:409});f.owner_id=u.id;f.recipients=Array.isArray(f.recipients)?f.recipients:[];for(const prior of f.recipients){if(prior.user_id!==u.id&&prior.permission==='owner'){prior.permission='revoked';prior.revoked_at=new Date().toISOString();const old=s.permissions.find(p=>p.file_id===f.id&&p.user_id===prior.user_id);if(old){old.active=false;old.revoked_at=prior.revoked_at;}}}let r=f.recipients.find(x=>x.user_id===u.id);if(r){r.permission='owner';r.fingerprint=item.fingerprint;r.granted_at=r.granted_at||new Date().toISOString();}else f.recipients.push({user_id:u.id,fingerprint:item.fingerprint,permission:'owner',granted_at:new Date().toISOString()});s.permissions=s.permissions.filter(p=>!(p.file_id===f.id&&p.user_id===u.id));}
  });
  await this.audit('legacy_file.ownership_assigned',{admin_id:adminId,assignments:verified});
  return {assigned:verified.length,files:verified.map(x=>({file_id:x.file_id,owner_id:x.owner_id}))};
 }
 async download(user,fileId){const file=await this.db.view(s=>s.files.find(f=>f.id===fileId));if(!file)throw Object.assign(new Error('File not found.'),{status:404});const recipient=file.recipients.find(r=>r.user_id===user.id&&r.permission!=='revoked');if(!recipient||(recipient.permission!=='owner'&&recipient.permission!=='download'))throw Object.assign(new Error('You do not have download permission for this file.'),{status:403});const raw=await readFile(join(this.storage,file.stored_name));if(file.encrypted_size!==undefined&&raw.length!==file.encrypted_size)throw Object.assign(new Error('Stored encrypted file size does not match metadata; download denied.'),{status:409});if(file.encrypted_sha256&&createHash('sha256').update(raw).digest('hex')!==file.encrypted_sha256)throw Object.assign(new Error('Stored encrypted file checksum mismatch; download denied.'),{status:409});const {version,envelope}=inspectEnvelope(raw);const hasEnvelope=Array.isArray(envelope.recipients)?envelope.recipients.some(r=>r.user_id===user.id&&r.fingerprint===recipient.fingerprint&&typeof r.wrapped_key==='string'):Boolean(envelope.wrapped_keys?.[recipient.fingerprint]);if(version!==2||!hasEnvelope)throw Object.assign(new Error('Recipient RSA envelope missing; download denied.'),{status:403});await this.audit('file.download',{file_id:fileId,user_id:user.id});return {name:file.name,data:raw};}
 async grant(ownerId,fileId,recipientId,permission='viewer'){if(!['viewer','download'].includes(permission))throw Object.assign(new Error('Permission must be viewer or download.'),{status:400});const outcome=await this.db.transaction(s=>{const f=s.files.find(x=>x.id===fileId&&x.owner_id===ownerId);if(!f)throw Object.assign(new Error('Owned file not found.'),{status:404});const u=s.users.find(x=>x.id===recipientId);if(!u)throw Object.assign(new Error('Recipient not found.'),{status:404});if(!u.key_fingerprint||!f.recipients.some(r=>r.user_id===recipientId&&r.fingerprint===u.key_fingerprint))throw Object.assign(new Error('Grant rejected: this file has no matching RSA key envelope for that recipient. Re-encrypt and upload with the recipient selected.'),{status:409});let r=f.recipients.find(x=>x.user_id===recipientId);r.permission=permission;r.granted_at=new Date().toISOString();let p=s.permissions.find(x=>x.file_id===fileId&&x.user_id===recipientId);if(p){p.permission=permission;p.active=true;}else s.permissions.push({file_id:fileId,user_id:recipientId,permission,active:true,created_at:r.granted_at});return {file_id:fileId,recipient_id:recipientId,permission};});await this.audit('permission.grant',outcome);return outcome;}
 async revoke(ownerId,fileId,recipientId){const outcome=await this.db.transaction(s=>{const f=s.files.find(x=>x.id===fileId&&x.owner_id===ownerId);if(!f)throw Object.assign(new Error('Owned file not found.'),{status:404});const r=f.recipients.find(x=>x.user_id===recipientId);if(!r||r.permission==='owner')throw Object.assign(new Error('Active recipient permission not found.'),{status:404});r.permission='revoked';r.revoked_at=new Date().toISOString();const p=s.permissions.find(x=>x.file_id===fileId&&x.user_id===recipientId);if(p){p.active=false;p.revoked_at=r.revoked_at;}return {file_id:fileId,recipient_id:recipientId,revoked:true};});await this.audit('permission.revoke',outcome);return outcome;}
 async remove(user,fileId){const result=await this.db.transaction(s=>{const i=s.files.findIndex(f=>f.id===fileId&&f.owner_id===user.id);if(i<0)throw Object.assign(new Error('Owned file not found.'),{status:404});const [f]=s.files.splice(i,1);s.permissions=s.permissions.filter(p=>p.file_id!==fileId);s.share_links=(s.share_links||[]).filter(l=>l.file_id!==fileId);return f;});await unlink(join(this.storage,result.stored_name));await this.audit('file.delete',{file_id:fileId,owner_id:user.id});return {removed:true,id:fileId};}

 async createPreviewLink(ownerId,fileId,expiresInDays=7){
  if(!Number.isInteger(expiresInDays)||expiresInDays<1||expiresInDays>30)throw Object.assign(new Error('Preview links must expire in 1–30 days.'),{status:400});
  const {file,user}=await this.db.view(s=>({file:s.files.find(f=>f.id===fileId&&f.owner_id===ownerId),user:s.users.find(u=>u.id===ownerId)}));
  if(!file||!user?.key_fingerprint)throw Object.assign(new Error('Owned file or registered owner key not found.'),{status:404});
  const stored=String(file.stored_name||'');if(!stored||basename(stored)!==stored||stored==='.'||stored==='..')throw Object.assign(new Error('Unsafe encrypted file storage reference.'),{status:409});const target=resolve(this.storage,stored);if(!target.startsWith(resolve(this.storage)+sep))throw Object.assign(new Error('Encrypted file storage reference is outside the storage directory.'),{status:409});const raw=await readFile(target);
  if(file.encrypted_size!==undefined&&raw.length!==file.encrypted_size)throw Object.assign(new Error('Stored encrypted file size does not match metadata.'),{status:409});
  if(file.encrypted_sha256&&createHash('sha256').update(raw).digest('hex')!==file.encrypted_sha256)throw Object.assign(new Error('Stored encrypted file checksum mismatch.'),{status:409});
  const {version,envelope}=inspectEnvelope(raw);
  const hasOwnerEnvelope=version===2&&Array.isArray(envelope.recipients)&&envelope.recipients.some(r=>r.user_id===ownerId&&r.fingerprint===user.key_fingerprint&&typeof r.wrapped_key==='string');
  if(!hasOwnerEnvelope)throw Object.assign(new Error('This file has no matching RSA envelope for your registered key; a preview link cannot be created.'),{status:409});
  const secret=token(),linkId=id(),createdAt=new Date(),expiresAt=new Date(createdAt.getTime()+expiresInDays*86400000).toISOString();
  await this.db.transaction(s=>{s.share_links=s.share_links||[];s.share_links.push({id:linkId,file_id:fileId,token_hash:createHash('sha256').update(secret).digest('hex'),created_by:ownerId,created_at:createdAt.toISOString(),expires_at:expiresAt,revoked:false});});
  await this.audit('preview_link.create',{file_id:fileId,link_id:linkId,owner_id:ownerId,expires_at:expiresAt});
  return {link_id:linkId,token:secret,expires_at:expiresAt};
 }
 async revokePreviewLink(ownerId,fileId,linkId){
  const result=await this.db.transaction(s=>{const file=s.files.find(f=>f.id===fileId&&f.owner_id===ownerId);if(!file)throw Object.assign(new Error('Owned file not found.'),{status:404});const link=(s.share_links||[]).find(l=>l.id===linkId&&l.file_id===fileId);if(!link)throw Object.assign(new Error('Preview link not found.'),{status:404});if(!link.revoked){link.revoked=true;link.revoked_at=new Date().toISOString();}return {file_id:fileId,link_id:linkId,revoked:true};});
  await this.audit('preview_link.revoke',{file_id:fileId,link_id:linkId,owner_id:ownerId});return result;
 }
 async publicPreview(secret){
  if(typeof secret!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(secret))throw Object.assign(new Error('Preview link not found or expired.'),{status:404});
  const hash=createHash('sha256').update(secret).digest('hex');
  const record=await this.db.view(s=>{const link=(s.share_links||[]).find(l=>l.token_hash===hash&&!l.revoked&&Date.parse(l.expires_at)>Date.now());if(!link)return null;const file=s.files.find(f=>f.id===link.file_id);return file?{link,file}:null;});
  if(!record)throw Object.assign(new Error('Preview link not found or expired.'),{status:404});
  const stored=String(record.file.stored_name||'');if(!stored||basename(stored)!==stored||stored==='.'||stored==='..')throw Object.assign(new Error('Unsafe encrypted file storage reference.'),{status:409});const target=resolve(this.storage,stored);if(!target.startsWith(resolve(this.storage)+sep))throw Object.assign(new Error('Encrypted file storage reference is outside the storage directory.'),{status:409});const raw=await readFile(target);
  if(record.file.encrypted_size!==undefined&&raw.length!==record.file.encrypted_size)throw Object.assign(new Error('Stored encrypted file size mismatch.'),{status:409});
  if(record.file.encrypted_sha256&&createHash('sha256').update(raw).digest('hex')!==record.file.encrypted_sha256)throw Object.assign(new Error('Stored encrypted file checksum mismatch.'),{status:409});
  inspectEnvelope(raw);
  await this.audit('preview_link.access',{file_id:record.file.id,link_id:record.link.id});
  return {name:record.file.name,data:raw};
 }
}
