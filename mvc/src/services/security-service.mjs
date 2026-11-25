import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt=promisify(scryptCb);
export const hashPassword=async(password)=>{if(typeof password!=='string'||password.length<12||password.length>200)throw Object.assign(new Error('Password must be 12–200 characters.'),{status:400});const salt=randomBytes(16),derived=await scrypt(password,salt,64,{N:16384,r:8,p:1});return `scrypt$16384$8$1$${salt.toString('base64')}$${derived.toString('base64')}`;};
export const verifyPassword=async(password,stored)=>{try{if(typeof password!=='string'||password.length<1||password.length>200)return false;const [alg,n,r,p,salt,hash]=stored.split('$');if(alg!=='scrypt')return false;const expected=Buffer.from(hash,'base64'),actual=await scrypt(password,Buffer.from(salt,'base64'),expected.length,{N:Number(n),r:Number(r),p:Number(p)});return actual.length===expected.length&&timingSafeEqual(actual,expected);}catch{return false;}};
export const token=()=>randomBytes(32).toString('base64url');
export const id=()=>randomBytes(16).toString('hex');
export const sha256=(v)=>createHash('sha256').update(v).digest('hex');
export function normalizeEmail(v){const e=String(v||'').trim().toLowerCase();if(e.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))throw Object.assign(new Error('Enter a valid email address.'),{status:400});return e;}
