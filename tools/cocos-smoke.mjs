import { createHmac } from 'node:crypto';

const env = (k) => {
  const v = process.env[k]?.trim();
  if (!v) throw new Error('Missing env: ' + k);
  return v;
};
const email = env('EMAIL'), password = env('PASSWORD');
const secret = env('TOTP_SECRET'), account = env('USER_ACCOUNT');
const auth = env('EXPO_PUBLIC_AUTH_URL').replace(/\/$/, '');
const api = env('EXPO_PUBLIC_API_URL').replace(/\/$/, '');
const anon = env('EXPO_PUBLIC_SUPABASE_ANON_KEY');
if (!/^\d+$/.test(account)) throw new Error('Invalid USER_ACCOUNT');
const headers = (token = anon, withAccount = false) => ({
  apikey: anon, Authorization: 'Bearer ' + token,
  'Content-Type': 'application/json',
  'x-store-version': process.env.API_STORE_VERSION || '1.0.0',
  'x-platform': process.env.API_PLATFORM || 'web',
  'x-app-flavor': process.env.API_APP_FLAVOR || 'CAPITAL',
  'x-update-id': '',
  ...(withAccount ? {'x-Account-ID': account} : {}),
});
async function request(url, { method = 'GET', token, body, withAccount = false } = {}) {
  const response = await fetch(url, {
    method, headers: headers(token, withAccount),
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) throw new Error('HTTP ' + response.status);
  return response.json();
}
function base32(value) {
  const s = value.toUpperCase().replace(/[\s=-]/g,'');
  if (!s || /[^A-Z2-7]/.test(s)) throw new Error('Invalid TOTP secret');
  let bits = 0, num = 0;
  const bytes = [];
  for (const c of s) {
    num = (num << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);
    bits += 5;
    if (bits >= 8) { bytes.push((num >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes);
}
async function getTotp() {
  const remaining = 30000 - Date.now() % 30000;
  if (remaining < 5000) await new Promise(r => setTimeout(r, remaining + 100));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));
  const mac = createHmac('sha1', base32(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6,'0');
}
function shape(data) {
  if (Array.isArray(data)) return {type:'array', count:data.length};
  if (data && typeof data === 'object')
    return {type:'object', keys:Object.keys(data).slice(0,30)};
  return {type: typeof data};
}
try {
  console.log('Stage 1: login');
  const first = await request(auth + '/auth/v1/token?grant_type=password',
    {method:'POST', body:{email,password}});
  if (!first?.access_token) throw new Error('Missing stage 1 access token');
  console.log('Stage 2: MFA');
  const factor = await request(auth + '/auth/v1/factors/default',
    {token:first.access_token});
  const factorId = factor?.factor_type === 'totp'
    ? factor?.id : (factor?.factor_type ?? factor?.id);
  if (!factorId || typeof factorId !== 'string') throw new Error('Missing factor');
  const path = auth + '/auth/v1/factors/' + encodeURIComponent(factorId);
  const challenge = await request(path + '/challenge',
    {method:'POST', token:first.access_token, body:{}});
  if (!challenge?.id) throw new Error('Missing challenge');
  const verified = await request(path + '/verify', {
    method:'POST', token:first.access_token,
    body:{challenge_id:challenge.id, code:await getTotp()},
  });
  const session = verified?.access_token
    ? verified : (verified?.data?.session ?? verified?.session ?? verified);
  if (!session?.access_token) throw new Error('Missing stage 2 access token');
  console.log('Authentication successful');

  const endpoints = {
    me: '/api/v2/users/me',
    balance: '/api/portfolio/balance?currency=ARS&period=MAX',
    portfolio: '/api/v2/portfolio?period=MAX&domain=BROKER&include=costBasis,allocation,cash',
    history: '/api/portfolio/history?currency=ARS&period=MAX&metric=balance',
    movements: '/api/movements?limit=30&sort_by=execution_date&offset=0',
  };
  let failure = false;
  for (const [name, endpoint] of Object.entries(endpoints)) {
    try {
      const result = await request(api + endpoint,
        {token:session.access_token, withAccount:true});
      console.log(name + ': OK ' + JSON.stringify(shape(result)));
    } catch(e) {
      console.log(name + ': FAILED ' + e.message);
      failure = true;
    }
  }
  if (failure) process.exitCode = 1;
} catch (e) {
  console.error('Smoke test failed: ' + e.message);
  process.exitCode = 1;
}
