// Pancha Pakshi Clock: server side. Runs as a Netlify Function (v2) and keeps all data in Netlify Blobs.
// Required environment variables: ADMIN_USER, ADMIN_PASSWORD, SESSION_SECRET (32+ random characters).
import crypto from 'node:crypto';

export const config = { path: '/api/*' };

const ADMIN_TTL = 12 * 3600, CLIENT_TTL = 14 * 86400, MAX_BODY = 4 * 1024 * 1024, MAX_PEOPLE = 300;
const USER_RE = /^[a-z0-9._@-]{3,32}$/, CLIENT_RE = /^[a-z0-9_-]{3,24}$/, DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const b64u = (b) => Buffer.from(b).toString('base64url');
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 32, (e, k) => (e ? rej(e) : res(k.toString('hex')))));
const normPass = (x) => String(x || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const pwKinds = (p) => (/[a-z]/.test(p) ? 1 : 0) + (/[A-Z]/.test(p) ? 1 : 0) + (/\d/.test(p) ? 1 : 0) + (/[^A-Za-z0-9]/.test(p) ? 1 : 0);
const str = (v, n) => String(v === undefined || v === null ? '' : v).slice(0, n);
const num = (v, lo, hi, d) => { const n = typeof v === 'number' ? v : parseInt(v, 10); return Number.isFinite(n) && n >= lo && n <= hi ? Math.trunc(n) : d; };

/* ---------- storage ---------- */
export function memoryStore() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
    async set(k, v) { m.set(k, JSON.stringify(v)); },
    async del(k) { m.delete(k); },
    async list(p) { return [...m.keys()].filter((k) => k.startsWith(p)); },
    _dump: m,
  };
}
async function blobsStore() {
  const { getStore } = await import('@netlify/blobs');
  const s = getStore({ name: 'pancha-pakshi', consistency: 'strong' });
  return {
    get: (k) => s.get(k, { type: 'json' }),
    set: (k, v) => s.setJSON(k, v),
    del: (k) => s.delete(k),
    async list(p) { const out = []; for await (const page of s.list({ prefix: p, paginate: true })) page.blobs.forEach((b) => out.push(b.key)); return out; },
  };
}

/* ---------- sanitising what the admin app stores ---------- */
function cleanBirth(b) {
  b = b && typeof b === 'object' ? b : {};
  const o = { method: str(b.method, 10), phase: str(b.phase, 4), nak: num(b.nak, 0, 26, 0), letter: num(b.letter, 0, 4, 0), tithi: num(b.tithi, 0, 14, 0), rasi: num(b.rasi, 0, 11, 0), weekday: num(b.weekday, 0, 6, 0),
    dobVia: str(b.dobVia, 10), dobDate: DATE_RE.test(b.dobDate || '') ? b.dobDate : '', dobTime: /^\d{2}:\d{2}$/.test(b.dobTime || '') ? b.dobTime : '12:00', placeId: str(b.placeId, 40), dobLetter: num(b.dobLetter, -1, 4, -1) };
  const c = b.custom && typeof b.custom === 'object' ? b.custom : {};
  o.custom = { name: str(c.name, 40), lat: str(c.lat, 12), lon: str(c.lon, 12), offH: str(c.offH, 8) };
  return o;
}
function cleanPerson(x) {
  if (!x || typeof x !== 'object' || typeof x.id !== 'string' || !x.id || !x.birth || typeof x.birth !== 'object') return null;
  const ac = x.acct && typeof x.acct === 'object' && CLIENT_RE.test(String(x.acct.user || '')) ? { user: String(x.acct.user), ex: num(x.acct.ex, 0, 4102444800000, 0) } : null;
  const sh = x.share && typeof x.share === 'object' ? { notes: x.share.notes !== false, plan: x.share.plan !== false, hora: x.share.hora !== false } : null;
  return { id: x.id.slice(0, 40), name: str(x.name, 60), birth: cleanBirth(x.birth), phone: str(x.phone, 60), tags: str(x.tags, 100), follow: DATE_RE.test(x.follow || '') ? x.follow : '',
    created: num(x.created, 0, 4102444800000, 0), status: ['new', 'active', 'follow', 'closed'].includes(x.status) ? x.status : 'new', acct: ac, share: sh,
    notes: (Array.isArray(x.notes) ? x.notes : []).filter((n) => n && typeof n.text === 'string').slice(0, 200).map((n) => ({ id: str(n.id || ('n' + crypto.randomBytes(3).toString('hex')), 20), ts: num(n.ts, 0, 4102444800000, 0), text: n.text.slice(0, 2000), shared: !!n.shared, kind: ['consult', 'call', 'message', 'followup'].includes(n.kind) ? n.kind : 'consult' })) };
}
function cleanState(s) {
  if (!s || typeof s !== 'object' || !Array.isArray(s.people) || s.people.length > MAX_PEOPLE) return null;
  const people = [], seen = new Set(), users = new Set();
  for (const x of s.people) {
    const p = cleanPerson(x); if (!p || seen.has(p.id)) continue; seen.add(p.id);
    if (p.acct) { if (users.has(p.acct.user)) return null; users.add(p.acct.user); }
    people.push(p);
  }
  const a = s.admin && typeof s.admin === 'object' ? s.admin : {}, cv = a.cv && typeof a.cv === 'object' ? a.cv : {};
  return { birth: cleanBirth(s.birth), personal: !!s.personal, people, activeId: seen.has(s.activeId) ? s.activeId : null, pPerson: seen.has(s.pPerson) ? s.pPerson : '',
    admin: { biz: str(a.biz, 60), contact: str(a.contact, 80), cv: { notes: cv.notes !== false, plan: cv.plan !== false, hora: cv.hora !== false }, autoLock: [0, 5, 15, 30, 60].includes(a.autoLock) ? a.autoLock : 15, lastBackup: num(a.lastBackup, 0, 4102444800000, 0) } };
}
function cleanView(v) {
  if (!v || typeof v !== 'object' || v.v !== 1 || !v.b || typeof v.b !== 'object') return null;
  const o = v.o && typeof v.o === 'object' ? v.o : {};
  return { v: 1, n: str(v.n, 60), b: cleanBirth(v.b), l: v.l === 'ta' ? 'ta' : 'en', bz: str(v.bz, 60), ct: str(v.ct, 80), o: { n: o.n ? 1 : 0, p: o.p ? 1 : 0, h: o.h ? 1 : 0 },
    nt: (Array.isArray(v.nt) ? v.nt : []).slice(0, 30).map((n) => ({ t: str(n && n.t, 500), d: num(n && n.d, 0, 4102444800000, 0), k: ['consult', 'call', 'message', 'followup'].includes(n && n.k) ? n.k : 'consult' })),
    ts: num(v.ts, 0, 4102444800000, 0), ex: num(v.ex, 0, 4102444800000, 0) };
}
const maskView = (v) => (v.ex > 0 && Date.now() > v.ex ? { v: 1, n: v.n, b: {}, l: v.l, bz: v.bz, ct: v.ct, o: { n: 0, p: 0, h: 0 }, nt: [], ts: v.ts, ex: v.ex } : v);

/* ---------- handler ---------- */
export function createHandler(getStore, env = process.env) {
  let storeP = null;
  const store = () => (storeP = storeP || Promise.resolve(getStore()));
  const out = (status, body, headers) => new Response(JSON.stringify(body), { status, headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }, headers || {}) });
  const cfg = () => {
    const user = String(env.ADMIN_USER || '').trim().toLowerCase(), pass = String(env.ADMIN_PASSWORD || ''), secret = String(env.SESSION_SECRET || '');
    return USER_RE.test(user) && pass.length >= 8 && secret.length >= 32 ? { user, pass, secret, fp: sha(user + '\n' + pass).slice(0, 24) } : null;
  };
  const sign = (c, data) => crypto.createHmac('sha256', c.secret).update(data).digest('base64url');
  const issue = (c, role, user, gen, ttl, secure) => {
    const body = b64u(JSON.stringify({ r: role, u: user, g: gen, e: Math.floor(Date.now() / 1000) + ttl }));
    return `pp_s=${body}.${sign(c, body)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ttl}${secure ? '; Secure' : ''}`;
  };
  const clearCookie = (secure) => `pp_s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`;
  const readToken = (req, c) => {
    const m = /(?:^|;\s*)pp_s=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)/.exec(req.headers.get('cookie') || '');
    if (!m || !eq(sign(c, m[1]), m[2])) return null;
    try { const t = JSON.parse(Buffer.from(m[1], 'base64url').toString()); return t && t.e > Date.now() / 1000 && (t.r === 'a' || t.r === 'c') && typeof t.u === 'string' ? t : null; } catch (e) { return null; }
  };
  // The admin credential is the environment variable unless the admin changed it in the app and the variable has not changed since.
  async function adminCred(s, c) {
    const ov = await s.get('admin-cred');
    if (ov && ov.fp === c.fp && USER_RE.test(ov.user || '')) return { user: ov.user, gen: ov.g, ov };
    return { user: c.user, gen: c.fp.slice(0, 12), ov: null };
  }
  async function checkAdminPw(c, ad, pw) {
    if (ad.ov) return eq(await scrypt(String(pw), ad.ov.salt), ad.ov.hash);
    return eq(sha(pw), sha(c.pass));
  }
  async function limited(s, keys) {
    const now = Date.now(); let wait = 0;
    for (const k of keys) { const r = await s.get('rl/' + k); if (r && r.until > now) wait = Math.max(wait, Math.ceil((r.until - now) / 1000)); }
    return wait;
  }
  async function noteFail(s, keys, limit) {
    const now = Date.now();
    for (const [i, k] of keys.entries()) { const r = (await s.get('rl/' + k)) || { n: 0, until: 0 }; r.n++; const lim = limit[i]; if (r.n >= lim) r.until = now + 30000 * Math.min(8, r.n - lim + 1); r.at = now; await s.set('rl/' + k, r); }
  }
  async function clearFail(s, k) { await s.del('rl/' + k); }
  async function readJson(req) {
    const txt = await req.text();
    if (txt.length > MAX_BODY) throw Object.assign(new Error('big'), { code: 413 });
    try { const j = JSON.parse(txt || '{}'); return j && typeof j === 'object' ? j : {}; } catch (e) { throw Object.assign(new Error('bad'), { code: 400 }); }
  }
  async function session(req, s, c) {
    const t = readToken(req, c); if (!t) return null;
    if (t.r === 'a') { const ad = await adminCred(s, c); return t.u === ad.user && t.g === ad.gen ? { role: 'admin', user: ad.user, ad } : null; }
    const rec = await s.get('acct/' + t.u); return rec && rec.g === t.g ? { role: 'client', user: t.u, rec } : null;
  }

  return async function handler(req, context) {
    const url = new URL(req.url), path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, ''), method = req.method.toUpperCase();
    const secure = url.protocol === 'https:';
    const ip = (context && context.ip) || req.headers.get('x-nf-client-connection-ip') || 'x';
    try {
      const c = cfg();
      if (!c) return out(503, { error: 'config' });
      const s = await store();
      if (method !== 'GET') {
        if (req.headers.get('x-pp') !== '1') return out(403, { error: 'csrf' });
        const o = req.headers.get('origin'); if (o) { try { if (new URL(o).host !== url.host) return out(403, { error: 'csrf' }); } catch (e) { return out(403, { error: 'csrf' }); } }
      }
      if (path === 'public' && method === 'GET') { const st = await s.get('state'); return out(200, { ok: true, biz: st && st.state && st.state.admin ? st.state.admin.biz : '' }); }
      if (path === 'me' && method === 'GET') {
        const ss = await session(req, s, c);
        if (!ss) return out(200, { role: null });
        if (ss.role === 'admin') return out(200, { role: 'admin', user: ss.user });
        const v = await s.get('view/' + ss.user); return out(200, { role: 'client', view: v ? maskView(v) : null });
      }
      if (path === 'login' && method === 'POST') {
        const b = await readJson(req), user = String(b.user || '').trim().toLowerCase().slice(0, 64), pw = String(b.pass || '').slice(0, 200);
        const keys = ['u/' + sha(user), 'ip/' + sha(ip)];
        const wait = await limited(s, keys); if (wait) return out(429, { error: 'wait', seconds: wait });
        const ad = await adminCred(s, c);
        let ok = null;
        if (user && user === ad.user) {
          if (!ad.ov) await scrypt('x', 'dummy-salt-0000');
          if (await checkAdminPw(c, ad, pw)) { await clearFail(s, keys[0]); return out(200, { role: 'admin', user: ad.user }, { 'set-cookie': issue(c, 'a', ad.user, ad.gen, ADMIN_TTL, secure) }); }
        } else if (CLIENT_RE.test(user)) {
          const rec = await s.get('acct/' + user), np = normPass(pw);
          const h = await scrypt(np.length === 8 ? np : 'x', rec ? rec.salt : 'dummy-salt-0000');
          if (rec && np.length === 8 && eq(h, rec.hash)) ok = rec;
          if (ok) {
            await clearFail(s, keys[0]);
            const v = await s.get('view/' + user);
            return out(200, { role: 'client', view: v ? maskView(v) : null }, { 'set-cookie': issue(c, 'c', user, ok.g, CLIENT_TTL, secure) });
          }
        } else { await scrypt('x', 'dummy-salt-0000'); }
        await noteFail(s, keys, [5, 15]);
        return out(401, { error: 'bad' });
      }
      if (path === 'logout' && method === 'POST') return out(200, { ok: true }, { 'set-cookie': clearCookie(secure) });
      const ss = await session(req, s, c);
      if (path === 'view' && method === 'GET') {
        if (!ss || ss.role !== 'client') return out(401, { error: 'auth' });
        const v = await s.get('view/' + ss.user); return out(200, { view: v ? maskView(v) : null });
      }
      if (!ss || ss.role !== 'admin') return out(401, { error: 'auth' });
      if (path === 'state' && method === 'GET') {
        const st = await s.get('state'); const live = new Set((await s.list('acct/')).map((k) => k.slice(5)));
        return out(200, { rev: st ? st.rev : 0, state: st ? st.state : null, live: [...live] });
      }
      if (path === 'state' && method === 'PUT') {
        const b = await readJson(req), cur = (await s.get('state')) || { rev: 0, state: null };
        if (b.rev !== cur.rev) return out(409, { error: 'rev', rev: cur.rev });
        const st = cleanState(b.state); if (!st) return out(400, { error: 'state' });
        const users = new Map(); st.people.forEach((p) => { if (p.acct) users.set(p.acct.user, p.id); });
        if (users.has(ss.user)) return out(409, { error: 'dup', user: ss.user });
        const recs = new Map();
        for (const [u, pid] of users) { const r = await s.get('acct/' + u); if (r && r.pid !== pid) return out(409, { error: 'dup', user: u }); if (r) recs.set(u, r); }
        const creds = b.creds && typeof b.creds === 'object' ? b.creds : {};
        for (const [u, pw] of Object.entries(creds)) { if (users.has(u) && normPass(pw).length !== 8) return out(400, { error: 'cred' }); }
        for (const [u, pw] of Object.entries(creds)) {
          if (!users.has(u)) continue;
          const salt = crypto.randomBytes(12).toString('hex'), rec = { pid: users.get(u), salt, hash: await scrypt(normPass(pw), salt), g: crypto.randomBytes(6).toString('hex') };
          await s.set('acct/' + u, rec); recs.set(u, rec);
        }
        for (const k of await s.list('acct/')) { const u = k.slice(5); if (!users.has(u)) { await s.del(k); await s.del('view/' + u); } }
        const views = b.views && typeof b.views === 'object' ? b.views : {};
        for (const [u, v] of Object.entries(views)) { if (!recs.has(u)) continue; const cv = cleanView(v); if (cv) await s.set('view/' + u, cv); }
        const rev = cur.rev + 1; await s.set('state', { rev, state: st });
        return out(200, { rev, live: [...recs.keys()] });
      }
      if (path === 'credentials' && method === 'POST') {
        const b = await readJson(req), keys = ['u/' + sha(ss.user), 'ip/' + sha(ip)];
        const wait = await limited(s, keys); if (wait) return out(429, { error: 'wait', seconds: wait });
        if (!(await checkAdminPw(c, ss.ad, String(b.old || '')))) { await noteFail(s, keys, [5, 15]); return out(401, { error: 'bad' }); }
        const user = String(b.user || '').trim().toLowerCase(), pw = String(b.pw || '');
        if (!USER_RE.test(user)) return out(400, { error: 'user' });
        if (pw.length < 8 || pwKinds(pw) < 2 || pw.toLowerCase().includes(user)) return out(400, { error: 'pw' });
        if (user !== ss.user && (await s.get('acct/' + user))) return out(409, { error: 'dup' });
        const salt = crypto.randomBytes(12).toString('hex'), g = crypto.randomBytes(6).toString('hex');
        await s.set('admin-cred', { user, salt, hash: await scrypt(pw, salt), fp: c.fp, g });
        await clearFail(s, keys[0]);
        return out(200, { ok: true, user }, { 'set-cookie': issue(c, 'a', user, g, ADMIN_TTL, secure) });
      }
      if (path === 'wipe' && method === 'POST') {
        for (const k of [...(await s.list('acct/')), ...(await s.list('view/'))]) await s.del(k);
        await s.del('state');
        return out(200, { ok: true });
      }
      return out(404, { error: 'none' });
    } catch (e) {
      if (e && e.code === 413) return out(413, { error: 'big' });
      if (e && e.code === 400) return out(400, { error: 'json' });
      return out(500, { error: 'server' });
    }
  };
}

export default async (req, context) => createHandler(blobsStore)(req, context);
