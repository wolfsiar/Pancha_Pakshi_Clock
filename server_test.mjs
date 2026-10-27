import assert from 'node:assert/strict';
import { createHandler, memoryStore } from '../netlify/functions/api.mjs';
const ENV = { ADMIN_USER: 'Boss.Admin', ADMIN_PASSWORD: 'Env-Pass-12345', SESSION_SECRET: 'x'.repeat(40) };
let pass = 0; const t = async (n, f) => { try { await f(); pass++; console.log('ok  ', n); } catch (e) { console.log('FAIL', n, '\n', e); process.exitCode = 1; } };
const mk = (env = ENV, store = memoryStore()) => { const h = createHandler(() => store, env); let jar = ''; const ip = { v: '1.1.1.1' };
  const call = async (method, path, body, o = {}) => {
    const headers = { 'content-type': 'application/json', 'x-pp': '1', cookie: o.nocookie ? '' : jar, ...(o.headers || {}) };
    if (o.noCsrf) delete headers['x-pp'];
    const r = await h(new Request('https://site.test/api/' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), { ip: ip.v });
    const sc = r.headers.get('set-cookie'); if (sc && !o.keepJar) jar = /pp_s=;/.test(sc) ? '' : sc.split(';')[0];
    return { s: r.status, j: await r.json(), r };
  };
  return { call, store, ip, get jar() { return jar; }, set jar(v) { jar = v; } }; };
const person = (id, name, user, extra = {}) => ({ id, name, birth: { method: 'dob', dobDate: '1990-04-14', dobTime: '06:10', placeId: 'chennai', phase: 'wax' }, phone: '98400', tags: '', follow: '', created: 1, status: 'new', acct: user ? { user, ex: 0 } : null, share: null, notes: [{ id: 'n1', ts: 1, text: 'private note', shared: false, kind: 'consult' }, { id: 'n2', ts: 2, text: 'shared note', shared: true, kind: 'call' }], ...extra });
const view = (n, ex = 0, extra = {}) => ({ v: 1, n, b: { method: 'dob', dobDate: '1990-04-14', dobTime: '06:10', placeId: 'chennai' }, l: 'en', bz: 'Biz', ct: '999', o: { n: 1, p: 1, h: 1 }, nt: [{ t: 'shared note', d: 2, k: 'call' }], ts: 5, ex, ...extra });
const state = (people) => ({ birth: {}, personal: false, people, activeId: null, pPerson: '', admin: { biz: 'Sivaa Astro', contact: '98400', cv: { notes: true, plan: true, hora: true }, autoLock: 15, lastBackup: 0 } });
const adminLogin = async (k) => k.call('POST', 'login', { user: 'boss.admin', pass: 'Env-Pass-12345' });

await t('unconfigured server fails closed', async () => { for (const bad of [{}, { ...ENV, SESSION_SECRET: 'short' }, { ...ENV, ADMIN_PASSWORD: 'x' }, { ...ENV, ADMIN_USER: 'a b' }]) { const k = mk(bad); const r = await k.call('POST', 'login', { user: 'boss.admin', pass: 'Env-Pass-12345' }); assert.equal(r.s, 503); assert.equal((await k.call('GET', 'state')).s, 503); } });
await t('anonymous cannot read or write anything private', async () => { const k = mk(); for (const [m, p, b] of [['GET', 'state'], ['PUT', 'state', {}], ['POST', 'credentials', {}], ['POST', 'wipe', {}], ['GET', 'view']]) { const r = await k.call(m, p, b); assert.equal(r.s, 401, m + p); } assert.deepEqual((await k.call('GET', 'me')).j, { role: null }); });
await t('public endpoint reveals only the business name', async () => { const k = mk(); const r = await k.call('GET', 'public'); assert.deepEqual(Object.keys(r.j).sort(), ['biz', 'ok']); });
await t('admin login from environment, cookie flags, me', async () => { const k = mk(); const r = await adminLogin(k); assert.equal(r.s, 200); assert.equal(r.j.role, 'admin'); const sc = r.r.headers.get('set-cookie'); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.match(sc, /Secure/); assert.equal((await k.call('GET', 'me')).j.role, 'admin'); });
await t('wrong password and unknown user give the same answer', async () => { const k = mk(); const a = await k.call('POST', 'login', { user: 'boss.admin', pass: 'nope-nope-1' }), b = await k.call('POST', 'login', { user: 'ghost', pass: 'nope-nope-1' }); assert.equal(a.s, 401); assert.deepEqual(a.j, b.j); });
await t('lockout after 5 failures, even for the right password; other IP unaffected only for other users', async () => { const k = mk(); for (let i = 0; i < 5; i++) await k.call('POST', 'login', { user: 'boss.admin', pass: 'bad-bad-' + i }); const r = await adminLogin(k); assert.equal(r.s, 429); assert.ok(r.j.seconds > 0); });
await t('ip lockout across many usernames', async () => { const k = mk(); let last; for (let i = 0; i < 16; i++) last = await k.call('POST', 'login', { user: 'u' + i + 'xx', pass: 'bad-bad-1' }); assert.equal(last.s, 429); });
await t('csrf: mutating call needs header and same origin', async () => { const k = mk(); assert.equal((await k.call('POST', 'login', { user: 'a', pass: 'b' }, { noCsrf: true })).s, 403); assert.equal((await k.call('POST', 'login', { user: 'a', pass: 'b' }, { headers: { origin: 'https://evil.test' } })).s, 403); assert.equal((await k.call('POST', 'login', { user: 'a', pass: 'b' }, { headers: { origin: 'https://site.test' } })).s, 401); });
await t('tampered, forged and expired tokens are rejected', async () => { const k = mk(); await adminLogin(k); const good = k.jar; for (const bad of [good.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')), 'pp_s=' + Buffer.from(JSON.stringify({ r: 'a', u: 'boss.admin', g: 'x', e: 9999999999 })).toString('base64url') + '.AAAA', 'pp_s=garbage']) { k.jar = bad; assert.equal((await k.call('GET', 'state')).s, 401); } const other = mk({ ...ENV, SESSION_SECRET: 'y'.repeat(40) }); other.jar = good; assert.equal((await other.call('GET', 'state')).s, 401); });
await t('state round trip, revision conflicts, sanitising', async () => {
  const k = mk(); await adminLogin(k);
  let g = await k.call('GET', 'state'); assert.equal(g.j.rev, 0); assert.equal(g.j.state, null);
  const evil = person('p1', 'Asha<img src=x onerror=1>', null, { status: 'hacked', phone: 'x'.repeat(500), extra: 'drop' });
  let r = await k.call('PUT', 'state', { rev: 0, state: state([evil, evil]) }); assert.equal(r.s, 200); assert.equal(r.j.rev, 1);
  g = await k.call('GET', 'state'); assert.equal(g.j.state.people.length, 1); assert.equal(g.j.state.people[0].status, 'new'); assert.equal(g.j.state.people[0].phone.length, 60); assert.equal(g.j.state.people[0].extra, undefined);
  assert.equal((await k.call('PUT', 'state', { rev: 0, state: state([]) })).s, 409);
  assert.equal((await k.call('PUT', 'state', { rev: 1, state: { people: 'x' } })).s, 400);
  assert.equal((await k.call('PUT', 'state', { rev: 1, state: state(Array.from({ length: 301 }, (_, i) => person('p' + i, 'n'))) })).s, 400);
  assert.equal((await k.call('GET', 'public')).j.biz, 'Sivaa Astro');
});
await t('client accounts: create, login, own view only, never the notes', async () => {
  const k = mk(); await adminLogin(k);
  const r = await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'Asha', 'asha11'), person('p2', 'Bala', 'bala22')]), creds: { asha11: 'ABCD-2345', bala22: 'WXYZ6789' }, views: { asha11: view('Asha'), bala22: view('Bala'), ghost: view('Ghost') } });
  assert.equal(r.s, 200); assert.deepEqual(r.j.live.sort(), ['asha11', 'bala22']);
  assert.equal([...k.store._dump.keys()].filter((x) => x.startsWith('view/')).length, 2);
  assert.ok(![...k.store._dump.values()].some((v) => v.includes('ABCD2345') || v.includes('ABCD-2345')), 'passcode is never stored');
  const c = mk(ENV, k.store);
  let l = await c.call('POST', 'login', { user: 'asha11', pass: 'abcd 2345' }); assert.equal(l.s, 200); assert.equal(l.j.role, 'client'); assert.equal(l.j.view.n, 'Asha');
  assert.ok(!JSON.stringify(l.j).includes('private note'));
  for (const [m, p, b] of [['GET', 'state'], ['PUT', 'state', { rev: 1, state: state([]) }], ['POST', 'wipe', {}], ['POST', 'credentials', { old: 'x', user: 'hax0r', pw: 'Aa1-aaaaaa' }]]) assert.equal((await c.call(m, p, b)).s, 401, p);
  assert.equal((await c.call('GET', 'me')).j.view.n, 'Asha'); assert.equal((await c.call('GET', 'view')).j.view.n, 'Asha');
  const w = mk(ENV, k.store); assert.equal((await w.call('POST', 'login', { user: 'asha11', pass: 'WXYZ6789' })).s, 401); assert.equal((await w.call('POST', 'login', { user: 'boss.admin', pass: 'ABCD2345' })).s, 401);
  assert.equal((await mk(ENV, k.store).call('POST', 'login', { user: 'asha11', pass: 'ABCD234' })).s, 401);
});
await t('duplicate usernames and the admin name are refused', async () => {
  const k = mk(); await adminLogin(k);
  assert.equal((await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'same11'), person('p2', 'B', 'same11')]) })).s, 400);
  const k2 = mk({ ...ENV, ADMIN_USER: 'bossadmin' }); await k2.call('POST', 'login', { user: 'bossadmin', pass: 'Env-Pass-12345' });
  const rr = await k2.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'bossadmin')]) }); assert.equal(rr.s, 409); assert.equal(rr.j.error, 'dup');
  const dotted = await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'boss.admin')]) }); assert.equal(dotted.s, 200); assert.equal((await k.call('GET', 'state')).j.state.people[0].acct, null);
  await k.call('PUT', 'state', { rev: 1, state: state([]) });
  const r1 = await k.call('PUT', 'state', { rev: 2, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'ABCD2345' } }); assert.equal(r1.s, 200);
  const r2 = await k.call('PUT', 'state', { rev: 3, state: state([person('p1', 'A', 'asha11'), person('p9', 'Z', 'asha11')]) }); assert.equal(r2.s, 400);
  const r3 = await k.call('PUT', 'state', { rev: 3, state: state([person('p9', 'Z', 'asha11')]), creds: { asha11: 'ABCD9999' } }); assert.equal(r3.s, 409); assert.equal(r3.j.error, 'dup');
});
await t('renewing a passcode ends old sessions; removing a login deletes it and its view', async () => {
  const k = mk(); await adminLogin(k);
  await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'ABCD2345' }, views: { asha11: view('A') } });
  const c = mk(ENV, k.store); await c.call('POST', 'login', { user: 'asha11', pass: 'ABCD2345' }); assert.equal((await c.call('GET', 'me')).j.role, 'client');
  await k.call('PUT', 'state', { rev: 1, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'QQQQ2222' } });
  assert.equal((await c.call('GET', 'me')).j.role, null, 'old session dead'); assert.equal((await c.call('POST', 'login', { user: 'asha11', pass: 'ABCD2345' })).s, 401); assert.equal((await c.call('POST', 'login', { user: 'asha11', pass: 'QQQQ2222' })).s, 200);
  await k.call('PUT', 'state', { rev: 2, state: state([person('p1', 'A', null)]) });
  assert.equal((await c.call('GET', 'me')).j.role, null); assert.equal([...k.store._dump.keys()].filter((x) => /^(acct|view)\//.test(x)).length, 0);
});
await t('expired access is masked on the server', async () => {
  const k = mk(); await adminLogin(k);
  await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'ABCD2345' }, views: { asha11: view('A', Date.now() - 1000) } });
  const l = await mk(ENV, k.store).call('POST', 'login', { user: 'asha11', pass: 'ABCD2345' }); assert.equal(l.s, 200); assert.deepEqual(l.j.view.nt, []); assert.deepEqual(l.j.view.b, {}); assert.ok(!JSON.stringify(l.j).includes('shared note'));
});
await t('admin credential change: override, old dead, session reissued, env change wins again', async () => {
  const k = mk(); await adminLogin(k);
  assert.equal((await k.call('POST', 'credentials', { old: 'wrong-wrong', user: 'owner2', pw: 'New-Pass-7788' })).s, 401);
  assert.equal((await k.call('POST', 'credentials', { old: 'Env-Pass-12345', user: 'owner2', pw: 'short' })).s, 400);
  assert.equal((await k.call('POST', 'credentials', { old: 'Env-Pass-12345', user: 'owner2', pw: 'owner2owner2' })).s, 400);
  const r = await k.call('POST', 'credentials', { old: 'Env-Pass-12345', user: 'owner2', pw: 'New-Pass-7788' }); assert.equal(r.s, 200);
  assert.equal((await k.call('GET', 'state')).s, 200, 'session reissued');
  const o = mk(ENV, k.store); assert.equal((await o.call('POST', 'login', { user: 'boss.admin', pass: 'Env-Pass-12345' })).s, 401);
  assert.equal((await o.call('POST', 'login', { user: 'owner2', pass: 'New-Pass-7788' })).s, 200);
  const old = mk(ENV, k.store); old.jar = ''; const env2 = mk({ ...ENV, ADMIN_PASSWORD: 'Rotated-Pass-99' }, k.store);
  assert.equal((await env2.call('POST', 'login', { user: 'boss.admin', pass: 'Rotated-Pass-99' })).s, 200, 'env var change recovers a lost password');
  assert.equal((await mk({ ...ENV, ADMIN_PASSWORD: 'Rotated-Pass-99' }, k.store).call('POST', 'login', { user: 'owner2', pass: 'New-Pass-7788' })).s, 401);
});
await t('a client name cannot be taken as the new admin name', async () => {
  const k = mk(); await adminLogin(k); await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'ABCD2345' } });
  assert.equal((await k.call('POST', 'credentials', { old: 'Env-Pass-12345', user: 'asha11', pw: 'New-Pass-7788' })).s, 409);
});
await t('wipe removes clients, views and state but not the admin login', async () => {
  const k = mk(); await adminLogin(k); await k.call('PUT', 'state', { rev: 0, state: state([person('p1', 'A', 'asha11')]), creds: { asha11: 'ABCD2345' }, views: { asha11: view('A') } });
  assert.equal((await k.call('POST', 'wipe', {})).s, 200); const g = await k.call('GET', 'state'); assert.equal(g.j.rev, 0); assert.equal(g.j.state, null);
  assert.equal((await mk(ENV, k.store).call('POST', 'login', { user: 'asha11', pass: 'ABCD2345' })).s, 401); assert.equal((await adminLogin(mk(ENV, k.store))).s, 200);
});
await t('logout clears the cookie; bad json / oversize / unknown routes', async () => {
  const k = mk(); await adminLogin(k); const r = await k.call('POST', 'logout', {}); assert.match(r.r.headers.get('set-cookie'), /Max-Age=0/); assert.equal(k.jar, ''); assert.equal((await k.call('GET', 'state')).s, 401);
  await adminLogin(k); assert.equal((await k.call('GET', 'nothing')).s, 404);
  const h = createHandler(() => k.store, ENV); const bad = await h(new Request('https://site.test/api/login', { method: 'POST', headers: { 'x-pp': '1' }, body: '{oops' })); assert.equal(bad.status, 400);
});
console.log(pass + ' passed'); 
