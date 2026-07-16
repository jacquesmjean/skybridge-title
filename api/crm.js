// Skybridge Title — Service Desk backend (zero external dependencies).
// Node built-ins only: `crypto` for password hashing + signed session cookies,
// global `fetch` for Upstash/Vercel KV (REST) and Resend email. No npm install,
// so a config gap never breaks the marketing site. All routes go through
// /api/crm?action=... to keep the whole backend in one serverless function.
const crypto = require('crypto');

const SESSION_HOURS = 12;
const COOKIE = 'sbsess';

function pbkdf2(pw, saltHex, iter) {
  return crypto.pbkdf2Sync(pw, Buffer.from(saltHex, 'hex'), iter, 32, 'sha256').toString('hex');
}
function verifyPw(pw, stored) {
  try {
    const [iter, salt, hash] = String(stored).split(':');
    const h = pbkdf2(pw, salt, parseInt(iter, 10));
    return h.length === hash.length &&
      crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
  } catch (_) { return false; }
}
function sign(obj, secret) {
  const b = Buffer.from(JSON.stringify(obj)).toString('base64url');
  const m = crypto.createHmac('sha256', secret).update(b).digest('base64url');
  return b + '.' + m;
}
function verifyTok(tok, secret) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const [b, m] = tok.split('.');
  const e = crypto.createHmac('sha256', secret).update(b).digest('base64url');
  if (e.length !== m.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(m))) return null;
  try {
    const o = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (o.exp && Date.now() > o.exp) return null;
    return o;
  } catch (_) { return null; }
}
function getCookie(req, name) {
  const c = req.headers.cookie || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function currentUser(req) {
  const s = process.env.PORTAL_SECRET;
  if (!s) return null;
  return verifyTok(getCookie(req, COOKIE), s);
}
async function kv(cmd) {
  const url = process.env.KV_REST_API_URL, tok = process.env.KV_REST_API_TOKEN;
  if (!url || !tok) return null;
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
      body: JSON.stringify(cmd)
    });
    return await r.json();
  } catch (_) { return null; }
}
async function sendEmail(subject, text) {
  const key = process.env.RESEND_API_KEY;
  if (!key) return;
  const to = (process.env.PORTAL_NOTIFY || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!to.length) return;
  const from = process.env.PORTAL_FROM || 'Skybridge Title <onboarding@resend.dev>';
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to, subject, text })
    });
  } catch (_) {}
}
function readBody(req) {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => (d += c));
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch (_) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
const S = (v, n) => String(v == null ? '' : v).slice(0, n);
const cleanDetails = (d) => { if (!d || typeof d !== 'object' || Array.isArray(d)) return undefined; const o = {}; let n = 0; for (const k in d) { if (n++ > 40) break; const v = S(d[k], 500); if (v) o[String(k).slice(0, 60)] = v; } return Object.keys(o).length ? o : undefined; };

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const action = (req.query && req.query.action) || '';
  try {
    if (action === 'me') {
      const u = currentUser(req);
      if (!u) return res.status(401).json({ error: 'unauthorized' });
      return res.status(200).json({ user: { email: u.email, name: u.name } });
    }

    if (action === 'login') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
      const secret = process.env.PORTAL_SECRET;
      let users = [];
      try { users = JSON.parse(process.env.PORTAL_USERS || '[]'); } catch (_) {}
      if (!secret || !users.length) return res.status(503).json({ error: 'Portal is not activated yet.' });
      const b = await readBody(req);
      const email = S(b.email, 160).trim().toLowerCase();
      const pw = S(b.password, 200);
      const u = users.find(x => String(x.email).toLowerCase() === email);
      if (!u || !verifyPw(pw, u.hash)) return res.status(401).json({ error: 'Invalid email or password.' });
      const tok = sign({ email: u.email, name: u.name || u.email, exp: Date.now() + SESSION_HOURS * 3600e3 }, secret);
      res.setHeader('Set-Cookie', COOKIE + '=' + encodeURIComponent(tok) + '; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=' + (SESSION_HOURS * 3600));
      return res.status(200).json({ ok: true, name: u.name || u.email });
    }

    if (action === 'logout') {
      res.setHeader('Set-Cookie', COOKIE + '=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0');
      return res.status(200).json({ ok: true });
    }

    if (action === 'submit') {
      if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
      const b = await readBody(req);
      if (b.company_hp) return res.status(200).json({ ok: true }); // honeypot
      const type = S(b.type, 24) || 'contact';
      const lead = {
        id: crypto.randomUUID(), ts: Date.now(),
        ref: (type === 'order') ? ('SB-' + Date.now().toString(36).toUpperCase().slice(-6)) : undefined,
        type, name: S(b.name, 120), email: S(b.email, 160),
        phone: S(b.phone, 60), company: S(b.company, 160), role: S(b.role, 60),
        area: S(b.area, 120), topic: S(b.topic, 120), message: S(b.message, 4000),
        details: cleanDetails(b.details),
        source: S(b.source, 80) || 'website', lang: S(b.lang, 8), status: 'new'
      };
      await kv(['SET', 'sb:lead:' + lead.id, JSON.stringify(lead)]);
      await kv(['LPUSH', 'sb:leadids', lead.id]);
      await kv(['LTRIM', 'sb:leadids', 0, 9999]);
      const detailLines = lead.details ? Object.keys(lead.details).map(k => k + ': ' + lead.details[k]) : [];
      await sendEmail(
        'New ' + lead.type + ' submission' + (lead.ref ? ' [' + lead.ref + ']' : '') + ' — ' + (lead.name || lead.email || 'Skybridge'),
        ['Type: ' + lead.type, lead.ref ? 'Order #: ' + lead.ref : '', 'Name: ' + lead.name, 'Email: ' + lead.email,
         'Phone: ' + lead.phone, 'Company: ' + lead.company, 'Role: ' + lead.role, 'Topic: ' + lead.topic]
          .concat(detailLines).concat(['Source: ' + lead.source, '', lead.message]).filter(x => x !== '').join('\n')
      );
      return res.status(200).json({ ok: true });
    }

    // ---- authenticated routes ----
    const u = currentUser(req);
    if (!u) return res.status(401).json({ error: 'unauthorized' });

    if (action === 'leads') {
      if (req.method === 'PATCH') {
        const b = await readBody(req);
        const id = S(b.id, 64);
        if (!id) return res.status(400).json({ error: 'id required' });
        const g = await kv(['GET', 'sb:lead:' + id]);
        const raw = g && g.result;
        if (!raw) return res.status(404).json({ error: 'not found' });
        const lead = JSON.parse(raw);
        if (b.status) lead.status = S(b.status, 24);
        lead.updatedBy = u.email; lead.updatedTs = Date.now();
        await kv(['SET', 'sb:lead:' + id, JSON.stringify(lead)]);
        return res.status(200).json({ ok: true });
      }
      const idsR = await kv(['LRANGE', 'sb:leadids', 0, 999]);
      const ids = (idsR && idsR.result) || [];
      if (!ids.length) return res.status(200).json({ leads: [], store: !!process.env.KV_REST_API_URL });
      const mg = await kv(['MGET'].concat(ids.map(i => 'sb:lead:' + i)));
      const arr = (mg && mg.result) || [];
      const leads = arr.filter(Boolean).map(s => { try { return JSON.parse(s); } catch (_) { return null; } }).filter(Boolean);
      return res.status(200).json({ leads, store: true });
    }

    return res.status(404).json({ error: 'unknown action' });
  } catch (_) {
    return res.status(500).json({ error: 'server error' });
  }
};
