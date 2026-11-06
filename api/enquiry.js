// POST /api/enquiry — the only server endpoint on the site.
// No database: a valid request is forwarded by email (Resend) and nothing is stored.
import { createHash } from 'node:crypto';

const MAX_BYTES = 8 * 1024;
const MIN_FILL_MS = 2500;          // humans take longer than this to fill the form
const MAX_AGE_MS = 6 * 60 * 60e3;  // form timestamps older than 6h are rejected
const RATE_WINDOW_MS = 10 * 60e3;
const RATE_MAX = 5;                // per IP per window, per warm instance
const INTERESTS = new Set(['womens-sport', 'polo', 'brand-mastery', 'private-assets', 'unscripted-table', 'other']);
const EMAIL = /^[^\s@<>()[\]\\,;:"]{1,64}@[^\s@<>()[\]\\,;:"]{1,189}\.[^\s@<>()[\]\\,;:"]{2,}$/;

const hits = new Map();

export function allowedOrigins(env = process.env) {
  return (env.ALLOWED_ORIGINS || 'https://harringtonverve.com,https://www.harringtonverve.com')
    .split(',').map(s => s.trim()).filter(Boolean);
}

export function clientIp(req) {
  // On Vercel, x-forwarded-for is set by the platform edge; first entry is the client.
  const xf = String(req.headers['x-forwarded-for'] || '');
  return xf.split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

const fingerprint = ip => createHash('sha256').update('hv:' + ip).digest('hex').slice(0, 12);

export function rateLimited(ip, now = Date.now()) {
  const list = (hits.get(ip) || []).filter(t => now - t < RATE_WINDOW_MS);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear(); // bound memory
  return list.length > RATE_MAX;
}
export function _resetRate() { hits.clear(); }

// Strip control characters (incl. CR/LF, which blocks header injection) and trim.
function clean(v, max, keepNewlines = false) {
  if (typeof v !== 'string') return '';
  const re = keepNewlines ? /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F]/g : /[\u0000-\u001F\u007F]/g;
  return v.replace(re, '').trim().slice(0, max);
}

export function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function validate(body, now = Date.now()) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Invalid request.' };
  if (typeof body.website === 'string' && body.website.length > 0) return { spam: 'honeypot' };
  const t = Number(body.t);
  if (!Number.isFinite(t) || now - t < MIN_FILL_MS || now - t > MAX_AGE_MS) return { spam: 'timing' };

  const name = clean(body.name, 120);
  const email = clean(body.email, 254).toLowerCase();
  const interest = clean(body.interest, 40);
  const message = clean(body.message, 2000, true);

  const fields = {};
  if (name.length < 2) fields.name = 'Enter your name.';
  if (!EMAIL.test(email)) fields.email = 'Enter a valid email address.';
  if (!INTERESTS.has(interest)) fields.interest = 'Choose an area of interest.';
  if (typeof body.message === 'string' && body.message.length > 2000) fields.message = 'Keep the message under 2,000 characters.';
  if (Object.keys(fields).length) return { error: Object.values(fields)[0], fields };
  return { data: { name, email, interest, message } };
}

function log(level, event, extra) {
  // Structured, PII-free security log (visible in Vercel runtime logs / log drains).
  console[level](JSON.stringify({ at: new Date().toISOString(), src: 'enquiry', event, ...extra }));
}

async function sendMail(data, env, fetchImpl) {
  const key = env.RESEND_API_KEY;
  if (!key) throw Object.assign(new Error('mail not configured'), { code: 'NOCONF' });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    const r = await fetchImpl('https://api.resend.com/emails', {
      method: 'POST',
      signal: ctrl.signal,
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.MAIL_FROM || 'Harrington Verve <website@harringtonverve.com>',
        to: [env.MAIL_TO || 'enquiries@harringtonverve.com'],
        reply_to: data.email,
        subject: `Introduction request: ${data.interest}`,
        text: `Name: ${data.name}\nEmail: ${data.email}\nInterest: ${data.interest}\n\n${data.message || '(no message)'}`,
        html: `<p><b>Name:</b> ${escapeHtml(data.name)}<br><b>Email:</b> ${escapeHtml(data.email)}<br><b>Interest:</b> ${escapeHtml(data.interest)}</p><p>${escapeHtml(data.message || '(no message)').replace(/\n/g, '<br>')}</p>`
      })
    });
    if (!r.ok) throw Object.assign(new Error('mail provider ' + r.status), { code: 'UPSTREAM' });
  } finally {
    clearTimeout(timer);
  }
}

function reply(req, res, status, payload) {
  const wantsHtml = String(req.headers.accept || '').includes('text/html') && !String(req.headers['content-type'] || '').includes('json');
  res.setHeader('Cache-Control', 'no-store');
  if (wantsHtml) {
    // Plain HTML form post (no JS): redirect back instead of printing JSON.
    res.statusCode = 303;
    res.setHeader('Location', status < 400 ? '/?sent=1#introduction' : '/?error=1#introduction');
    return res.end();
  }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

export function makeHandler({ env = process.env, fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  return async function handler(req, res) {
    const ip = clientIp(req);
    const who = fingerprint(ip);

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return reply(req, res, 405, { error: 'Method not allowed.' });
    }

    // CSRF: only accept same-site browser posts from our own origins.
    const origin = String(req.headers.origin || '');
    const site = String(req.headers['sec-fetch-site'] || '');
    if (!allowedOrigins(env).includes(origin) || (site && site !== 'same-origin')) {
      log('warn', 'blocked_origin', { who, origin: origin.slice(0, 80) });
      return reply(req, res, 403, { error: 'Request blocked.' });
    }

    const ctype = String(req.headers['content-type'] || '');
    if (!ctype.startsWith('application/json') && !ctype.startsWith('application/x-www-form-urlencoded')) {
      return reply(req, res, 415, { error: 'Unsupported content type.' });
    }
    if (Number(req.headers['content-length'] || 0) > MAX_BYTES) {
      log('warn', 'oversize', { who });
      return reply(req, res, 413, { error: 'Request too large.' });
    }

    if (rateLimited(ip, now())) {
      log('warn', 'rate_limited', { who });
      res.setHeader('Retry-After', '600');
      return reply(req, res, 429, { error: 'Too many requests.' });
    }

    let body = req.body;
    if (typeof body === 'string') {
      if (body.length > MAX_BYTES) return reply(req, res, 413, { error: 'Request too large.' });
      try { body = ctype.startsWith('application/json') ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body)); }
      catch { return reply(req, res, 400, { error: 'Invalid request.' }); }
    }
    if (body && JSON.stringify(body).length > MAX_BYTES) return reply(req, res, 413, { error: 'Request too large.' });

    const v = validate(body, now());
    if (v.spam) {
      log('warn', 'spam_dropped', { who, reason: v.spam });
      return reply(req, res, 200, { ok: true }); // look successful to bots
    }
    if (v.error) return reply(req, res, 422, { error: v.error, fields: v.fields });

    try {
      await sendMail(v.data, env, fetchImpl);
    } catch (e) {
      log('error', 'mail_failed', { who, code: e.code || 'ERR' });
      return reply(req, res, 503, { error: 'The request could not be sent. Write to enquiries@harringtonverve.com instead.' });
    }
    log('info', 'enquiry_sent', { who, interest: v.data.interest });
    return reply(req, res, 200, { ok: true });
  };
}

export default makeHandler();
