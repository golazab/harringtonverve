import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { makeHandler, validate, escapeHtml, _resetRate } from '../api/enquiry.js';

const ORIGIN = 'https://harringtonverve.com';
const NOW = 1_800_000_000_000;
const env = { RESEND_API_KEY: 'test_key', ALLOWED_ORIGINS: ORIGIN };

function mockRes() {
  return {
    statusCode: 200, headers: {}, body: '',
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b = '') { this.body = b; }
  };
}
function req(overrides = {}) {
  return {
    method: 'POST',
    headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin', 'content-type': 'application/json', accept: 'application/json', 'x-forwarded-for': '203.0.113.7', ...(overrides.headers || {}) },
    body: { name: 'Ada Lovelace', email: 'ada@example.com', interest: 'polo', message: 'Hello', website: '', t: NOW - 10_000, ...(overrides.body || {}) },
    ...('method' in overrides ? { method: overrides.method } : {})
  };
}
function setup(fetchImpl) {
  const calls = [];
  const f = fetchImpl || (async (url, opts) => { calls.push({ url, opts }); return { ok: true, status: 200 }; });
  return { calls, handler: makeHandler({ env, fetchImpl: f, now: () => NOW }) };
}

beforeEach(() => _resetRate());

test('valid enquiry is sent and returns 200', async () => {
  const { calls, handler } = setup();
  const res = mockRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('rejects non-POST methods', async () => {
  const { handler } = setup();
  const res = mockRes();
  await handler(req({ method: 'GET' }), res);
  assert.equal(res.statusCode, 405);
});

test('CSRF: rejects foreign origin', async () => {
  const { calls, handler } = setup();
  const res = mockRes();
  await handler(req({ headers: { origin: 'https://evil.example' } }), res);
  assert.equal(res.statusCode, 403);
  assert.equal(calls.length, 0);
});

test('CSRF: rejects missing origin', async () => {
  const { handler } = setup();
  const r = req(); delete r.headers.origin;
  const res = mockRes();
  await handler(r, res);
  assert.equal(res.statusCode, 403);
});

test('CSRF: rejects cross-site fetch metadata even with spoofed origin', async () => {
  const { handler } = setup();
  const res = mockRes();
  await handler(req({ headers: { 'sec-fetch-site': 'cross-site' } }), res);
  assert.equal(res.statusCode, 403);
});

test('rejects unexpected content types', async () => {
  const { handler } = setup();
  const res = mockRes();
  await handler(req({ headers: { 'content-type': 'text/plain' } }), res);
  assert.equal(res.statusCode, 415);
});

test('rejects oversized bodies', async () => {
  const { handler } = setup();
  const res = mockRes();
  await handler(req({ headers: { 'content-length': '50000' } }), res);
  assert.equal(res.statusCode, 413);
  const res2 = mockRes();
  await handler(req({ body: { message: 'x'.repeat(9000) } }), res2);
  assert.equal(res2.statusCode, 413);
});

test('server-side validation: bad email, missing name, unknown interest', async () => {
  const { calls, handler } = setup();
  for (const body of [{ email: 'not-an-email' }, { name: '' }, { interest: 'crypto' }, { email: 'a@b.c' }]) {
    const res = mockRes();
    await handler(req({ body }), res);
    assert.equal(res.statusCode, 422, JSON.stringify(body));
  }
  assert.equal(calls.length, 0);
});

test('rejects non-string / object payloads safely', async () => {
  const { handler } = setup();
  for (const body of [{ name: { $gt: '' } }, { email: ['a@b.com'] }]) {
    const res = mockRes();
    await handler(req({ body }), res);
    assert.equal(res.statusCode, 422);
  }
});

test('honeypot and timing traps drop spam silently', async () => {
  const { calls, handler } = setup();
  for (const body of [{ website: 'http://spam' }, { t: NOW - 500 }, { t: 'abc' }, { t: NOW - 7 * 3600e3 }]) {
    const res = mockRes();
    await handler(req({ body }), res);
    assert.equal(res.statusCode, 200);
  }
  assert.equal(calls.length, 0);
});

test('rate limit: 6th request from same IP in window gets 429', async () => {
  const { handler } = setup();
  const codes = [];
  for (let i = 0; i < 6; i++) { const res = mockRes(); await handler(req(), res); codes.push(res.statusCode); }
  assert.deepEqual(codes, [200, 200, 200, 200, 200, 429]);
  const other = mockRes();
  await handler(req({ headers: { 'x-forwarded-for': '198.51.100.9' } }), other);
  assert.equal(other.statusCode, 200);
});

test('XSS: user input is escaped in the HTML email', async () => {
  const { calls, handler } = setup();
  const res = mockRes();
  await handler(req({ body: { name: '<script>alert(1)</script>', message: '<img src=x onerror=alert(1)>' } }), res);
  assert.equal(res.statusCode, 200);
  const sent = JSON.parse(calls[0].opts.body);
  assert.ok(!sent.html.includes('<script>'));
  assert.ok(!sent.html.includes('<img'));
  assert.ok(sent.html.includes('&lt;script&gt;'));
});

test('header injection: CR/LF stripped from name and email', () => {
  const v = validate({ name: 'Ada\r\nBcc: x@evil.com', email: 'ada@example.com\r\nBcc: x@evil.com', interest: 'polo', t: NOW - 10_000 }, NOW);
  assert.ok(v.error, 'email with CRLF payload must be rejected');
  const v2 = validate({ name: 'Ada\r\nBcc: x', email: 'ada@example.com', interest: 'polo', t: NOW - 10_000 }, NOW);
  assert.ok(!/[\r\n]/.test(v2.data.name));
});

test('API key travels only in server-side Authorization header', async () => {
  const { calls, handler } = setup();
  const res = mockRes();
  await handler(req(), res);
  assert.equal(calls[0].opts.headers.Authorization, 'Bearer test_key');
  assert.ok(!res.body.includes('test_key'));
});

test('mail provider down: returns 503 with a useful message, does not hang', async () => {
  const { handler } = setup(async () => { throw new Error('ECONNRESET'); });
  const res = mockRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 503);
  assert.match(JSON.parse(res.body).error, /enquiries@harringtonverve\.com/);
});

test('mail provider timeout is aborted (fetch receives an AbortSignal)', async () => {
  let signal;
  const { handler } = setup(async (u, o) => { signal = o.signal; return { ok: true, status: 200 }; });
  await handler(req(), mockRes());
  assert.ok(signal instanceof AbortSignal);
});

test('missing API key: 503, no crash', async () => {
  const handler = makeHandler({ env: { ALLOWED_ORIGINS: ORIGIN }, now: () => NOW });
  const res = mockRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 503);
});

test('no-JS form post gets a 303 redirect instead of JSON', async () => {
  const { handler } = setup();
  const res = mockRes();
  const body = new URLSearchParams({ name: 'Ada Lovelace', email: 'ada@example.com', interest: 'polo', t: String(NOW - 10_000) }).toString();
  await handler({ ...req(), headers: { ...req().headers, 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html' }, body }, res);
  assert.equal(res.statusCode, 303);
  assert.equal(res.headers.location, '/?sent=1#introduction');
});

test('escapeHtml covers all five characters', () => {
  assert.equal(escapeHtml(`<>&"'`), '&lt;&gt;&amp;&quot;&#39;');
});

test('vercel.json ships the security headers', () => {
  const cfg = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  const all = cfg.headers.find(h => h.source === '/(.*)').headers;
  const get = k => all.find(h => h.key === k)?.value || '';
  assert.match(get('Content-Security-Policy'), /default-src 'self'/);
  assert.match(get('Content-Security-Policy'), /frame-ancestors 'none'/);
  assert.doesNotMatch(get('Content-Security-Policy'), /unsafe-inline|unsafe-eval/);
  assert.match(get('Strict-Transport-Security'), /max-age=63072000/);
  for (const k of ['X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy', 'Cross-Origin-Opener-Policy']) assert.ok(get(k), k);
});

test('no inline scripts, styles or event handlers in HTML (CSP-compatible)', () => {
  for (const f of ['index.html', 'privacy.html', '404.html']) {
    const html = readFileSync(new URL('../' + f, import.meta.url), 'utf8');
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, f);
    assert.doesNotMatch(html, /\son[a-z]+=/i, f);
    assert.doesNotMatch(html, /\sstyle=/i, f);
    assert.doesNotMatch(html, /<style/i, f);
  }
});

test('The Unscripted Table is an accepted area of interest', () => {
  const v = validate({ name: 'Ada Lovelace', email: 'ada@example.com', interest: 'unscripted-table', t: NOW - 10_000 }, NOW);
  assert.equal(v.data.interest, 'unscripted-table');
});
