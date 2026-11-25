'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const https = require('node:https');
const http = require('node:http');
const { execFile, execFileSync } = require('node:child_process');
const { promisify } = require('node:util');
const exec = promisify(execFile);
const { configuration, environment, redact, safeResult, junit, discover } = require('./run-postman');

const fake = {
  OIDC_ISSUER: 'https://tenant.example/', OIDC_AUDIENCE: 'https://library-system',
  AUTH0_TEST_USERNAME: 'fake-user@example.test', AUTH0_TEST_PASSWORD: 'fake password&+"value',
  AUTH0_TEST_CLIENT_ID: 'fake-client', AUTH0_TEST_CLIENT_SECRET: 'fake-secret',
};

test('required configuration is explicit and credentials stay in runtime environment', () => {
  const config = configuration(fake, 'v4');
  assert.equal(config.baseURL, 'http://localhost:8080');
  for (const key of Object.keys(fake)) assert.throws(() => configuration({ ...fake, [key]: '' }, 'v4'), new RegExp(key));
  for (const OIDC_ISSUER of ['http://tenant.example/', 'https://secret@tenant.example/', 'https://tenant.example/?query=1', 'https://tenant.example']) {
    assert.throws(() => configuration({ ...fake, OIDC_ISSUER }, 'v4'));
  }
  assert.throws(() => configuration(fake, 'v3'));
  const values = Object.fromEntries(environment(config, 'https://tenant.example/oauth/token').values.map(item => [item.key, item.value]));
  assert.equal(values.clientId, fake.AUTH0_TEST_CLIENT_ID);
  assert.equal(values.clientSecret, fake.AUTH0_TEST_CLIENT_SECRET);
  assert.equal(values.audience, fake.OIDC_AUDIENCE);
});

test('redaction covers raw, URI, form-encoded, JSON-escaped secrets and JWTs', () => {
  const secret = fake.AUTH0_TEST_PASSWORD;
  const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl';
  const input = [secret, encodeURIComponent(secret), new URLSearchParams({ v: secret }).toString().slice(2), JSON.stringify(secret).slice(1, -1), jwt].join(' | ');
  const output = redact(input, new Set([secret]));
  assert(!output.includes(secret));
  assert(!output.includes(encodeURIComponent(secret)));
  assert(!output.includes(jwt));
  assert(output.includes('[REDACTED]'));
});

test('request/runtime errors and incomplete runs fail sanitized reports even without failed assertions', () => {
  for (const stats of [
    { requests: { total: 14, failed: 1 }, assertions: { total: 14, failed: 0 } },
    { requests: { total: 0, failed: 0 }, assertions: { total: 0, failed: 0 } },
    { requests: { total: 14, failed: 0 }, assertions: { total: 13, failed: 0 } },
    { requests: { total: 14, failed: 0 }, assertions: { total: 14, failed: 1 } },
  ]) {
    const result = safeResult({ run: { stats, failures: [] } }, new Set());
    assert(result.failures.length > 0);
    assert(!junit(result).includes('failures="0"'));
  }
  const result = safeResult({ run: { stats: { requests: { total: 14 }, assertions: { total: 14, failed: 1 } }, failures: [{ error: { test: 'Name <tag>', message: `bad ${fake.AUTH0_TEST_PASSWORD}` } }] } }, new Set([fake.AUTH0_TEST_PASSWORD]));
  assert(!junit(result).includes(fake.AUTH0_TEST_PASSWORD));
  assert(junit(result).includes('&lt;tag&gt;'));
});

test('discovery enforces issuer/origin, disables redirects and bounds the body while reading', async t => {
  const config = configuration(fake, 'v4');
  let makeResponse = () => new Response(JSON.stringify({ issuer: config.issuer, token_endpoint: config.issuer + 'oauth/token' }));
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, config.issuer + '.well-known/openid-configuration');
    assert.equal(options.redirect, 'error');
    assert(options.signal instanceof AbortSignal);
    return makeResponse();
  });
  assert.equal(await discover(config), config.issuer + 'oauth/token');
  for (const metadata of [
    { issuer: 'https://other.example/', token_endpoint: config.issuer + 'oauth/token' },
    { issuer: config.issuer, token_endpoint: 'https://other.example/oauth/token' },
    { issuer: config.issuer, token_endpoint: 'http://tenant.example/oauth/token' },
  ]) {
    makeResponse = () => new Response(JSON.stringify(metadata));
    await assert.rejects(discover(config));
  }
  let canceled = false;
  makeResponse = () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)); },
    cancel() { canceled = true; },
  }));
  await assert.rejects(discover(config), /too large/);
  assert(canceled);
});

test('Newman reporters:[] suppresses CLI and sandbox console credentials', async t => {
  const server = http.createServer((_req, res) => { res.end('{}'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const code = `const n=require('newman');let seen=0;const run=n.run({reporters:[],collection:{info:{name:'console privacy',schema:'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'},event:[{listen:'prerequest',script:{type:'text/javascript',exec:['console.log(pm.environment.get("secret"))']}}],item:[{name:'request',request:{method:'GET',url:process.env.TEST_URL}}]},environment:{values:[{key:'secret',value:process.env.TEST_SECRET,enabled:true}]}},(e,s)=>{if(e||s.run.failures.length)process.exitCode=1;console.log('console events='+seen);});run.on('console',()=>seen++);`;
  const result = await exec(process.execPath, ['-e', code], { cwd: __dirname, env: { ...process.env, TEST_URL: `http://127.0.0.1:${server.address().port}`, TEST_SECRET: fake.AUTH0_TEST_PASSWORD } });
  assert.equal(result.stdout.trim(), 'console events=1');
  assert(!result.stderr.includes(fake.AUTH0_TEST_PASSWORD));
});

test('actual 14-request collection runs against an HTTPS stand-in with no credential output', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lab5-newman-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cert = path.join(directory, 'cert.pem'), key = path.join(directory, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const library = { libraryUid: '83575e12-7ce0-48ee-9931-51919ff3c9ee', name: 'Библиотека имени 7 Непьющих', city: 'Москва', address: '2-я Бауманская ул., д.5, стр.1' };
  const book = { bookUid: 'f7cdc58f-2caf-4b15-9727-f89dcc629b27', name: 'Краткий курс C++ в 7 томах', author: 'Бьерн Страуструп', genre: 'Научная фантастика', condition: 'EXCELLENT' };
  const accessToken = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl';
  let issuer, stars = 75, reservation, broken = false, grants = 0;
  const server = https.createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) }, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const send = (status, body) => { res.statusCode = status; res.end(body === undefined ? '' : JSON.stringify(body)); };
    if (req.url === '/.well-known/openid-configuration') return send(200, { issuer, token_endpoint: issuer + 'oauth/token' });
    let raw = ''; for await (const chunk of req) raw += chunk;
    if (req.url === '/oauth/token') {
      grants++;
      const form = new URLSearchParams(raw);
      if (form.get('client_id') !== fake.AUTH0_TEST_CLIENT_ID || form.get('client_secret') !== fake.AUTH0_TEST_CLIENT_SECRET || form.get('audience') !== fake.OIDC_AUDIENCE || form.get('grant_type') !== 'password' || form.get('username') !== fake.AUTH0_TEST_USERNAME || form.get('password') !== fake.AUTH0_TEST_PASSWORD) return send(400, { error: 'bad fixture grant' });
      return send(200, { access_token: accessToken, token_type: 'Bearer', expires_in: 900 });
    }
    if (req.headers.authorization !== 'Bearer ' + accessToken) return send(401, { message: 'authentication required' });
    const url = new URL(req.url, issuer);
    if (url.pathname === '/api/v1/libraries') return send(200, { page: 1, pageSize: 1, totalElements: 1, items: [{ ...library, name: broken ? fake.AUTH0_TEST_PASSWORD : library.name }] });
    if (url.pathname.endsWith('/books')) return send(200, { page: 1, pageSize: 1, totalElements: 1, items: [book] });
    if (url.pathname === '/api/v1/rating') return send(200, { stars });
    if (url.pathname === '/api/v1/reservations' && req.method === 'POST') {
      const body = JSON.parse(raw);
      reservation = { reservationUid: 'f5026466-a194-4012-99bd-cc8a9c689fde', status: 'RENTED', startDate: new Date().toISOString().slice(0, 10), tillDate: body.tillDate, book, library };
      return send(200, reservation);
    }
    if (url.pathname === '/api/v1/reservations') return send(200, [reservation]);
    if (url.pathname.endsWith('/return')) { stars++; return send(204); }
    return send(501, { message: 'not modeled by stand-in' });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  issuer = `https://127.0.0.1:${server.address().port}/`;
  for (const fail of [false, true]) {
    broken = fail; stars = 75;
    const reports = path.join(directory, fail ? 'failure' : 'success');
    const result = await exec(process.execPath, [path.join(__dirname, 'run-postman.js'), 'v4'], { env: { ...process.env, ...fake, OIDC_ISSUER: issuer, BASE_URL: issuer, TEST_REPORT_DIR: reports, NODE_EXTRA_CA_CERTS: cert } }).catch(error => error);
    const report = fs.readFileSync(path.join(reports, 'newman.xml'), 'utf8');
    const output = String(result.stdout) + String(result.stderr) + report;
    for (const secret of [fake.AUTH0_TEST_PASSWORD, fake.AUTH0_TEST_CLIENT_SECRET, accessToken, encodeURIComponent(fake.AUTH0_TEST_PASSWORD)]) assert(!output.includes(secret), 'credential leaked from runner/report');
    if (fail) { assert.notEqual(result.code, undefined); assert(!report.includes('failures="0"')); }
    else { assert.equal(result.code, undefined); assert.match(result.stdout, /Requests: 14; assertions: 14; failures: 0/); }
  }
  assert.equal(grants, 2);
});
