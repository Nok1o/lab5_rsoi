'use strict';

// Destructive failure injection is limited to a disposable local Compose stack.
// Auth0 is real. Only Gateway requests M2M tokens; this driver never obtains one.
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { setTimeout: sleep } = require('node:timers/promises');
const { configuration, discover, redact } = require('./run-postman');
const exec = promisify(execFile);
const root = path.resolve(__dirname, '..');
const stream = 'gateway:{returns}:jobs';
const group = 'return-workers';
const jobKeys = ['reservationUid', 'libraryUid', 'bookUid', 'username', 'originalCondition', 'returnedCondition', 'expired', 'stage'].sort();

function ensure(condition, message) {
  if (!condition) throw new Error(message);
}

function settings(env) {
  const config = configuration(env, 'v4');
  ensure(/^lab5-(ci|worker)-[a-z0-9-]+$/.test(env.COMPOSE_PROJECT_NAME || ''), 'Use a disposable COMPOSE_PROJECT_NAME: lab5-worker-<unique suffix>');
  ensure(config.baseURL === 'http://localhost:8080' || config.baseURL === 'http://127.0.0.1:8080', 'Worker test requires the local Compose Gateway on port 8080');
  return { ...config, project: env.COMPOSE_PROJECT_NAME };
}

async function compose(config, ...args) {
  try {
    const { stdout } = await exec('docker', ['compose', '--env-file', '/dev/null', '--project-directory', root, '--project-name', config.project, ...args], {
      cwd: root, timeout: 60000, maxBuffer: 1024 * 1024,
    });
    return stdout;
  } catch {
    // execFile errors contain stdout/stderr; do not propagate Docker state.
    throw new Error('Compose operation failed (check container state, not secret environment dumps)');
  }
}

async function request(url, token, method = 'GET', body, expected = 200) {
  let response;
  try {
    response = await fetch(url, {
      method, redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error('HTTP request failed or timed out');
  }
  ensure(response.status === expected, `Expected HTTP ${expected}, received ${response.status}`);
  if (expected === 204 || expected === 401) { await response.body?.cancel(); return; }
  try { return await response.json(); } catch { throw new Error('Expected a JSON response'); }
}

async function userToken(config, sensitive) {
  const endpoint = await discover(config);
  const response = await fetch(endpoint, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: config.clientID, client_secret: config.clientSecret,
      username: config.username, password: config.password, audience: config.audience, scope: 'openid profile email' }),
  });
  ensure(response.status === 200, `Auth0 user grant returned HTTP ${response.status}`);
  const body = await response.json();
  for (const key of ['access_token', 'id_token', 'refresh_token']) if (typeof body[key] === 'string') sensitive.add(body[key]);
  ensure(body.token_type?.toLowerCase() === 'bearer' && typeof body.access_token === 'string', 'Auth0 did not return a Bearer access token');
  // Decode only for the expected test identity. All services verify the JWT.
  let claims;
  try { claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString()); } catch { throw new Error('Auth0 did not return a JWT'); }
  ensure(typeof claims.sub === 'string' && claims.sub !== '', 'Auth0 token has no subject');
  return { token: body.access_token, subject: claims.sub };
}

async function redis(config, ...args) {
  const output = await compose(config, 'exec', '-T', 'redis', 'redis-cli', '--json', ...args);
  try { return JSON.parse(output); } catch { throw new Error('Redis returned an unexpected response'); }
}

function inspectJobs(entries, expected, sensitive) {
  ensure(Array.isArray(entries) && entries.length === 1, 'Expected exactly one deferred return in the isolated stream');
  const fields = entries[0][1];
  ensure(Array.isArray(fields) && fields.length === 2 && fields[0] === 'payload', 'Unexpected Stream fields');
  const raw = fields[1];
  ensure(typeof raw === 'string' && !/\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(raw), 'Stream must not contain a JWT');
  for (const secret of sensitive) if (secret) ensure(!raw.includes(secret), 'Stream contains a credential');
  let job;
  try { job = JSON.parse(raw); } catch { throw new Error('Invalid return job JSON'); }
  ensure(JSON.stringify(Object.keys(job).sort()) === JSON.stringify(jobKeys), 'Return job contains unexpected fields (including possible credentials)');
  for (const [key, value] of Object.entries(expected)) ensure(job[key] === value, `Unexpected return job field: ${key}`);
  return job;
}

async function waitFor(label, predicate, wait = sleep, timeout = 90000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    // Unexpected HTTP/Redis errors fail immediately; only an expected not-ready
    // state is retried, so a permanent authorization failure cannot be hidden.
    if (await predicate()) return;
    await wait(1000);
  }
  throw new Error(`Timed out: ${label}`);
}

function report(result) {
  const escape = value => String(value).replace(/[<>&"']/g, char => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[char]));
  const passed = result.passed.map(name => `<testcase name="${escape(name)}"/>`).join('\n');
  const failed = result.failure ? `<testcase name="${escape(result.step)}"><failure message="${escape(result.failure)}"/></testcase>` : '';
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="Lab5 Auth0 deferred worker" tests="${result.passed.length + (result.failure ? 1 : 0)}" failures="${result.failure ? 1 : 0}">\n${passed}\n${failed}\n</testsuite></testsuites>\n`;
}

async function scenario(config, sensitive, check, io) {
  const { api, command, redisCommand, grant, wait } = io;
  const local = port => `http://127.0.0.1:${port}`;
  let token, subject, libraryUid, bookUid, baseline, initialStars, reservationUid;
  let changed = false;
  try {
    await check('Fresh local stack and empty return stream', async () => {
      for (const port of [8080, 8060, 8050, 8070]) await api(`${local(port)}/manage/health`);
      ensure(await redisCommand('XLEN', stream) === 0, 'Worker test requires an empty Stream in a fresh Compose stack');
      ensure((await redisCommand('XPENDING', stream, group))[0] === 0, 'Worker test requires no pending deliveries');
    });
    await check('Real Auth0 user grant', async () => { ({ token, subject } = await grant()); });
    await check('User JWT cannot call either worker API', async () => {
      const libraries = await api(`${config.baseURL}/api/v1/libraries?city=${encodeURIComponent('Москва')}&page=1&size=10`, token);
      libraryUid = libraries.items?.[0]?.libraryUid;
      ensure(typeof libraryUid === 'string', 'No library fixture');
      const books = await api(`${config.baseURL}/api/v1/libraries/${libraryUid}/books?showAll=false&page=1&size=25`, token);
      const book = books.items?.find(item => item.availableCount > 0);
      ensure(book, 'No available book fixture');
      bookUid = book.bookUid;
      baseline = { count: book.availableCount, condition: book.condition };
      await api(`${local(8060)}/internal/v1/libraries/${libraryUid}/books/${bookUid}`, token, 'GET', undefined, 401);
      await api(`${local(8050)}/internal/v1/rating`, token, 'PATCH', { username: subject, delta: 1 }, 401);
    });
    const bookURL = `${local(8060)}/api/v1/libraries/${libraryUid}/books/${bookUid}`;
    const ratingURL = `${local(8050)}/api/v1/rating`;
    await check('Rent a book and record the persisted user rating', async () => {
      const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
      const reservation = await api(`${config.baseURL}/api/v1/reservations`, token, 'POST', { libraryUid, bookUid, tillDate: tomorrow });
      ensure(reservation.status === 'RENTED' && typeof reservation.reservationUid === 'string', 'Expected a rented reservation');
      reservationUid = reservation.reservationUid;
      initialStars = (await api(ratingURL, token)).stars;
      ensure(Number.isInteger(initialStars) && initialStars < 100, 'Expected a rating below its maximum');
      ensure((await api(bookURL, token)).availableCount === baseline.count - 1, 'Rent did not reduce book stock');
    });
    const expectedJob = { reservationUid, libraryUid, bookUid, username: subject, returnedCondition: baseline.condition, expired: false };
    await check('Accept return while Library and Rating are stopped', async () => {
      changed = true;
      await command('stop', '--timeout', '20', 'library-service', 'rating-service');
      await api(`${config.baseURL}/api/v1/reservations/${reservationUid}/return`, token, 'POST', {
        condition: baseline.condition, date: new Date().toISOString().slice(0, 10),
      }, 204);
      const reservation = await api(`${local(8070)}/api/v1/reservations/${reservationUid}`, token);
      ensure(reservation.status === 'RETURNED', 'Reservation was not closed before deferring completion');
      inspectJobs(await redisCommand('XRANGE', stream, '-', '+'), { ...expectedJob, stage: 'RESTORE_BOOK' }, sensitive);
    });
    await check('Restart Gateway without replaying the user request', async () => {
      await command('restart', '--timeout', '20', 'gateway-service');
      await wait('Gateway restart', async () => {
        try { await api(`${local(8080)}/manage/health`); return true; } catch { return false; }
      });
      // From this point only direct user READs of downstream state are made.
      // Gateway has no original request context; Redis contains no user JWT.
      await wait('pending restore delivery', async () => (await redisCommand('XPENDING', stream, group))[0] > 0);
      inspectJobs(await redisCommand('XRANGE', stream, '-', '+'), { ...expectedJob, stage: 'RESTORE_BOOK' }, sensitive);
    });
    await check('M2M worker restores book and persists the rating stage', async () => {
      await command('start', 'library-service');
      await wait('Library health', async () => {
        try { await api(`${local(8060)}/manage/health`); return true; } catch { return false; }
      });
      await wait('RESTORE_BOOK to UPDATE_RATING', async () => {
        const job = inspectJobs(await redisCommand('XRANGE', stream, '-', '+'), expectedJob, sensitive);
        return job.stage === 'UPDATE_RATING';
      });
      const book = await api(bookURL, token);
      ensure(book.availableCount === baseline.count && book.condition === baseline.condition, 'Worker did not restore book stock/condition');
      await wait('pending rating delivery', async () => (await redisCommand('XPENDING', stream, group))[0] > 0);
    });
    await check('M2M worker updates the original user and acknowledges the job', async () => {
      await command('start', 'rating-service');
      await wait('Rating health', async () => {
        try { await api(`${local(8050)}/manage/health`); return true; } catch { return false; }
      });
      await wait('deferred rating completion', async () => {
        const rating = await api(ratingURL, token);
        ensure(rating.stars <= initialStars + 1, 'Rating was changed more than once');
        return rating.stars === initialStars + 1 && await redisCommand('XLEN', stream) === 0 && (await redisCommand('XPENDING', stream, group))[0] === 0;
      });
      ensure((await api(bookURL, token)).availableCount === baseline.count, 'Book stock was changed more than once');
    });
  } finally {
    // Restore availability on any assertion failure; CI still removes its own
    // disposable stack in an always() step. Never delete user volumes here.
    if (changed) await command('start', 'library-service', 'rating-service', 'gateway-service');
  }
}

async function main(env = process.env) {
  const config = settings(env);
  const sensitive = new Set([config.username, config.password, config.clientSecret, env.OIDC_WORKER_CLIENT_SECRET]);
  const result = { passed: [], step: 'Worker scenario', failure: '' };
  const check = async (name, operation) => {
    result.step = name;
    await operation();
    result.passed.push(name);
    console.log(`PASS: ${name}`);
  };
  try {
    await scenario(config, sensitive, check, {
      api: request, command: (...args) => compose(config, ...args), redisCommand: (...args) => redis(config, ...args),
      grant: () => userToken(config, sensitive), wait: (label, predicate) => waitFor(label, predicate),
    });
  } catch (error) {
    result.failure = redact(error.message, sensitive);
    console.error(`FAIL: ${result.step}: ${result.failure}`);
    process.exitCode = 1;
  }
  const directory = path.resolve(env.TEST_REPORT_DIR || path.join(root, 'test-reports'));
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'worker.xml'), report(result), { mode: 0o600 });
  console.log(`Worker checks: ${result.passed.length}; failures: ${result.failure ? 1 : 0}`);
  return result;
}

module.exports = { settings, inspectJobs, waitFor, report, scenario };
if (require.main === module) main().catch(() => { console.error('Worker test configuration or report failed; verify required variables and the report directory'); process.exitCode = 1; });
