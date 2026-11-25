'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { settings, inspectJobs, waitFor, report, scenario } = require('./test-worker');

const env = {
  OIDC_ISSUER: 'https://tenant.example/', OIDC_AUDIENCE: 'https://library-system',
  AUTH0_TEST_USERNAME: 'test@example.test', AUTH0_TEST_PASSWORD: 'secret password',
  AUTH0_TEST_CLIENT_ID: 'user-client', AUTH0_TEST_CLIENT_SECRET: 'user-secret',
  COMPOSE_PROJECT_NAME: 'lab5-ci-123-1', BASE_URL: 'http://localhost:8080',
};
const job = {
  reservationUid: 'reservation', libraryUid: 'library', bookUid: 'book', username: 'auth0|original-user',
  originalCondition: '', returnedCondition: 'EXCELLENT', expired: false, stage: 'RESTORE_BOOK',
};
const entries = value => [['1-0', ['payload', JSON.stringify(value)]]];

test('failure injection only accepts disposable Compose projects and a loopback Gateway', () => {
  assert.equal(settings(env).project, env.COMPOSE_PROJECT_NAME);
  for (const project of ['', 'production', 'lab5-ci-', '--help', 'lab5-ci-x/../y']) {
    assert.throws(() => settings({ ...env, COMPOSE_PROJECT_NAME: project }), /disposable/);
  }
  for (const baseURL of ['https://production.example', 'http://localhost:8081', 'http://user@localhost:8080']) {
    assert.throws(() => settings({ ...env, BASE_URL: baseURL }));
  }
});

test('queued work must have the original identity, expected stage, and no JWT/credential fields', () => {
  const expected = { username: job.username, stage: 'RESTORE_BOOK' };
  assert.deepEqual(inspectJobs(entries(job), expected, new Set(['worker-secret'])), job);
  for (const value of [
    { ...job, username: 'auth0|someone-else' },
    { ...job, stage: 'UPDATE_RATING' },
    { ...job, access_token: 'credential' },
    { ...job, username: 'worker-secret' },
    { ...job, username: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln' },
  ]) assert.throws(() => inspectJobs(entries(value), expected, new Set(['worker-secret'])));
  assert.throws(() => inspectJobs([], expected, new Set()));
  assert.throws(() => inspectJobs([entries(job)[0], entries(job)[0]], expected, new Set()));
});

test('polling cannot swallow a permanent error or wait forever', async () => {
  await assert.rejects(waitFor('authorization', async () => { throw new Error('HTTP 401'); }), /401/);
  await assert.rejects(waitFor('queue', async () => false, () => new Promise(resolve => setTimeout(resolve, 2)), 5), /Timed out: queue/);
});

function driver({ discard = false, duplicate = false } = {}) {
  const state = { stopped: false, restarted: false, rented: false, returned: false, job: null, count: 3, stars: 76, commands: [] };
  const token = 'test-user-token';
  return { state, io: {
    grant: async () => ({ token, subject: job.username }),
    api: async (url, bearer, method = 'GET', _body, expected = 200) => {
      const parsed = new URL(url);
      if (parsed.pathname === '/manage/health') return { status: 'ok' };
      assert.equal(bearer, token);
      if (state.restarted) assert.notEqual(parsed.port, '8080', 'No user API calls to Gateway after restart');
      if (parsed.pathname.startsWith('/internal/')) { assert.equal(expected, 401); return; }
      if (parsed.pathname === '/api/v1/libraries') return { items: [{ libraryUid: job.libraryUid }] };
      if (parsed.pathname.endsWith('/books')) return { items: [{ bookUid: job.bookUid, availableCount: state.count, condition: 'EXCELLENT' }] };
      if (parsed.pathname.endsWith('/books/book')) return { availableCount: state.count, condition: 'EXCELLENT' };
      if (parsed.pathname === '/api/v1/rating') return { stars: state.stars };
      if (parsed.pathname === '/api/v1/reservations' && method === 'POST') {
        state.rented = true; state.count--;
        return { reservationUid: job.reservationUid, status: 'RENTED' };
      }
      if (parsed.pathname.endsWith('/return')) {
        assert(state.rented && state.stopped); assert.equal(expected, 204);
        state.returned = true; state.job = { ...job };
        return;
      }
      if (parsed.pathname.endsWith('/reservations/reservation')) return { status: state.returned ? 'RETURNED' : 'RENTED' };
      throw new Error('Unexpected test request');
    },
    command: async (...args) => {
      state.commands.push(args);
      if (args[0] === 'stop') state.stopped = true;
      if (args[0] === 'restart') { assert(state.job); state.restarted = true; }
      if (args[0] === 'start' && args.length === 2 && args[1] === 'library-service') {
        assert(state.restarted);
        state.count++;
        state.job = discard ? null : { ...job, originalCondition: 'EXCELLENT', stage: 'UPDATE_RATING' };
      }
      if (args[0] === 'start' && args.length === 2 && args[1] === 'rating-service') {
        assert.equal(state.job.stage, 'UPDATE_RATING');
        state.stars += duplicate ? 2 : 1; state.job = null;
      }
    },
    redisCommand: async command => {
      if (command === 'XLEN') return state.job ? 1 : 0;
      if (command === 'XPENDING') return [state.job ? 1 : 0];
      if (command === 'XRANGE') return state.job ? entries(state.job) : [];
      throw new Error('Unexpected Redis command');
    },
    wait: async (label, predicate) => { assert(await predicate(), label); },
  } };
}

test('driver covers both stages after Gateway restart and writes a passing report', async () => {
  const { state, io } = driver();
  const result = { passed: [] };
  await scenario(settings(env), new Set(['worker-secret']), async (name, operation) => { await operation(); result.passed.push(name); }, io);
  assert.equal(result.passed.length, 8);
  assert.equal(state.stars, 77);
  assert.equal(state.count, 3);
  assert.equal(state.job, null);
  assert.deepEqual(state.commands.at(-1), ['start', 'library-service', 'rating-service', 'gateway-service']);
  assert.match(report(result), /tests="8" failures="0"/);
});

test('discarded jobs or duplicate effects fail the driver and always restore availability', async () => {
  for (const options of [{ discard: true }, { duplicate: true }]) {
    const { state, io } = driver(options);
    await assert.rejects(scenario(settings(env), new Set(), async (_name, operation) => operation(), io));
    assert.deepEqual(state.commands.at(-1), ['start', 'library-service', 'rating-service', 'gateway-service']);
  }
  assert.match(report({ passed: ['done'], step: 'stage <1>', failure: 'HTTP "401"' }), /failures="1"/);
  assert.match(report({ passed: [], step: 'stage <1>', failure: 'HTTP "401"' }), /stage &lt;1&gt;/);
});
