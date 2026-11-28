'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { target, openForward, health } = require('./port-forward');

const pod = (name, ready, extra = {}) => ({ metadata: { name, ...extra },
  status: { conditions: [{ type: 'Ready', status: ready ? 'True' : 'False' }] },
  spec: { containers: [{ ports: [{ name: 'web', containerPort: 8000 }] }] } });

test('Service port maps to a ready Pod targetPort, including Traefik 80 -> 8000', () => {
  const pods = { items: [pod('not-ready', false), pod('terminating', true, { deletionTimestamp: 'now' }), pod('ready', true)] };
  for (const targetPort of ['web', 8000]) {
    assert.deepEqual(target({ spec: { ports: [{ port: 80, targetPort }] } }, pods, 80), { name: 'ready', port: 8000 });
  }
  assert.throws(() => target({ spec: { ports: [{ port: 80 }] } }, { items: [] }, 80), /No ready/);
  assert.throws(() => target({ spec: { ports: [{ port: 80, targetPort: 'missing' }] } }, pods, 80), /targetPort/);
  assert.throws(() => target({ spec: { ports: [{ port: 80, protocol: 'UDP' }] } }, pods, 80), /TCP/);
});

test('local tunnel listens only on loopback, passes healthcheck, and closes its channels', async () => {
  let connects = 0, terminations = 0;
  const forward = await openForward({}, async () => async socket => {
    connects++;
    const ws = new EventEmitter();
    ws.terminate = () => { terminations++; ws.emit('close'); };
    socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{"status":"ok"}'));
    return ws;
  });
  try {
    assert.equal(new URL(forward.url).hostname, '127.0.0.1');
    await health(forward);
    assert.equal(connects, 1);
  } finally { forward.close(); }
  assert.equal(forward.isAlive(), false);
  assert.ok(terminations >= 1);
});

test('connection failure is not replayed and fails preflight without exposing raw credentials', async () => {
  let connects = 0;
  const forward = await openForward({}, async () => async () => {
    connects++;
    throw new Error('SECRET-TLS-STATE');
  });
  try {
    await assert.rejects(health(forward), error => /tests were not started/.test(error.message) && !error.message.includes('SECRET'));
    assert.equal(connects, 1);
  } finally { forward.close(); }
});

test('invalid local ports are rejected before loading credentials', async () => {
  for (const localPort of [-1, 65536, '18080']) await assert.rejects(openForward({ localPort }), /Invalid local port/);
});
