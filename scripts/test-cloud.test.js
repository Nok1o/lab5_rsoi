'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { cloudSettings, mutation } = require('./test-cloud');
const env = {
  OIDC_ISSUER: 'https://tenant.example/', OIDC_AUDIENCE: 'https://library-system',
  AUTH0_TEST_USERNAME: 'user@example.test', AUTH0_TEST_PASSWORD: 'test-password',
  AUTH0_TEST_CLIENT_ID: 'test-client', AUTH0_TEST_CLIENT_SECRET: 'test-secret',
  KUBE_CONTEXT: 'rsoi-lab5-aws', KUBE_NAMESPACE: 'library-system', WORKER_TEST_ALLOW_FAILURE_INJECTION: 'yes',
};

test('cloud test is restricted to the explicit Lab5 context/namespace and requires consent', () => {
  assert.equal(cloudSettings(env).baseURL, 'http://127.0.0.1:8080');
  for (const values of [{ KUBE_CONTEXT: 'production' }, { KUBE_NAMESPACE: 'kube-system' }, { WORKER_TEST_ALLOW_FAILURE_INJECTION: '' }]) {
    assert.throws(() => cloudSettings({ ...env, ...values }));
  }
  if (!require('node:fs').existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token')) {
    assert.throws(() => cloudSettings({ ...env, CLOUD_TEST_INTERNAL_NETWORK: 'yes' }), /only inside/);
  }
});

test('failure injection scales only Library/Rating, preserves replica counts and restarts only Gateway', () => {
  const replicas = { 'library-service': 2, 'rating-service': 1, 'gateway-service': 1 };
  assert.deepEqual(mutation(['stop', '--timeout', '20', 'library-service', 'rating-service'], replicas), [
    ['scale', 'deployment/library-service', '--replicas=0'], ['scale', 'deployment/rating-service', '--replicas=0'],
  ]);
  assert.deepEqual(mutation(['start', 'library-service'], replicas), [['scale', 'deployment/library-service', '--replicas=2']]);
  assert.deepEqual(mutation(['restart', '--timeout', '20', 'gateway-service'], replicas), [
    ['rollout', 'restart', 'deployment/gateway-service'], ['rollout', 'status', 'deployment/gateway-service', '--timeout=120s'],
  ]);
  for (const args of [['stop', 'gateway-service'], ['stop', 'reservation-service'], ['stop', 'library-service', 'library-service'], ['delete', 'library-service'], ['start', 'unknown-service'], ['restart', 'library-service']]) {
    assert.throws(() => mutation(args, replicas));
  }
  assert.throws(() => mutation(['start', 'rating-service'], {}));
});
