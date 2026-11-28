'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { verify, main } = require('./grade-results');

function reports(t) {
  const files = {
    'outcomes.json': JSON.stringify({ oauth: 'success', worker: 'success' }),
    'newman.xml': '<testsuites><testsuite name="Lab5 OAuth collection" tests="1" failures="0"><testcase name="14 assertions passed"/></testsuite></testsuites>',
    'worker.xml': '<testsuites><testsuite name="Lab5 Auth0 deferred worker" tests="8" failures="0"></testsuite></testsuites>',
    'newman.log': 'Original Newman requests, assertions and statistics table\n',
  };
  t.mock.method(fs, 'readFileSync', file => {
    const name = path.basename(file);
    if (!(name in files)) throw new Error('Missing report');
    return files[name];
  });
  return files;
}

test('original grader receives the exact CLI output, without a handmade success banner', t => {
  const files = reports(t), output = [];
  t.mock.method(process.stdout, 'write', value => { output.push(value); return true; });
  main('/reports');
  assert.equal(output.join(''), files['newman.log']);
  assert(!output.join('').includes('🦄'));
});

test('failed, skipped or missing real steps cannot receive a passing grade', t => {
  const files = reports(t);
  for (const outcome of ['failure', 'skipped', '', 'cancelled']) {
    for (const name of ['oauth', 'worker']) {
      files['outcomes.json'] = JSON.stringify({ oauth: 'success', worker: 'success', [name]: outcome });
      assert.throws(() => verify('/reports'), /both succeed/);
    }
  }
  delete files['outcomes.json'];
  assert.throws(() => verify('/reports'));
});

test('incomplete or failed XML reports cannot receive a passing grade', t => {
  const files = reports(t);
  for (const name of ['newman.xml', 'worker.xml']) {
    const original = files[name];
    files[name] = original.replace('failures="0"', 'failures="1"');
    assert.throws(() => verify('/reports'));
    files[name] = original.replace(name === 'newman.xml' ? '14 assertions' : 'tests="8"', name === 'newman.xml' ? '13 assertions' : 'tests="7"');
    assert.throws(() => verify('/reports'));
    files[name] = original;
  }
});
