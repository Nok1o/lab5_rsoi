'use strict';

// Newman receives credentials in memory, never in command-line arguments or an
// exported environment/report. Use the complete standard CLI reporter;
// redact credential values before it formats console messages and failures.
const fs = require('node:fs');
const path = require('node:path');
const { inspect } = require('node:util');

function required(env, name) {
  const value = env[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`Set ${name}`);
  return value;
}

function endpoint(value, label, protocols) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${label} must be an absolute URL`); }
  if (!protocols.includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${label} has an unsupported scheme, credentials, query or fragment`);
  }
  return parsed;
}

function configuration(env, variant) {
  if (variant !== 'v4') throw new Error('Only the selected variant v4 is supported');
  const issuerValue = required(env, 'OIDC_ISSUER').trim();
  const issuer = endpoint(issuerValue, 'OIDC_ISSUER', ['https:']);
  if (!issuerValue.endsWith('/')) throw new Error('OIDC_ISSUER must include its trailing slash');
  const base = endpoint(env.BASE_URL || 'http://localhost:8080', 'BASE_URL', ['http:', 'https:']);
  return {
    issuer: issuer.href,
    baseURL: base.href.replace(/\/$/, ''),
    audience: required(env, 'OIDC_AUDIENCE').trim(),
    username: required(env, 'AUTH0_TEST_USERNAME'),
    password: required(env, 'AUTH0_TEST_PASSWORD'),
    clientID: required(env, 'AUTH0_TEST_CLIENT_ID').trim(),
    clientSecret: required(env, 'AUTH0_TEST_CLIENT_SECRET'),
  };
}

function environment(config, tokenEndpoint) {
  return { name: 'Lab5 runtime (not exported)', values: Object.entries({
    serviceUrl: config.baseURL,
    identityProviderUrl: config.issuer.replace(/\/$/, ''),
    tokenEndpoint,
    audience: config.audience,
    username: config.username,
    password: config.password,
    clientId: config.clientID,
    clientSecret: config.clientSecret,
  }).map(([key, value]) => ({ key, value, enabled: true })) };
}

async function discover(config) {
  const response = await fetch(config.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration', {
    redirect: 'error', signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`OIDC discovery returned HTTP ${response.status}`);
  const chunks = [];
  let size = 0;
  const reader = response.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 1024 * 1024) {
      await reader.cancel();
      throw new Error('OIDC discovery response is too large');
    }
    chunks.push(Buffer.from(value));
  }
  const text = Buffer.concat(chunks).toString('utf8');
  let metadata;
  try { metadata = JSON.parse(text); } catch { throw new Error('OIDC discovery returned invalid JSON'); }
  if (metadata.issuer !== config.issuer) throw new Error('OIDC discovery returned a different issuer');
  const token = endpoint(metadata.token_endpoint, 'OIDC token_endpoint', ['https:']);
  if (token.origin !== new URL(config.issuer).origin) throw new Error('OIDC token_endpoint must have the issuer origin');
  return token.href;
}

function redact(value, sensitive) {
  let text = String(value || '');
  for (const secret of sensitive) {
    if (!secret) continue;
    for (const form of new Set([secret, encodeURIComponent(secret), new URLSearchParams({ v: secret }).toString().slice(2), JSON.stringify(secret).slice(1, -1), inspect(secret, { colors: false }).slice(1, -1)])) {
      text = text.split(form).join('[REDACTED]');
    }
  }
  // Also cover JWTs from an unexpected error response or failure message.
  return text.replace(/\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED JWT]');
}

function protectCLI(run, sensitive) {
  // Keep every report section enabled. Only credential values are replaced;
  // assertion results, counts and failure details otherwise remain unchanged.
  run.prependListener('console', (_error, args) => {
    args.messages = args.messages.map(value => redact(typeof value === 'string' ? value : inspect(value, { depth: null, colors: false }), sensitive));
  });
  run.prependListener('done', (_error, summary) => {
    for (const failure of summary?.run?.failures || []) {
      for (const key of ['name', 'test', 'message', 'stack']) {
        if (typeof failure.error?.[key] === 'string') failure.error[key] = redact(failure.error[key], sensitive);
      }
    }
  });
}

function xml(value) {
  return String(value).replace(/[<>&"']/g, char => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[char]));
}

function safeResult(summary, sensitive) {
  const failures = (summary.run.failures || []).map(failure => ({
    name: redact(failure.error && failure.error.test || failure.source && failure.source.name || 'Collection failure', sensitive),
    message: redact(failure.error && failure.error.message || 'Request or assertion failed', sensitive),
  }));
  const stats = summary.run.stats;
  if (stats.requests.total !== 14 || stats.assertions.total < 14) {
    failures.push({ name: 'Collection completeness', message: 'The complete 14-request collection with assertions did not run' });
  }
  if ((summary.run.error || Object.values(stats).some(stat => stat && stat.failed > 0)) && failures.length === 0) {
    failures.push({ name: 'Collection runtime', message: 'A request, script or assertion failed' });
  }
  return {
    requests: stats.requests.total,
    assertions: stats.assertions.total,
    failedAssertions: stats.assertions.failed,
    failures,
  };
}

function junit(result) {
  const failures = result.failures.map(failure => `<testcase name="${xml(failure.name)}"><failure message="${xml(failure.message)}"/></testcase>`).join('\n');
  const passed = Math.max(0, result.assertions - result.failedAssertions);
  // This is a sanitized aggregate, not Newman's raw request/response report.
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="Lab5 OAuth collection" tests="${result.failures.length + (passed > 0 ? 1 : 0)}" failures="${result.failures.length}">\n${passed > 0 ? `<testcase name="${passed} assertions passed"/>` : ''}\n${failures}\n</testsuite></testsuites>\n`;
}

async function main(env = process.env, variant = process.argv[2] || 'v4') {
  const config = configuration(env, variant);
  const sensitive = new Set([config.username, config.password, config.clientID, config.clientSecret]);
  try {
    const tokenEndpoint = await discover(config);
    const newman = require('newman');
    const collection = JSON.parse(fs.readFileSync(path.join(__dirname, '..', variant, 'postman', 'collection.json'), 'utf8'));
    const summary = await new Promise((resolve, reject) => {
      const run = newman.run({
        collection, environment: environment(config, tokenEndpoint), reporters: ['cli'],
        verbose: false,
        timeout: 120000, timeoutRequest: 15000, timeoutScript: 5000,
        ignoreRedirects: true, bail: false,
      }, (error, result) => error ? reject(error) : resolve(result));
      protectCLI(run, sensitive);
      run.prependListener('request', (error, args) => {
        if (typeof error?.message === 'string') error.message = redact(error.message, sensitive);
        if (!args.response) return;
        // Capture credentials for redaction only; never print/store bodies.
        try {
          const body = args.response.json();
          for (const key of ['access_token', 'id_token', 'refresh_token']) if (typeof body[key] === 'string') sensitive.add(body[key]);
        } catch { /* Ordinary non-JSON/empty API responses are not credentials. */ }
      });
    });
    const result = safeResult(summary, sensitive);
    console.log(`Requests: ${result.requests}; assertions: ${result.assertions}; failures: ${result.failures.length}`);
    for (const failure of result.failures) console.error(`${failure.name}: ${failure.message}`);
    const reportDirectory = path.resolve(env.TEST_REPORT_DIR || path.join(__dirname, '..', 'test-reports'));
    fs.mkdirSync(reportDirectory, { recursive: true });
    fs.writeFileSync(path.join(reportDirectory, 'newman.xml'), junit(result), { mode: 0o600 });
    if (result.requests !== 14 || result.assertions < 14 || result.failures.length > 0) process.exitCode = 1;
    return result;
  } catch (error) {
    // Error objects can include full runtime state; never dump the object/stack.
    throw new Error(redact(error.message, sensitive));
  }
}

module.exports = { configuration, environment, redact, safeResult, junit, discover, protectCLI, main };
if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
