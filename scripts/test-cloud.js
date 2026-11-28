'use strict';

// Same OAuth collection and worker assertions as Compose CI. Kubernetes is real;
// Local runs use TLS-protected port-forwards. An explicit in-cluster mode uses
// private Service DNS instead. Neither mode sends Bearer through the public NLB.
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { configuration, redact, main: collection } = require('./run-postman');
const { scenario, request, userToken, waitFor, report } = require('./test-worker');
const { openForward, health } = require('./port-forward');
const exec = promisify(execFile);
const services = { 8080: 'gateway-service', 8060: 'library-service', 8050: 'rating-service', 8070: 'reservation-service' };

function cloudSettings(env) {
  if (env.KUBE_CONTEXT !== 'rsoi-lab5-aws' || env.KUBE_NAMESPACE !== 'library-system') {
    throw new Error('Cloud test is restricted to context rsoi-lab5-aws, namespace library-system');
  }
  if (env.WORKER_TEST_ALLOW_FAILURE_INJECTION !== 'yes') {
    throw new Error('Set WORKER_TEST_ALLOW_FAILURE_INJECTION=yes: this test temporarily scales Library/Rating to zero and restarts Gateway');
  }
  const internalNetwork = env.CLOUD_TEST_INTERNAL_NETWORK === 'yes';
  if (internalNetwork && !fs.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token')) {
    throw new Error('Private Service DNS mode is allowed only inside a Kubernetes Pod');
  }
  return { ...configuration({ ...env, BASE_URL: 'http://127.0.0.1:8080' }, 'v4'), context: env.KUBE_CONTEXT, namespace: env.KUBE_NAMESPACE, internalNetwork };
}

function mutation(args, replicas) {
  const [action, ...rest] = args;
  const targets = rest.filter(value => Object.values(services).includes(value));
  if (action === 'restart' && targets.length === 1 && targets[0] === 'gateway-service') {
    return [['rollout', 'restart', 'deployment/gateway-service'], ['rollout', 'status', 'deployment/gateway-service', '--timeout=120s']];
  }
  if (!['start', 'stop'].includes(action) || targets.length === 0 || new Set(targets).size !== targets.length ||
      targets.some(name => !['library-service', 'rating-service', ...(action === 'start' ? ['gateway-service'] : [])].includes(name))) {
    throw new Error('Unsupported cloud failure-injection operation');
  }
  return targets.map(name => {
    if (!Number.isInteger(replicas[name]) || replicas[name] < 1) throw new Error('Missing original replica count');
    return ['scale', `deployment/${name}`, `--replicas=${action === 'stop' ? 0 : replicas[name]}`];
  });
}

async function main(env = process.env) {
  const config = cloudSettings(env);
  const sensitive = new Set([config.username, config.password, config.clientSecret, env.OIDC_WORKER_CLIENT_SECRET]);
  const replicas = {}, forwards = new Map(), touched = new Set();
  const result = { passed: [], step: 'Cloud preflight', failure: '' };
  async function kubectl(args, namespace = config.namespace) {
    try {
      return (await exec('kubectl', ['--context', config.context, '--namespace', namespace, ...args], { timeout: 150000, maxBuffer: 1024 * 1024 })).stdout;
    } catch {
      throw new Error('Kubernetes operation failed; check API access, RBAC and workload readiness');
    }
  }
  function close(service) {
    const forward = forwards.get(service);
    if (forward) forward.close();
    forwards.delete(service);
  }
  async function tunnel(service, port, namespace = config.namespace) {
    if (config.internalNetwork) return `http://${service}.${namespace}.svc.cluster.local:${port}`;
    const existing = forwards.get(service);
    if (existing?.isAlive()) return existing.url;
    close(service);
    const forward = await openForward({ context: config.context, namespace, service, port: Number(port) });
    forwards.set(service, forward);
    await health(forward);
    return forward.url;
  }
  async function api(url, ...args) {
    const parsed = new URL(url);
    const service = services[parsed.port];
    if (parsed.hostname !== '127.0.0.1' || !service) throw new Error('Unexpected test destination');
    const base = service === 'gateway-service' ? await tunnel('traefik', 80, 'ingress-system') : await tunnel(service, parsed.port);
    return request(base + parsed.pathname + parsed.search, ...args);
  }
  async function command(...args) {
    const plan = mutation(args, replicas);
    for (const operation of plan) {
      const name = operation.find(value => value.startsWith('deployment/'))?.slice('deployment/'.length);
      if (operation[0] === 'scale') { touched.add(name); close(name); }
      await kubectl(operation);
      if (operation[0] === 'scale') {
        if (args[0] === 'stop') {
          await waitFor('all service Pods stopped', async () => {
            const pods = JSON.parse(await kubectl(['get', 'pods', '-l', `app.kubernetes.io/instance=${name}`, '-o', 'json']));
            return pods.items.length === 0;
          });
        } else {
          await kubectl(['rollout', 'status', `deployment/${name}`, '--timeout=120s']);
        }
      }
    }
  }
  try {
    const deployments = JSON.parse(await kubectl(['get', 'deployments', ...Object.values(services), '-o', 'json']));
    for (const deployment of deployments.items) {
      const name = deployment.metadata.name;
      const count = deployment.spec.replicas;
      if (!Object.values(services).includes(name) || !Number.isInteger(count) || count < 1 || deployment.status.availableReplicas !== count ||
          !deployment.spec.template.spec.containers.every(container => /(?:^|\/)nok1o\/lab5_rsoi:/.test(container.image))) {
        throw new Error('Expected four healthy Lab5 deployments before failure injection');
      }
      replicas[name] = count;
    }
    if (Object.keys(replicas).length !== 4) throw new Error('Expected all four Lab5 deployments');
    const base = await tunnel('traefik', 80, 'ingress-system');
    // Verify every route before acquiring user tokens or running mutating tests.
    for (const [port, service] of Object.entries(services)) {
      if (service !== 'gateway-service') await tunnel(service, port);
    }
    console.log('PASS: TLS-protected port-forwards and all four healthchecks');
    const summary = await collection({ ...env, BASE_URL: base }, 'v4');
    if (summary.failures.length > 0) throw new Error('OAuth collection failed; cloud failure injection was not started');
    result.step = 'Missing/malformed credentials rejected by all four services';
    for (const [port, route] of [[8080, '/api/v1/rating'], [8060, '/api/v1/libraries?city=test'], [8050, '/api/v1/rating'], [8070, '/api/v1/reservations']]) {
      for (const token of [undefined, 'not-a-jwt']) await api(`http://127.0.0.1:${port}${route}`, token, 'GET', undefined, 401);
    }
    console.log(`PASS: ${result.step} (8 HTTP checks)`);
    await scenario(config, sensitive, async (name, operation) => {
      result.step = name;
      await operation();
      result.passed.push(name);
      console.log(`PASS: ${name}`);
    }, {
      api, command, grant: () => userToken(config, sensitive), wait: (label, predicate) => waitFor(label, predicate),
      redisCommand: async (...args) => {
        // REDISCLI_AUTH is already injected into the Redis container by Secret.
        // No Redis password is read or passed through command-line arguments.
        const output = await kubectl(['exec', 'statefulset/library-infra-redis', '--', 'redis-cli', '--json', ...args]);
        try { return JSON.parse(output); } catch { throw new Error('Redis returned an unexpected response'); }
      },
    });
  } catch (error) {
    result.failure = redact(error.message, sensitive);
    console.error(`FAIL: ${result.step}: ${result.failure}`);
    process.exitCode = 1;
  } finally {
    // Restore original replicas on ordinary failure, including failure inside
    // scenario cleanup. A forcibly killed process still requires manual recovery.
    for (const name of touched) {
      try { await kubectl(['scale', `deployment/${name}`, `--replicas=${replicas[name]}`]); }
      catch { result.failure ||= 'Failed to restore original replicas; restore Library/Rating manually'; process.exitCode = 1; }
    }
    for (const service of forwards.keys()) close(service);
  }
  const directory = path.resolve(env.TEST_REPORT_DIR || path.join(__dirname, '..', 'test-reports'));
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'worker-cloud.xml'), report(result), { mode: 0o600 });
  console.log(`Cloud worker checks: ${result.passed.length}; failures: ${result.failure ? 1 : 0}`);
}

module.exports = { cloudSettings, mutation };
if (require.main === module) main().catch(() => { console.error('Cloud test configuration or report failed; check required variables and failure-injection consent'); process.exitCode = 1; });
