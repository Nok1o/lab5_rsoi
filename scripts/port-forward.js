'use strict';

// Native Kubernetes WebSocket channels, not kubectl's SPDY-over-WebSocket.
// AWS authentication and the EKS CA come from the existing local kubeconfig.
const net = require('node:net');
const { Writable } = require('node:stream');

function target(service, pods, port) {
  const servicePort = service.spec?.ports?.find(value => value.port === Number(port));
  if (!servicePort || servicePort.protocol && servicePort.protocol !== 'TCP') throw new Error('Expected a TCP Service port');
  const pod = pods.items.find(value => !value.metadata.deletionTimestamp &&
    value.status?.conditions?.some(condition => condition.type === 'Ready' && condition.status === 'True'));
  if (!pod) throw new Error('No ready Pod for the Service');
  const remote = servicePort.targetPort ?? servicePort.port;
  const resolved = typeof remote === 'number' ? remote : pod.spec.containers.flatMap(value => value.ports || [])
    .find(value => value.name === remote && (!value.protocol || value.protocol === 'TCP'))?.containerPort;
  if (!Number.isInteger(resolved) || resolved < 1 || resolved > 65535) throw new Error('Could not resolve Service targetPort');
  return { name: pod.metadata.name, port: resolved };
}

async function connector({ context, namespace, service, port }) {
  const { KubeConfig, CoreV1Api, PortForward } = await import('@kubernetes/client-node');
  const { WebSocketHandler } = await import('@kubernetes/client-node/dist/web-socket-handler.js');
  const { default: WebSocket } = await import('ws');
  const config = new KubeConfig();
  config.loadFromDefault();
  config.setCurrentContext(context);
  const cluster = config.getCurrentCluster();
  if (!cluster?.server?.startsWith('https://') || cluster.skipTLSVerify || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
    throw new Error('Port-forward requires an HTTPS Kubernetes API with certificate verification');
  }
  const api = config.makeApiClient(CoreV1Api);
  const signal = () => ({ signal: AbortSignal.timeout(7000) });
  const spec = await api.readNamespacedService({ namespace, name: service }, signal());
  const selector = Object.entries(spec.spec?.selector || {}).map(([key, value]) => `${key}=${value}`).join(',');
  if (!selector) throw new Error('Service has no Pod selector');
  const pods = await api.listNamespacedPod({ namespace, labelSelector: selector }, signal());
  const pod = target(spec, pods, port);
  const handler = new WebSocketHandler(config, (uri, protocols, options) =>
    new WebSocket(uri, protocols, { ...options, handshakeTimeout: 7000, rejectUnauthorized: true }));
  const forward = new PortForward(config, true, handler);
  // No automatic retry: replaying bytes could repeat a POST/PATCH operation.
  return (socket, errors) => forward.portForward(namespace, pod.name, [pod.port], socket, errors, socket, 0);
}

async function openForward(options, makeConnector = connector) {
  const { localPort = 0 } = options;
  if (!Number.isInteger(localPort) || localPort < 0 || localPort > 65535) throw new Error('Invalid local port');
  let connect;
  try { connect = await makeConnector(options); }
  catch { throw new Error('Could not resolve a ready Service Pod using the verified Kubernetes connection'); }
  const sockets = new Set(), channels = new Set();
  let closed = false;
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.pause();
    socket.setTimeout(20000, () => socket.destroy());
    socket.on('error', () => {}); // Never log socket/runtime objects containing credentials.
    let channel;
    socket.on('close', () => {
      sockets.delete(socket);
      channel?.terminate();
    });
    const errors = new Writable({ write(chunk, _encoding, done) {
      if (chunk.length) socket.destroy();
      done();
    } });
    Promise.resolve().then(() => connect(socket, errors)).then(ws => {
      channel = ws;
      if (closed || socket.destroyed) { ws.terminate(); return; }
      channels.add(ws);
      ws.on('close', () => { channels.delete(ws); socket.end(); });
      ws.on('error', () => socket.destroy());
      socket.resume();
    }, () => socket.destroy());
  });
  const close = () => {
    closed = true;
    for (const socket of sockets) socket.destroy();
    for (const channel of channels) channel.terminate();
    server.close();
  };
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(localPort, '127.0.0.1', resolve);
  });
  server.on('error', close);
  return { url: `http://127.0.0.1:${server.address().port}`, close, isAlive: () => !closed && server.listening };
}

async function health(forward) {
  try {
    const response = await fetch(`${forward.url}/manage/health`, { redirect: 'error', signal: AbortSignal.timeout(10000) });
    if (response.status === 200 && (await response.json()).status === 'ok') return;
  } catch { /* Report only a fixed message, never raw TLS/authentication state. */ }
  throw new Error('Port-forward healthcheck failed; tests were not started. Check API access and the VPN connection');
}

module.exports = { target, openForward, health };
if (require.main === module) {
  const ports = { 'gateway-service': 8080, 'library-service': 8060, 'rating-service': 8050, 'reservation-service': 8070, traefik: 80 };
  const service = process.argv[2] || 'traefik';
  let forward;
  (async () => {
    if (!ports[service]) throw new Error('Unsupported service');
    forward = await openForward({ context: 'rsoi-lab5-aws', namespace: service === 'traefik' ? 'ingress-system' : 'library-system',
      service, port: ports[service], localPort: Number(process.argv[3] || 18080) });
    await health(forward);
    console.log(`Forwarding ${forward.url} -> ${service} (TLS-verified Kubernetes WebSocket); health=200`);
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => forward.close());
  })().catch(() => {
    forward?.close();
    console.error('Could not establish a verified Kubernetes WebSocket port-forward; check aws login, kubeconfig, VPN and RBAC');
    process.exitCode = 1;
  });
}
