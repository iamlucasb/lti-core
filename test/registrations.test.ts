import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type { LtiTool, Registration } from '../src/index.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const target = 'https://tool.example/launch';
const otherTarget = 'https://tool.example/other';
const issuerA = 'https://platform-a.example';
const issuerB = 'https://platform-b.example';
let server: Server;
let port: number;
const keys = new Map<string, { privateKey: CryptoKey; jwk: Record<string, unknown> }>();

before(async () => {
  for (const name of ['a', 'a2', 'b']) {
    const pair = await generateKeyPair('RS256', { extractable: true });
    keys.set(name, { privateKey: pair.privateKey,
      jwk: { ...await exportJWK(pair.publicKey), kid: 'shared-kid', alg: 'RS256', use: 'sig' } });
  }
  server = createServer(tlsOptions, (request, response) => {
    const name = request.url?.slice(1) ?? '';
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: keys.has(name) ? [keys.get(name)!.jwk] : [] }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  port = address.port;
});
after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

function registrations(): Registration[] {
  return [
    { issuer: issuerA, clientId: 'client-a', authorizationEndpoint: issuerA + '/authorize',
      jwksUri: `https://127.0.0.1:${port}/a`, deployments: ['a-one', 'a-two'], allowedTargetLinkUris: [target] },
    { issuer: issuerA, clientId: 'client-a2', authorizationEndpoint: issuerA + '/authorize',
      jwksUri: `https://127.0.0.1:${port}/a2`, deployments: ['a2-one'], allowedTargetLinkUris: [otherTarget] },
    { issuer: issuerB, clientId: 'client-b', authorizationEndpoint: issuerB + '/authorize',
      jwksUri: `https://127.0.0.1:${port}/b`, deployments: ['b-one'], allowedTargetLinkUris: [target] },
  ];
}

function setup(config = registrations()) {
  return createLtiTool({ resolver: { async resolve(issuer: string) { return config.filter(r => r.issuer === issuer); } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore() });
}

interface Login {
  iss: string;
  target_link_uri: string;
  login_hint: string;
  client_id?: string;
  lti_deployment_id?: string;
}

function login(iss: string, target_link_uri = target, extra: Record<string, string> = {}): Login {
  return { iss, target_link_uri, login_hint: 'opaque', ...extra };
}
async function signed(key: string, iss: string, aud: string, nonce: string, deploymentId: string,
  targetLinkUri = target, changes: Record<string, unknown> = {}) {
  return signLaunch({ privateKey: keys.get(key)!.privateKey, kid: 'shared-kid', issuer: iss,
    audience: aud, subject: 'same-sub', nonce, deploymentId, targetLinkUri, resourceLinkId: 'link-1',
    roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'], changes });
}

async function attempt(tool: LtiTool, request: Login, key: string,
  aud: string, deploymentId: string, changes: Record<string, unknown> = {}, targetLinkUri = request.target_link_uri) {
  const url = new URL((await tool.initiate(request)).url);
  const state = url.searchParams.get('state')!;
  const nonce = url.searchParams.get('nonce')!;
  return { url, launch: async () => tool.validate({ state, id_token: await signed(key, request.iss, aud, nonce,
    deploymentId, targetLinkUri, changes) }) };
}
function rejects(code: string) {
  return (error: unknown) => {
    assert.ok(error instanceof LtiError);
    assert.equal(error.code, code);
    assert.equal(error.message, `${code}: ${error.reason}`);
    return true;
  };
}

test('two issuers and two registrations under one issuer isolate identity and preserve it across deployments', async () => {
  const tool = setup();
  for (const scenario of [
    { iss: issuerA, targetUri: target, key: 'a', client: 'client-a', deployment: 'a-one' },
    { iss: issuerA, targetUri: target, key: 'a', client: 'client-a', deployment: 'a-two' },
    { iss: issuerA, targetUri: otherTarget, key: 'a2', client: 'client-a2', deployment: 'a2-one' },
    { iss: issuerB, targetUri: target, key: 'b', client: 'client-b', deployment: 'b-one' },
  ]) {
    const { url, launch } = await attempt(tool, login(scenario.iss, scenario.targetUri),
      scenario.key, scenario.client, scenario.deployment);
    assert.equal(url.origin + url.pathname, scenario.iss + '/authorize');
    assert.equal(url.searchParams.get('client_id'), scenario.client);
    const context = await launch();
    assert.deepEqual(context.platform, { issuer: scenario.iss, clientId: scenario.client,
      deploymentId: scenario.deployment });
    assert.equal(context.user.id, 'same-sub');
    assert.equal(context.targetLinkUri, scenario.targetUri);
  }
});

test('simultaneous launches scope a shared client id and state by issuer', async () => {
  const config = registrations();
  config[2] = { ...config[2]!, clientId: 'client-a' };
  const tool = setup(config);
  const [platformA, platformB] = await Promise.all([
    attempt(tool, login(issuerA), 'a', 'client-a', 'a-one'),
    attempt(tool, login(issuerB), 'b', 'client-a', 'b-one'),
  ]);
  const stateA = platformA.url.searchParams.get('state')!;
  const stateB = platformB.url.searchParams.get('state')!;
  assert.notEqual(stateA, stateB);
  assert.notEqual(platformA.url.searchParams.get('nonce'), platformB.url.searchParams.get('nonce'));
  assert.equal(platformA.url.origin + platformA.url.pathname, issuerA + '/authorize');
  assert.equal(platformB.url.origin + platformB.url.pathname, issuerB + '/authorize');

  const [contextA, contextB] = await Promise.all([platformA.launch(), platformB.launch()]);
  assert.equal(contextA.user.id, 'same-sub');
  assert.equal(contextB.user.id, 'same-sub');
  assert.deepEqual(contextA.platform, { issuer: issuerA, clientId: 'client-a', deploymentId: 'a-one' });
  assert.deepEqual(contextB.platform, { issuer: issuerB, clientId: 'client-a', deploymentId: 'b-one' });
});

test('ambiguous login is refused; explicit client or deployment selects only its registration', async () => {
  const config = registrations();
  config[1] = { ...config[1]!, allowedTargetLinkUris: [target, otherTarget] };
  const tool = setup(config);
  await assert.rejects(tool.initiate(login(issuerA)), rejects('INVALID_LOGIN'));
  const chosen = await attempt(tool, login(issuerA, target, { client_id: 'client-a2' }),
    'a2', 'client-a2', 'a2-one');
  assert.equal(chosen.url.searchParams.get('client_id'), 'client-a2');
  assert.equal((await chosen.launch()).platform.clientId, 'client-a2');
  const byDeployment = await attempt(tool, login(issuerA, target, { lti_deployment_id: 'a-two' }),
    'a', 'client-a', 'a-two');
  assert.equal((await byDeployment.launch()).platform.deploymentId, 'a-two');
  await assert.rejects(tool.initiate(login(issuerA, target, { client_id: 'unknown' })), rejects('INVALID_LOGIN'));
  await assert.rejects(tool.initiate(login(issuerA, target, { lti_deployment_id: 'unknown' })), rejects('INVALID_DEPLOYMENT'));
});

test('signed cross-platform, foreign client, key, deployment and target are refused', async () => {
  for (const scenario of [
    { key: 'b', aud: 'client-a', deployment: 'a-one', code: 'INVALID_TOKEN' },
    { key: 'a2', aud: 'client-a', deployment: 'a-one', code: 'INVALID_TOKEN' },
    { key: 'a', aud: 'client-a2', deployment: 'a-one', code: 'INVALID_AUDIENCE' },
    { key: 'a', aud: 'client-a', deployment: 'a2-one', code: 'INVALID_DEPLOYMENT' },
    { key: 'a', aud: 'client-a', deployment: 'a-one', code: 'INVALID_CLAIMS', targetUri: otherTarget },
  ]) {
    const tool = setup();
    const { launch } = await attempt(tool, login(issuerA), scenario.key, scenario.aud,
      scenario.deployment, {}, scenario.targetUri);
    await assert.rejects(launch(), rejects(scenario.code));
  }
  const tool = setup();
  const { url } = await attempt(tool, login(issuerA), 'a', 'client-a', 'a-one');
  await assert.rejects(tool.validate({ state: url.searchParams.get('state'),
    id_token: await signed('b', issuerB, 'client-a', url.searchParams.get('nonce')!, 'a-one') }),
  rejects('INVALID_TOKEN'));
  const hinted = await attempt(tool, login(issuerA, target, { lti_deployment_id: 'a-two' }),
    'a', 'client-a', 'a-one');
  await assert.rejects(hinted.launch(), rejects('INVALID_DEPLOYMENT'));
});

test('a valid platform key cannot authenticate a token with another issuer', async () => {
  const tool = setup();
  const { url } = await attempt(tool, login(issuerA), 'a', 'client-a', 'a-one');
  await assert.rejects(tool.validate({ state: url.searchParams.get('state'),
    id_token: await signed('a', issuerB, 'client-a', url.searchParams.get('nonce')!, 'a-one') }),
  rejects('INVALID_ISSUER'));
});

test('overlapping hints cannot select a default registration or a foreign target', async () => {
  const config = registrations();
  config[1] = { ...config[1]!, deployments: ['a-one', 'a2-one'], allowedTargetLinkUris: [target, otherTarget] };
  const tool = setup(config);
  await assert.rejects(tool.initiate(login(issuerA, target, { lti_deployment_id: 'a-one' })),
    rejects('INVALID_LOGIN'));
  await assert.rejects(tool.initiate(login(issuerA, otherTarget, { client_id: 'client-a' })),
    rejects('INVALID_TARGET'));
  await assert.rejects(tool.initiate(login(issuerB, otherTarget)), rejects('INVALID_TARGET'));
  await assert.rejects(tool.initiate(login('https://unknown.example')), rejects('INVALID_LOGIN'));
});

test('duplicate client registrations and resolver errors fail closed', async () => {
  const config = registrations();
  config.push({ ...config[0]! });
  const duplicate = setup(config);
  await assert.rejects(duplicate.initiate(login(issuerA, target, { client_id: 'client-a' })),
    rejects('INVALID_LOGIN'));
  const broken = createLtiTool({ resolver: { async resolve() { throw new Error('private config failure'); } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore() });
  await assert.rejects(broken.initiate(login(issuerA)), rejects('INVALID_CONFIGURATION'));
});
