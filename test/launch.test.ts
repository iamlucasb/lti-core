import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, MemoryOneTimeStore, LtiError } from '../src/index.js';
import type { LtiDiagnostic, OneTimeStore } from '../src/index.js';
import { asResourceLink } from './fixtures/launch-kind.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';
const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
const redirectUri = 'https://tool.example/callback';
let jwksUri: string;
let privateKey: CryptoKey;
let server: Server;
let publicJwk: Record<string, unknown>;

before(async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  privateKey = keys.privateKey;
  publicJwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
  server = createServer(tlsOptions, (request, response) => {
    if (request.url === '/broken') {
      response.statusCode = 503;
      response.end('unavailable');
      return;
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: [publicJwk] }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  jwksUri = `https://127.0.0.1:${address.port}/keys`;
});
after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

function tool(store: OneTimeStore = new MemoryOneTimeStore()) {
  return createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
      deployments: ['deployment-1', 'another-deployment'], allowedTargetLinkUris: [target] }] : []; } },
    redirectUri, store,
  });
}

async function sign(nonce: string, changes: Record<string, unknown> = {}, key = privateKey, kid = 'test-key') {
  return signLaunch({ privateKey: key, kid, issuer, audience: 'client-1', subject: 'user-17', nonce,
    deploymentId: 'deployment-1', targetLinkUri: target, resourceLinkId: 'resource-42',
    roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'], changes });
}

test('a signed resource link launch yields an LTI context via the public API', async () => {
  const lti = tool();
  const authorization = new URL((await lti.initiate({ iss: issuer, login_hint: 'opaque+hint',
    lti_message_hint: 'another opaque hint', target_link_uri: target })).url);
  assert.equal(authorization.origin + authorization.pathname, 'https://platform.example/authorize');
  assert.equal(authorization.searchParams.get('login_hint'), 'opaque+hint');
  assert.equal(authorization.searchParams.get('lti_message_hint'), 'another opaque hint');
  assert.equal(authorization.searchParams.get('response_type'), 'id_token');
  assert.equal(authorization.searchParams.get('response_mode'), 'form_post');
  assert.equal(authorization.searchParams.get('prompt'), 'none');
  assert.equal(authorization.searchParams.get('scope'), 'openid');
  assert.equal(authorization.searchParams.get('redirect_uri'), redirectUri);
  assert.equal(authorization.searchParams.get('client_id'), 'client-1');
  const state = authorization.searchParams.get('state')!;
  const nonce = authorization.searchParams.get('nonce')!;
  assert.notEqual(state, nonce);
  const { claims, ...context } = await lti.validate({ state, id_token: await sign(nonce) });
  assert.equal(claims.sub, 'user-17');
  assert.equal(claims.nonce, nonce);
  assert.deepEqual(context, {
    messageType: 'LtiResourceLinkRequest',
    platform: { issuer, clientId: 'client-1', deploymentId: 'deployment-1' },
    user: { id: 'user-17' }, resourceLink: { id: 'resource-42' },
    targetLinkUri: target, roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
    normalizedRoles: ['membership:Learner'],
  });
  await assert.rejects(lti.validate({ state, id_token: await sign(nonce) }),
    (error: unknown) => error instanceof LtiError && error.code === 'INVALID_STATE');
});
test('a signed rich launch exposes optional profile, course, resource and presentation data', async () => {
  const lti = tool();
  const authorization = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await lti.validate({ state: authorization.searchParams.get('state'),
    id_token: await sign(authorization.searchParams.get('nonce')!, {
      name: 'Ada Lovelace', given_name: 'Ada', family_name: 'Lovelace', email: 'ada@example.org', locale: 'en-GB',
      [claim + 'context']: { id: 'course-7', label: 'MATH', title: 'Analytical Engines',
        type: ['http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering'] },
      [claim + 'resource_link']: { id: 'resource-42', title: 'Lesson', description: 'Introduction' },
      [claim + 'launch_presentation']: { document_target: 'window', width: 800, height: 600,
        return_url: 'https://platform.example/return%20path', locale: 'fr-FR' },
      [claim + 'custom']: { section: 'A', source: 'platform' },
    }) });
  assert.deepEqual(context.user, { id: 'user-17', name: 'Ada Lovelace', givenName: 'Ada',
    familyName: 'Lovelace', email: 'ada@example.org', locale: 'en-GB' });
  assert.deepEqual(context.context, { id: 'course-7', label: 'MATH', title: 'Analytical Engines',
    type: ['http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering'] });
  assert.deepEqual(asResourceLink(context).resourceLink, { id: 'resource-42', title: 'Lesson', description: 'Introduction' });
  assert.deepEqual(context.launchPresentation, { documentTarget: 'window', width: 800, height: 600,
    returnUrl: 'https://platform.example/return%20path', locale: 'fr-FR' });
  assert.deepEqual(context.custom, { section: 'A', source: 'platform' });
});
test('name and email claims are independently optional', async () => {
  const scenarios: { changes: Record<string, unknown>; expected: Record<string, string> }[] = [
    { changes: {}, expected: { id: 'user-17' } },
    { changes: { name: 'Ada Lovelace' }, expected: { id: 'user-17', name: 'Ada Lovelace' } },
    { changes: { email: 'ada@example.org' }, expected: { id: 'user-17', email: 'ada@example.org' } },
    { changes: { name: 'Ada Lovelace', email: 'ada@example.org' },
      expected: { id: 'user-17', name: 'Ada Lovelace', email: 'ada@example.org' } },
  ];
  for (const { changes, expected } of scenarios) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, changes) });
    assert.deepEqual(context.user, expected);
  }
});
test('each initiation has fresh unpredictable state and nonce without requiring optional hints', async () => {
  const lti = tool();
  const login = { iss: issuer, login_hint: 'hint', target_link_uri: target };
  const first = new URL((await lti.initiate(login)).url);
  const second = new URL((await lti.initiate(login)).url);
  for (const parameter of ['state', 'nonce']) {
    assert.match(first.searchParams.get(parameter)!, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(first.searchParams.get(parameter), second.searchParams.get(parameter));
  }
  assert.equal(first.searchParams.has('lti_message_hint'), false);
  assert.equal(first.searchParams.has('lti_deployment_id'), false);
});

test('login rejects missing identifiers, an alien client and an unapproved target', async () => {
  const lti = tool();
  for (const login of [
    { login_hint: 'hint', target_link_uri: target },
    { iss: issuer, target_link_uri: target },
    { iss: issuer, login_hint: '', target_link_uri: target },
    { iss: issuer, login_hint: 'hint' },
    { iss: issuer, login_hint: 'hint', target_link_uri: target, client_id: 'alien' },
  ]) await assert.rejects(lti.initiate(login), { code: 'INVALID_LOGIN' });
  await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: 'https://evil.example/launch' }),
    { code: 'INVALID_TARGET' });
});

test('empty optional login parameters are treated as absent', async () => {
  const lti = tool();
  const { url, state } = await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target,
    client_id: '', lti_deployment_id: '', lti_message_hint: '' });
  const authorization = new URL(url);
  assert.equal(authorization.searchParams.get('client_id'), 'client-1');
  assert.equal(authorization.searchParams.has('lti_deployment_id'), false);
  assert.equal(authorization.searchParams.has('lti_message_hint'), false);
  const launch = await lti.validate({ state,
    id_token: await sign(authorization.searchParams.get('nonce')!) });
  assert.equal(launch.platform.clientId, 'client-1');
});

test('unmatched state and mismatched nonce cannot launch', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const state = url.searchParams.get('state')!;
  const nonce = url.searchParams.get('nonce')!;
  const token = await sign(nonce);
  await assert.rejects(lti.validate({ state: 'wrong', id_token: token }), { code: 'INVALID_STATE' });
  await assert.rejects(lti.validate({ state, id_token: await sign('wrong') }), { code: 'INVALID_NONCE' });
  await assert.rejects(lti.validate({ state, id_token: token }), { code: 'INVALID_STATE' });
});
test('a response without state is rejected', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const id_token = await sign(url.searchParams.get('nonce')!);
  await assert.rejects(Reflect.apply(lti.validate, lti, [{ id_token }]),
    (error: unknown) => error instanceof LtiError && error.code === 'INVALID_STATE');
});

test('signed invalid launches fail closed with stable errors', async () => {
  const wrongKey = (await generateKeyPair('RS256')).privateKey;
  const cases: { name: string; changes?: Record<string, unknown>; key?: CryptoKey; kid?: string; code: string;
    reason: string }[] = [
    { name: 'signature', key: wrongKey, code: 'INVALID_TOKEN', reason: 'token:signature' },
    { name: 'unknown kid', kid: 'alien', code: 'JWKS_ERROR', reason: 'jwks:no_matching_key' },
    { name: 'expired', changes: { exp: 1 }, code: 'TOKEN_EXPIRED', reason: 'token:exp' },
    { name: 'future iat', changes: { iat: Math.floor(Date.now() / 1000) + 600 }, code: 'INVALID_TOKEN', reason: 'token:iat' },
    { name: 'issuer', changes: { iss: 'https://alien.example' }, code: 'INVALID_ISSUER', reason: 'token:iss' },
    { name: 'audience', changes: { aud: 'alien' }, code: 'INVALID_AUDIENCE', reason: 'token:aud' },
    { name: 'azp', changes: { aud: ['client-1', 'other'], azp: 'other' }, code: 'INVALID_AUDIENCE', reason: 'token:aud' },
    { name: 'deployment', changes: { [claim + 'deployment_id']: 'other' }, code: 'INVALID_DEPLOYMENT', reason: 'deployment:unknown' },
    { name: 'target', changes: { [claim + 'target_link_uri']: 'https://evil.example/launch' }, code: 'INVALID_CLAIMS', reason: 'claim:target_link_uri' },
    { name: 'missing deployment', changes: { [claim + 'deployment_id']: undefined }, code: 'INVALID_DEPLOYMENT', reason: 'deployment:missing' },
    { name: 'missing target', changes: { [claim + 'target_link_uri']: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:target_link_uri' },
    { name: 'missing message type', changes: { [claim + 'message_type']: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:message_type' },
    { name: 'missing resource link', changes: { [claim + 'resource_link']: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:resource_link' },
    { name: 'version', changes: { [claim + 'version']: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:version' },
    { name: 'wrong version', changes: { [claim + 'version']: '1.2.0' }, code: 'INVALID_CLAIMS', reason: 'claim:version' },
    { name: 'message', changes: { [claim + 'message_type']: 'LtiDeepLinkingRequest' }, code: 'INVALID_CLAIMS', reason: 'claim:deep_linking_settings' },
    { name: 'subject', changes: { sub: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:sub' },
    { name: 'empty subject', changes: { sub: '' }, code: 'INVALID_CLAIMS', reason: 'claim:sub' },
    { name: 'invalid subject type', changes: { sub: 42 }, code: 'INVALID_CLAIMS', reason: 'claim:sub' },
    { name: 'resource', changes: { [claim + 'resource_link']: {} }, code: 'INVALID_CLAIMS', reason: 'claim:resource_link.id' },
    { name: 'roles', changes: { [claim + 'roles']: undefined }, code: 'INVALID_CLAIMS', reason: 'claim:roles' },
  ];
  for (const scenario of cases) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const state = url.searchParams.get('state')!;
    const nonce = url.searchParams.get('nonce')!;
    const id_token = await sign(nonce, scenario.changes, scenario.key, scenario.kid);
    await assert.rejects(lti.validate({ state, id_token }), (error: unknown) => {
      assert.ok(error instanceof LtiError, scenario.name);
      assert.equal(error.code, scenario.code, scenario.name);
      assert.equal(error.reason, scenario.reason, scenario.name);
      assert.equal(error.message, `${scenario.code}: ${scenario.reason}`, scenario.name);
      return true;
    });
  }
});
test('payload and signature tampering after signing invalidate the token', async () => {
  const lti = tool();
  const tamper = (token: string, part: 'payload' | 'signature') => {
    const [header, payloadSegment, signature] = token.split('.');
    assert.ok(header && payloadSegment && signature);
    if (part === 'signature') {
      const alteredSignature = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
      return [header, payloadSegment, alteredSignature].join('.');
    }
    const payload: unknown = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
    assert.ok(typeof payload === 'object' && payload !== null && !Array.isArray(payload));
    const alteredPayload = Buffer.from(JSON.stringify({ ...payload, sub: 'user-18' })).toString('base64url');
    return [header, alteredPayload, signature].join('.');
  };

  for (const part of ['payload', 'signature'] as const) {
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const id_token = tamper(await sign(url.searchParams.get('nonce')!), part);
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'), id_token }),
      (error: unknown) => error instanceof LtiError && error.code === 'INVALID_TOKEN');
  }
});

test('two concurrent validations cannot both consume a state', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const response = { state: url.searchParams.get('state')!, id_token: await sign(url.searchParams.get('nonce')!) };
  const outcomes = await Promise.allSettled([lti.validate(response), lti.validate(response)]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter(result => result.status === 'rejected' && result.reason instanceof LtiError &&
    result.reason.code === 'INVALID_STATE').length, 1);
});
test('two simultaneous initiation states can each validate independently', async () => {
  const lti = tool();
  const login = { iss: issuer, login_hint: 'hint', target_link_uri: target };
  const attempts = await Promise.all([lti.initiate(login), lti.initiate(login)]);
  const responses = await Promise.all(attempts.map(async authorization => {
    const params = new URL(authorization.url).searchParams;
    return { state: params.get('state'), id_token: await sign(params.get('nonce')!) };
  }));
  assert.notEqual(responses[0]?.state, responses[1]?.state);
  const contexts = await Promise.all(responses.map(response => lti.validate(response)));
  assert.deepEqual(contexts.map(context => asResourceLink(context).resourceLink.id), ['resource-42', 'resource-42']);
});

test('two tools using independent store adapters share attempts and reject cross-attempt nonce', async () => {
  const entries = new Map<string, { value: string; expiresAt: number }>();
  const adapter = (): OneTimeStore => ({
    async put(state, value, expiresAt) {
      if (entries.has(state)) throw new Error('duplicate state');
      entries.set(state, { value, expiresAt });
    },
    async take(state) {
      await Promise.resolve();
      const entry = entries.get(state);
      entries.delete(state);
      return entry && entry.expiresAt > Date.now() ? entry.value : undefined;
    },
  });
  const first = tool(adapter());
  const second = tool(adapter());
  const login = { iss: issuer, login_hint: 'hint', target_link_uri: target };
  const firstAttempt = new URL((await first.initiate(login)).url).searchParams;
  const secondAttempt = new URL((await second.initiate(login)).url).searchParams;
  const stateA = firstAttempt.get('state')!;
  const stateB = secondAttempt.get('state')!;
  assert.notEqual(stateA, stateB);
  const tokenA = await sign(firstAttempt.get('nonce')!);
  const tokenB = await sign(secondAttempt.get('nonce')!);
  await assert.rejects(second.validate({ state: stateA, id_token: tokenB }), { code: 'INVALID_NONCE' });
  const independent = new URL((await second.initiate(login)).url).searchParams;
  assert.equal((await second.validate({ state: independent.get('state'),
    id_token: await sign(independent.get('nonce')!) })).user.id, 'user-17');
  await assert.rejects(first.validate({ state: stateA, id_token: tokenA }), { code: 'INVALID_STATE' });
  assert.equal(asResourceLink(await first.validate({ state: stateB, id_token: tokenB })).resourceLink.id, 'resource-42');
  const firstIndependent = new URL((await first.initiate(login)).url).searchParams;
  assert.equal((await first.validate({ state: firstIndependent.get('state'),
    id_token: await sign(firstIndependent.get('nonce')!) })).user.id, 'user-17');

  const replayedAttempt = new URL((await first.initiate(login)).url).searchParams;
  const response = { state: replayedAttempt.get('state')!, id_token: await sign(replayedAttempt.get('nonce')!) };
  const outcomes = await Promise.allSettled([first.validate(response), second.validate(response)]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled' &&
    asResourceLink(result.value).resourceLink.id === 'resource-42').length, 1);
  assert.equal(outcomes.filter(result => result.status === 'rejected' && result.reason instanceof LtiError &&
    result.reason.code === 'INVALID_STATE').length, 1);
});

test('memory store isolates keys, expires values and permits one concurrent take', async () => {
  const store = new MemoryOneTimeStore();
  const expiresAt = Date.now() + 60_000;
  await store.put('same-state', 'original', expiresAt);
  await assert.rejects(store.put('same-state', 'replacement', expiresAt));
  await store.put('other-state', 'independent', expiresAt);
  const concurrent = await Promise.all([store.take('same-state'), store.take('same-state')]);
  assert.equal(concurrent.filter(value => value === 'original').length, 1);
  assert.equal(concurrent.filter(value => value === undefined).length, 1);
  assert.equal(await store.take('other-state'), 'independent');
  await store.put('expired-state', 'expired', Date.now() - 1);
  assert.equal(await store.take('expired-state'), undefined);
});

test('an expired pending state cannot yield a context even if storage returns it', async () => {
  const entries = new Map<string, string>();
  const lti = tool({
    async put(state, value) {
      const launch = JSON.parse(value) as Record<string, unknown>;
      entries.set(state, JSON.stringify({ ...launch, expiresAt: Date.now() - 1 }));
    },
    async take(state) {
      const value = entries.get(state);
      entries.delete(state);
      return value;
    },
  });
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!) }), { code: 'INVALID_STATE' });
});

test('a deployment hint is bound to the signed deployment', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target,
    lti_deployment_id: 'another-deployment' })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!) }), { code: 'INVALID_DEPLOYMENT' });
});

function optionalDeploymentTool(deployments: readonly string[] = ['deployment-1']) {
  return createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri, deployments,
      allowedTargetLinkUris: [target], deploymentIdRequired: false }] : []; } },
    redirectUri, store: new MemoryOneTimeStore(),
  });
}

async function launchWith(lti: ReturnType<typeof createLtiTool>, changes: Record<string, unknown>,
  login: Record<string, unknown> = {}) {
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target, ...login })).url);
  return lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, changes) });
}

const withoutDeployment = { [claim + 'deployment_id']: undefined };

test('a registration that does not require deployment_id accepts a launch without it', async () => {
  for (const deployments of [['deployment-1'], []]) {
    const context = await launchWith(optionalDeploymentTool(deployments), withoutDeployment);
    assert.deepEqual(context.platform, { issuer, clientId: 'client-1' });
    assert.equal('deploymentId' in context.platform, false);
    assert.equal(context.user.id, 'user-17');
  }
  const hinted = await launchWith(optionalDeploymentTool(), withoutDeployment,
    { lti_deployment_id: 'deployment-1' });
  assert.deepEqual(hinted.platform, { issuer, clientId: 'client-1' });
});

test('a present deployment_id is still validated when the registration does not require it', async () => {
  const known = await launchWith(optionalDeploymentTool(), {});
  assert.deepEqual(known.platform, { issuer, clientId: 'client-1', deploymentId: 'deployment-1' });
  const open = await launchWith(optionalDeploymentTool([]), { [claim + 'deployment_id']: 'any-deployment' });
  assert.equal(open.platform.deploymentId, 'any-deployment');

  for (const [deployments, deploymentId] of [
    [['deployment-1'], 'unknown-deployment'], [['deployment-1'], ''], [['deployment-1'], 42],
    [['deployment-1'], null], [[], ''], [[], 'a'.repeat(256)], [[], 'déploiement'], [[], ['deployment-1']],
  ] as const) {
    await assert.rejects(launchWith(optionalDeploymentTool(deployments), { [claim + 'deployment_id']: deploymentId }),
      { code: 'INVALID_DEPLOYMENT' }, JSON.stringify(deploymentId));
  }
});

test('an optional deployment_id stays bound to the initiation hint', async () => {
  for (const [deployments, hint, signed] of [
    [['deployment-1', 'another-deployment'], 'another-deployment', 'deployment-1'],
    [[], 'deployment-a', 'deployment-b'],
  ] as const) {
    await assert.rejects(launchWith(optionalDeploymentTool(deployments), { [claim + 'deployment_id']: signed },
      { lti_deployment_id: hint }), { code: 'INVALID_DEPLOYMENT' });
  }
  const bound = await launchWith(optionalDeploymentTool([]), { [claim + 'deployment_id']: 'deployment-a' },
    { lti_deployment_id: 'deployment-a' });
  assert.equal(bound.platform.deploymentId, 'deployment-a');

  await assert.rejects(optionalDeploymentTool().initiate({ iss: issuer, login_hint: 'hint',
    target_link_uri: target, lti_deployment_id: 'unknown-deployment' }), { code: 'INVALID_DEPLOYMENT' });
  await assert.rejects(optionalDeploymentTool([]).initiate({ iss: issuer, login_hint: 'hint',
    target_link_uri: target, lti_deployment_id: 'déploiement' }), { code: 'INVALID_DEPLOYMENT' });
});

test('an optional deployment_id does not relax any other launch check', async () => {
  const { privateKey: wrongKey } = await generateKeyPair('RS256');
  for (const scenario of [
    { changes: { iss: 'https://alien.example' }, code: 'INVALID_ISSUER' },
    { changes: { aud: 'alien' }, code: 'INVALID_AUDIENCE' },
    { changes: {}, key: wrongKey, code: 'INVALID_TOKEN' },
    { changes: { nonce: 'other-nonce' }, code: 'INVALID_NONCE' },
    { changes: { [claim + 'target_link_uri']: 'https://evil.example/launch' }, code: 'INVALID_CLAIMS' },
    { changes: { [claim + 'version']: '1.2.0' }, code: 'INVALID_CLAIMS' },
    { changes: { [claim + 'message_type']: 'LtiDeepLinkingRequest' }, code: 'INVALID_CLAIMS' },
    { changes: { sub: undefined }, code: 'INVALID_CLAIMS' },
  ]) {
    const lti = optionalDeploymentTool([]);
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const state = url.searchParams.get('state');
    const id_token = await sign(url.searchParams.get('nonce')!, { ...withoutDeployment, ...scenario.changes },
      scenario.key);
    await assert.rejects(lti.validate({ state, id_token }), { code: scenario.code }, scenario.code);
    await assert.rejects(lti.validate({ state, id_token }), { code: 'INVALID_STATE' });
  }
});

test('deploymentIdRequired must be a boolean and defaults to required', async () => {
  for (const deploymentIdRequired of ['false', 0, null]) {
    const lti = createLtiTool({ resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri, deployments: [],
      allowedTargetLinkUris: [target], deploymentIdRequired } as never]; } },
    redirectUri, store: new MemoryOneTimeStore() });
    await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
      { code: 'INVALID_CONFIGURATION' });
  }
  const required = createLtiTool({ resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
    authorizationEndpoint: 'https://platform.example/authorize', jwksUri, deployments: ['deployment-1'],
    allowedTargetLinkUris: [target], deploymentIdRequired: true }]; } },
  redirectUri, store: new MemoryOneTimeStore() });
  await assert.rejects(launchWith(required, withoutDeployment), { code: 'INVALID_DEPLOYMENT' });
});

test('missing signed security claims and key id are rejected', async () => {
  for (const scenario of [
    { changes: { nonce: undefined }, code: 'INVALID_NONCE' },
    { changes: { exp: undefined }, code: 'INVALID_TOKEN' },
    { changes: { iat: undefined }, code: 'INVALID_TOKEN' },
    { changes: { [claim + 'resource_link']: { id: 4.2 } }, code: 'INVALID_CLAIMS' },
    { changes: {}, code: 'JWKS_ERROR', kid: '' },
  ]) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, scenario.changes, privateKey, scenario.kid) }),
      { code: scenario.code });
  }
});

test('a single-element audience array and empty roles are valid', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { aud: ['client-1'], [claim + 'roles']: [] }) });
  assert.deepEqual(context.roles, []);
  assert.deepEqual(context.normalizedRoles, []);
});
test('a signed token for an additional untrusted audience is rejected even with the expected azp', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { aud: ['client-1', 'other'], azp: 'client-1' }) }),
  { code: 'INVALID_AUDIENCE' });
});

test('a mismatching azp is rejected with the expected sole audience', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { azp: 'other' }) }),
  { code: 'INVALID_AUDIENCE' });
});

test('a token signed with a published non-RS256 key is rejected', async () => {
  const previousJwk = publicJwk;
  const keys = await generateKeyPair('ES256', { extractable: true });
  publicJwk = { ...await exportJWK(keys.publicKey), kid: 'ec-key', alg: 'ES256', use: 'sig' };
  try {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const id_token = await signLaunch({ privateKey: keys.privateKey, kid: 'ec-key', algorithm: 'ES256',
      issuer, audience: 'client-1', subject: 'user-17', nonce: url.searchParams.get('nonce')!,
      deploymentId: 'deployment-1', targetLinkUri: target, resourceLinkId: 'resource-42',
      roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'] });
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'), id_token }),
      { code: 'INVALID_TOKEN' });
  } finally {
    publicJwk = previousJwk;
  }
});

test('JWKS and store failures emit safe normalized diagnostics', async () => {
  const diagnostics: LtiDiagnostic[] = [];
  const lti = createLtiTool({ resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
    authorizationEndpoint: 'https://platform.example/authorize', jwksUri: jwksUri.replace('/keys', '/broken'),
    deployments: ['deployment-1'], allowedTargetLinkUris: [target] }]; } }, redirectUri,
    store: new MemoryOneTimeStore(), onDiagnostic: diagnostic => diagnostics.push(diagnostic) });
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!) }), { code: 'JWKS_ERROR' });
  const failing = createLtiTool({ resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
    authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
    deployments: ['deployment-1'], allowedTargetLinkUris: [target] }]; } }, redirectUri,
    store: { async put() { throw new Error('secret storage failure'); },
      async take() { throw new Error('secret storage failure'); } },
    onDiagnostic: diagnostic => diagnostics.push(diagnostic) });
  await assert.rejects(failing.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
    (error: unknown) => error instanceof LtiError && error.code === 'STORE_ERROR' &&
      error.message === 'STORE_ERROR: store:put');
  await assert.rejects(failing.validate({ state: 'state', id_token: 'token' }), { code: 'STORE_ERROR' });
  assert.deepEqual(diagnostics, [
    { code: 'JWKS_REQUEST_FAILED', errorCode: 'JWKS_ERROR' },
    { code: 'STATE_PUT_FAILED', errorCode: 'STORE_ERROR' },
    { code: 'STATE_TAKE_FAILED', errorCode: 'STORE_ERROR' },
  ]);
  assert.equal(JSON.stringify(diagnostics).includes('secret storage failure'), false);
});

test('unknown vendor claims do not change raw LTI roles', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const roles = ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner', 'urn:vendor:unrecognized-role'];
  const context = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: roles,
      'https://vendor.example/claim/extra': { arbitrary: true } }) });
  assert.deepEqual(context.roles, roles);
  assert.deepEqual(context.normalizedRoles, ['membership:Learner']);
  assert.equal(context.user.id, 'user-17');
});
test('TestUser is normalized beside a real LTI role and alone', async () => {
  const marker = 'http://purl.imsglobal.org/vocab/lti/system/person#TestUser';
  const learner = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
  const lti = tool();
  const first = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await lti.validate({ state: first.searchParams.get('state'),
    id_token: await sign(first.searchParams.get('nonce')!, { [claim + 'roles']: [learner, marker] }) });
  assert.deepEqual(context.roles, [learner, marker]);
  assert.deepEqual(context.normalizedRoles, ['membership:Learner', 'system:TestUser']);
  const second = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const alone = await lti.validate({ state: second.searchParams.get('state'),
    id_token: await sign(second.searchParams.get('nonce')!, { [claim + 'roles']: [marker] }) });
  assert.deepEqual(alone.roles, [marker]);
  assert.deepEqual(alone.normalizedRoles, ['system:TestUser']);
});

test('invalid registration URLs fail with a stable LTI error before initiation', async () => {
  for (const field of ['jwksUri', 'authorizationEndpoint'] as const) {
    const registration = { issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
      jwksUri, deployments: ['deployment-1'], allowedTargetLinkUris: [target], [field]: 'not a URL' };
    const lti = createLtiTool({ resolver: { async resolve() { return [registration]; } },
      redirectUri, store: new MemoryOneTimeStore() });
    await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
      { code: 'INVALID_CONFIGURATION', message: 'INVALID_CONFIGURATION: registration:invalid' });
  }
});

test('issuer identifiers outside the HTTPS issuer profile are rejected before login', async () => {
  for (const invalidIssuer of ['http://platform.example', 'https://platform.example?tenant=1',
    'https://platform.example#fragment', 'https://user@platform.example', 'https://@platform.example',
    'https:platform.example', 'https://platform.example/path with space', 'https://platform.example/%zz']) {
    const lti = createLtiTool({ resolver: { async resolve() { return [{ issuer: invalidIssuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
      deployments: ['deployment-1'], allowedTargetLinkUris: [target] }]; } },
    redirectUri, store: new MemoryOneTimeStore() });
    await assert.rejects(lti.initiate({ iss: invalidIssuer, login_hint: 'hint', target_link_uri: target }),
      { code: 'INVALID_CONFIGURATION' });
  }
});
test('plaintext registration endpoints are rejected before initiating login', async () => {
  for (const field of ['jwksUri', 'authorizationEndpoint'] as const) {
    const registration = { issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
      jwksUri: 'https://platform.example/keys', deployments: ['deployment-1'], allowedTargetLinkUris: [target],
      [field]: 'http://platform.example/' + field };
    const lti = createLtiTool({ resolver: { async resolve() { return [registration]; } },
      redirectUri, store: new MemoryOneTimeStore() });
    await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
      { code: 'INVALID_CONFIGURATION', message: 'INVALID_CONFIGURATION: registration:invalid' });
  }
});
test('plaintext redirect URI is rejected when creating the tool', () => {
  assert.throws(() => createLtiTool({ resolver: { async resolve() { return []; } },
    redirectUri: 'http://tool.example/callback', store: new MemoryOneTimeStore() }),
  { code: 'INVALID_CONFIGURATION', message: 'INVALID_CONFIGURATION: config:redirectUri' });
});

test('plaintext launch target is rejected before initiating login', async () => {
  const registration = { issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
    jwksUri, deployments: ['deployment-1'], allowedTargetLinkUris: ['http://tool.example/launch'] };
  const lti = createLtiTool({ resolver: { async resolve() { return [registration]; } },
    redirectUri, store: new MemoryOneTimeStore() });
  await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
    { code: 'INVALID_CONFIGURATION', message: 'INVALID_CONFIGURATION: registration:invalid' });
});

test('a valid LIS membership sub-role can appear without its principal role', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const roles = ['http://purl.imsglobal.org/vocab/lis/v2/membership/Instructor#TeachingAssistant'];
  const context = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: roles }) });
  assert.deepEqual(context.roles, roles);
  assert.deepEqual(context.normalizedRoles, ['membership:Instructor/TeachingAssistant']);
});

test('other standard LIS sub-roles are valid without their principal role', async () => {
  const lti = tool();
  for (const [raw, normalized] of [
    ['http://purl.imsglobal.org/vocab/lis/v2/membership/Instructor#Grader', 'membership:Instructor/Grader'],
    ['http://purl.imsglobal.org/vocab/lis/v2/membership/Mentor#Tutor', 'membership:Mentor/Tutor'],
  ]) {
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: [raw] }) });
    assert.deepEqual(context.roles, [raw]);
    assert.deepEqual(context.normalizedRoles, [normalized]);
  }
});
test('institution None and Other each validate and normalize as standard roles', async () => {
  const lti = tool();
  for (const name of ['None', 'Other']) {
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const role = 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#' + name;
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: [role] }) });
    assert.deepEqual(context.roles, [role]);
    assert.deepEqual(context.normalizedRoles, ['institution:' + name]);
  }
});

test('standard roles retain their distinct LTI scopes alongside unrecognized roles', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const roles = ['http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator',
    'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor',
    'urn:vendor:role', 'http://purl.imsglobal.org/vocab/lis/v2/membership#Manager',
    'http://purl.imsglobal.org/vocab/lis/v2/membership#FutureRole'];
  const context = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: roles }) });
  assert.deepEqual(context.roles, roles);
  assert.deepEqual(context.normalizedRoles, ['system:Administrator', 'membership:Instructor', 'membership:Manager']);
});

const quirkyDeployment = '6f1c2a4e-8b3d-4c5f-9a7e-1d2b3c4d5e6f';

function quirkyPlatformTool() {
  return createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri, deployments: [quirkyDeployment],
      allowedTargetLinkUris: [target] }] : []; } },
    redirectUri, store: new MemoryOneTimeStore(),
  });
}

async function launchQuirkyPlatform(changes: Record<string, unknown> = {}) {
  const lti = quirkyPlatformTool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  return lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, {
      sub: '1987', name: 'Jeanne Martin', email: null, locale: 'fr',
      [claim + 'deployment_id']: quirkyDeployment,
      [claim + 'resource_link']: { id: 314, description: '', title: 'Module AFGSU 1' },
      [claim + 'context']: { id: 27, title: 'Formation AFGSU' },
      [claim + 'tool_platform']: { guid: 1, contact_email: null, name: 'Campus', url: 'https://campus.example',
        product_family_code: 'dokeos', version: '5.0' },
      [claim + 'roles']: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
        'http://purl.imsglobal.org/vocab/lis/v2/membership#Student'],
      [claim + 'launch_presentation']: { document_target: 'iframe', height: 600, width: 800,
        return_url: 'https://campus.example/main/lti/return.php?id=314' },
      ...changes,
    }) });
}

test('a launch with integer ids and null optional claims (as sent by Dokeos) is accepted', async () => {
  const { claims, ...launch } = await launchQuirkyPlatform();
  assert.deepEqual(claims[claim + 'tool_platform'], { guid: 1, contact_email: null, name: 'Campus',
    url: 'https://campus.example', product_family_code: 'dokeos', version: '5.0' });
  assert.deepEqual(launch, {
    messageType: 'LtiResourceLinkRequest',
    platform: { issuer, clientId: 'client-1', deploymentId: quirkyDeployment },
    user: { id: '1987', name: 'Jeanne Martin', locale: 'fr' },
    resourceLink: { id: '314', title: 'Module AFGSU 1', description: '' },
    context: { id: '27', title: 'Formation AFGSU' },
    launchPresentation: { documentTarget: 'iframe', width: 800, height: 600,
      returnUrl: 'https://campus.example/main/lti/return.php?id=314' },
    targetLinkUri: target,
    roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
      'http://purl.imsglobal.org/vocab/lis/v2/membership#Student'],
    normalizedRoles: ['membership:Learner'],
  });
});

test('descriptive identifiers accept safe non-negative integers as decimal strings', async () => {
  for (const id of [0, 7, Number.MAX_SAFE_INTEGER]) {
    const context = await launchQuirkyPlatform({ [claim + 'resource_link']: { id }, [claim + 'context']: { id } });
    assert.equal(asResourceLink(context).resourceLink.id, String(id));
    assert.equal(context.context?.id, String(id));
  }
  for (const id of [1.5, -1, Number.MAX_SAFE_INTEGER + 1, 1e300, true, false, {}, [], [7], null, '']) {
    await assert.rejects(launchQuirkyPlatform({ [claim + 'resource_link']: { id } }), { code: 'INVALID_CLAIMS' },
      `resource_link.id ${JSON.stringify(id)}`);
    await assert.rejects(launchQuirkyPlatform({ [claim + 'context']: { id } }), { code: 'INVALID_CLAIMS' },
      `context.id ${JSON.stringify(id)}`);
  }
});

test('security and identity claims stay strict strings', async () => {
  for (const [changes, code] of [
    [{ sub: 1987 }, 'INVALID_CLAIMS'], [{ sub: null }, 'INVALID_CLAIMS'],
    [{ [claim + 'deployment_id']: 42 }, 'INVALID_DEPLOYMENT'], [{ [claim + 'deployment_id']: null }, 'INVALID_DEPLOYMENT'],
    [{ aud: 1 }, 'INVALID_AUDIENCE'], [{ iss: null }, 'INVALID_ISSUER'], [{ nonce: 1 }, 'INVALID_NONCE'],
  ] as const) {
    await assert.rejects(launchQuirkyPlatform(changes), { code }, JSON.stringify(changes));
  }
});

test('null optional claims are treated as absent', async () => {
  const context = await launchQuirkyPlatform({
    name: null, given_name: null, family_name: null, email: null, locale: null, picture: null,
    [claim + 'resource_link']: { id: 314, title: null, description: null },
    [claim + 'context']: { id: 27, title: null, label: null, type: null },
    [claim + 'launch_presentation']: { document_target: null, width: null, height: null, return_url: null,
      locale: null },
    [claim + 'custom']: { kept: 'value', dropped: null },
  });
  assert.deepEqual(context.user, { id: '1987' });
  assert.deepEqual(asResourceLink(context).resourceLink, { id: '314' });
  assert.deepEqual(context.context, { id: '27' });
  assert.deepEqual(context.launchPresentation, {});
  assert.deepEqual(context.custom, { kept: 'value' });

  const bare = await launchQuirkyPlatform({ [claim + 'context']: null, [claim + 'launch_presentation']: null,
    [claim + 'custom']: null, [claim + 'tool_platform']: null });
  assert.equal('context' in bare, false);
  assert.equal('launchPresentation' in bare, false);
  assert.equal('custom' in bare, false);
});

test('null required claims are still rejected', async () => {
  for (const key of ['resource_link', 'roles', 'version', 'message_type', 'target_link_uri']) {
    await assert.rejects(launchQuirkyPlatform({ [claim + key]: null }), { code: 'INVALID_CLAIMS' }, key);
  }
});

test('an unknown document target is ignored without rejecting the launch', async () => {
  for (const document_target of ['popup', '', '_blank', 'IFRAME', 'constructor', 'toString']) {
    const context = await launchQuirkyPlatform({ [claim + 'launch_presentation']: { document_target, width: 800 } });
    assert.deepEqual(context.launchPresentation, { width: 800 }, document_target);
  }
});

test('a context claim without an identifier is rejected', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'context']: { title: 'missing course id' } }) }),
  { code: 'INVALID_CLAIMS' });
});

test('a presentation return URL that is not an absolute HTTPS URL is dropped before exposure', async () => {
  const lti = tool();
  for (const return_url of ['http://platform.example/return', '/return', 'not a URL',
    'https://platform.example/return with space', '\u0000https://platform.example/return',
    'https:platform.example/return', 'https://platform.example/rôle', 'https://platform.example/%zz', 42]) {
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, {
        [claim + 'launch_presentation']: { return_url, width: 800 },
      }) });
    assert.deepEqual(context.launchPresentation, { width: 800 }, JSON.stringify(return_url));
  }
});

test('OAuth endpoints with fragments are rejected as invalid configuration', async () => {
  assert.throws(() => createLtiTool({ resolver: { async resolve() { return []; } },
    redirectUri: 'https://tool.example/callback#fragment', store: new MemoryOneTimeStore() }),
  { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => createLtiTool({ resolver: { async resolve() { return []; } },
    redirectUri: 'https:tool.example/callback', store: new MemoryOneTimeStore() }),
  { code: 'INVALID_CONFIGURATION' });
  const lti = createLtiTool({ resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
    authorizationEndpoint: 'https://platform.example/authorize#fragment', jwksUri,
    deployments: ['deployment-1'], allowedTargetLinkUris: [target] }]; } }, redirectUri,
  store: new MemoryOneTimeStore() });
  await assert.rejects(lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target }),
    { code: 'INVALID_CONFIGURATION' });
});

test('LTI identifiers accept 255 ASCII characters and reject values outside that profile', async () => {
  const max = 'a'.repeat(255);
  const ltiForDeployment = (deployment: string) => createLtiTool({ resolver: { async resolve() { return [{
    issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
    deployments: [deployment], allowedTargetLinkUris: [target],
  }]; } }, redirectUri, store: new MemoryOneTimeStore() });
  const valid = ltiForDeployment(max);
  const authorization = new URL((await valid.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await valid.validate({ state: authorization.searchParams.get('state'),
    id_token: await sign(authorization.searchParams.get('nonce')!, {
      sub: max, [claim + 'deployment_id']: max, [claim + 'resource_link']: { id: max },
      [claim + 'context']: { id: max },
    }) });
  assert.equal(context.user.id, max);
  assert.equal(context.platform.deploymentId, max);
  assert.equal(asResourceLink(context).resourceLink.id, max);
  assert.equal(context.context?.id, max);

  for (const invalidDeployment of ['a'.repeat(256), 'déploiement']) {
    await assert.rejects(ltiForDeployment(invalidDeployment).initiate({
      iss: issuer, login_hint: 'hint', target_link_uri: target,
    }), { code: 'INVALID_CONFIGURATION' });
  }
  for (const changes of [
    { sub: 'a'.repeat(256) }, { sub: 'utilisateur' + 'é' },
    { [claim + 'resource_link']: { id: 'a'.repeat(256) } },
    { [claim + 'resource_link']: { id: 'ressource-é' } },
    { [claim + 'context']: { id: 'a'.repeat(256) } },
    { [claim + 'context']: { id: 'contexte-é' } },
  ]) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, changes) }), { code: 'INVALID_CLAIMS' });
  }
});

test('context types and presentation targets follow their LTI vocabularies', async () => {
  const standardType = 'http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering';
  const valid = tool();
  const validUrl = new URL((await valid.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await valid.validate({ state: validUrl.searchParams.get('state'),
    id_token: await sign(validUrl.searchParams.get('nonce')!, {
      [claim + 'context']: { id: 'course', type: [standardType, 'urn:vendor:context'] },
      [claim + 'launch_presentation']: { document_target: 'iframe' },
    }) });
  assert.deepEqual(context.context?.type, [standardType, 'urn:vendor:context']);
  assert.equal(context.launchPresentation?.documentTarget, 'iframe');

  for (const changes of [
    { [claim + 'context']: { type: ['CourseSection'] } },
    { [claim + 'context']: { id: 4.2, type: ['CourseSection'] } },
    { [claim + 'context']: ['course'] },
  ]) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, changes) }), { code: 'INVALID_CLAIMS' });
  }
});

test('deprecated short context types are normalized to their LIS v2 URIs', async () => {
  const course = 'http://purl.imsglobal.org/vocab/lis/v2/course#';
  for (const [type, expected] of [
    [['CourseSection'], [course + 'CourseSection']],
    [['CourseTemplate', 'CourseOffering', 'Group'],
      [course + 'CourseTemplate', course + 'CourseOffering', course + 'Group']],
    [[course + 'CourseOffering', 'CourseSection', 'urn:vendor:context'],
      [course + 'CourseOffering', course + 'CourseSection', 'urn:vendor:context']],
    [['CourseSection', course + 'CourseSection'], [course + 'CourseSection']],
    [['urn:lti:context-type:ims/lis/Group'], ['urn:lti:context-type:ims/lis/Group']],
    [['CourseSection', 'vendor type', 42, null], [course + 'CourseSection']],
  ] as const) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, {
        [claim + 'context']: { id: 'course', title: 'Cours', type },
      }) });
    assert.deepEqual(context.context, { id: 'course', title: 'Cours', type: expected });
  }
});

test('an unusable context type is ignored without rejecting the launch', async () => {
  for (const type of [
    [], ['urn:vendor:context'], ['UnknownType'], ['coursesection'], ['not a URI'], [42], ['course', 42], [null, {}],
    'CourseSection', 42, null, { CourseSection: true },
  ]) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const context = await lti.validate({ state: url.searchParams.get('state'),
      id_token: await sign(url.searchParams.get('nonce')!, {
        [claim + 'context']: { id: 'course', label: 'C1', type },
      }) });
    assert.deepEqual(context.context, { id: 'course', label: 'C1' }, JSON.stringify(type));
  }
});

test('public entry points normalize invalid top-level inputs', async () => {
  assert.throws(() => Reflect.apply(createLtiTool, undefined, [null]), { code: 'INVALID_CONFIGURATION' });
  const lti = tool();
  await assert.rejects(Reflect.apply(lti.initiate, lti, [null]), { code: 'INVALID_LOGIN' });
  await assert.rejects(Reflect.apply(lti.validate, lti, [null]), { code: 'INVALID_STATE' });
});

test('every standard LTI role URI has its specified normalized value', async () => {
  const mappings: [string, string][] = [];
  for (const [scope, base, names] of [
    ['membership', 'http://purl.imsglobal.org/vocab/lis/v2/membership#',
      ['Administrator', 'ContentDeveloper', 'Instructor', 'Learner', 'Mentor', 'Manager', 'Member', 'Officer']],
    ['institution', 'http://purl.imsglobal.org/vocab/lis/v2/institution/person#',
      ['Administrator', 'Faculty', 'Guest', 'Alumni', 'Instructor', 'Learner', 'Member', 'Mentor',
        'None', 'Observer', 'Officer', 'Other', 'ProspectiveStudent', 'Staff', 'Student']],
    ['system', 'http://purl.imsglobal.org/vocab/lis/v2/system/person#',
      ['Administrator', 'None', 'AccountAdmin', 'Creator', 'SysAdmin', 'SysSupport', 'User']],
  ] as const) for (const name of names) mappings.push([base + name, scope + ':' + name]);
  for (const [principal, names] of Object.entries({
    Administrator: ['Administrator', 'Developer', 'ExternalDeveloper', 'ExternalSupport',
      'ExternalSystemAdministrator', 'Support', 'SystemAdministrator'],
    ContentDeveloper: ['ContentDeveloper', 'ContentExpert', 'ExternalContentExpert', 'Librarian'],
    Instructor: ['ExternalInstructor', 'Grader', 'GuestInstructor', 'Lecturer', 'PrimaryInstructor',
      'SecondaryInstructor', 'TeachingAssistant', 'TeachingAssistantGroup', 'TeachingAssistantOffering',
      'TeachingAssistantSection', 'TeachingAssistantSectionAssociation', 'TeachingAssistantTemplate'],
    Learner: ['ExternalLearner', 'GuestLearner', 'Instructor', 'Learner', 'NonCreditLearner'],
    Manager: ['AreaManager', 'CourseCoordinator', 'ExternalObserver', 'Manager', 'Observer'], Member: ['Member'],
    Mentor: ['Advisor', 'Auditor', 'ExternalAdvisor', 'ExternalAuditor', 'ExternalLearningFacilitator',
      'ExternalMentor', 'ExternalReviewer', 'ExternalTutor', 'LearningFacilitator', 'Mentor', 'Reviewer', 'Tutor'],
    Officer: ['Chair', 'Communications', 'Secretary', 'Treasurer', 'Vice-Chair'],
  })) for (const name of names) mappings.push([
    'http://purl.imsglobal.org/vocab/lis/v2/membership/' + principal + '#' + name,
    'membership:' + principal + '/' + name,
  ]);
  mappings.push(['http://purl.imsglobal.org/vocab/lti/system/person#TestUser', 'system:TestUser']);
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, { [claim + 'roles']: mappings.map(([raw]) => raw) }) });
  assert.deepEqual(context.normalizedRoles, mappings.map(([, normalized]) => normalized));
});

test('locale claims are exposed only as valid BCP 47 language tags', async () => {
  const valid = tool();
  const validUrl = new URL((await valid.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const context = await valid.validate({ state: validUrl.searchParams.get('state'),
    id_token: await sign(validUrl.searchParams.get('nonce')!, {
      locale: 'x-lti-test', [claim + 'launch_presentation']: { locale: 'zh-Hant-TW' },
    }) });
  assert.equal(context.user.locale, 'x-lti-test');
  assert.equal(context.launchPresentation?.locale, 'zh-Hant-TW');
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const invalid = await lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, {
      locale: 'not a language', [claim + 'launch_presentation']: { locale: 'not a language' },
    }) });
  assert.equal('locale' in invalid.user, false);
  assert.deepEqual(invalid.launchPresentation, {});
});
