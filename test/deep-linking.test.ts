import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { inspect } from 'node:util';
import { after, before, test } from 'node:test';
import { createLocalJWKSet, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type { LtiContentItem, LtiDiagnostic, LtiTool, LtiToolConfig, OneTimeStore, ToolKeys } from '../src/index.js';
import { asDeepLinking, asResourceLink } from './fixtures/launch-kind.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';
const dl = 'https://purl.imsglobal.org/spec/lti-dl/claim/';
const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
const assignmentTarget = 'https://tool.example/assignments';
const returnUrl = 'https://platform.example/deep_links?course=7';
const instructor = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor';
let jwksUri: string;
let platformKey: CryptoKey;
let server: Server;
const tool1 = generateKeyPairSync('rsa', { modulusLength: 2048 });
const tool2 = generateKeyPairSync('rsa', { modulusLength: 2048 });
const toolKeys: ToolKeys = {
  signing: { kid: 'tool-2025', privateKey: tool1.privateKey },
  publicKeys: [{ ...tool2.publicKey.export({ format: 'jwk' }) as { kty: 'RSA'; n: string; e: string },
    kid: 'tool-2026' }],
};

before(async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  platformKey = keys.privateKey;
  const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'platform-key', alg: 'RS256', use: 'sig' };
  server = createServer(tlsOptions, (_request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: [publicJwk] }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  jwksUri = `https://127.0.0.1:${address.port}/keys`;
});
after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

type ConfigOverrides = { [K in keyof LtiToolConfig]?: LtiToolConfig[K] | undefined };

function tool(overrides: ConfigOverrides = {}, registration: Record<string, unknown> = {}): LtiTool {
  return createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
      deployments: ['deployment-1', 'deployment-2'], allowedTargetLinkUris: [target, assignmentTarget],
      ...registration }] : []; } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore(), toolKeys,
    ...overrides,
  } as LtiToolConfig);
}

const settings = (changes: Record<string, unknown> = {}) => ({
  deep_link_return_url: returnUrl, accept_types: ['ltiResourceLink', 'link'],
  accept_presentation_document_targets: ['iframe', 'window'], ...changes,
});

/** Claims of a deep linking request, applied over the resource link fixture. */
const deepLinkingRequest = (changes: Record<string, unknown> = {}) => ({
  [claim + 'message_type']: 'LtiDeepLinkingRequest', [claim + 'resource_link']: undefined,
  [claim + 'roles']: [instructor], [dl + 'deep_linking_settings']: settings(), ...changes,
});

async function sign(nonce: string, changes: Record<string, unknown>, key = platformKey, kid = 'platform-key') {
  return signLaunch({ privateKey: key, kid, issuer, audience: 'client-1', subject: 'teacher-3', nonce,
    deploymentId: 'deployment-1', targetLinkUri: target, resourceLinkId: 'resource-42',
    roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'], changes });
}

async function launch(lti: LtiTool, changes: Record<string, unknown>, login: Record<string, unknown> = {}) {
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target, ...login })).url);
  return lti.validate({ state: url.searchParams.get('state'),
    id_token: await sign(url.searchParams.get('nonce')!, changes) });
}

async function requestDeepLinking(lti: LtiTool, changes: Record<string, unknown> = {}) {
  return asDeepLinking(await launch(lti, deepLinkingRequest(changes)));
}

async function verifyResponse(lti: LtiTool, jwt: string) {
  return jwtVerify(jwt, createLocalJWKSet({ keys: [...lti.jwks().keys] }), {
    issuer: 'client-1', audience: issuer, algorithms: ['RS256'], requiredClaims: ['iat', 'exp', 'nonce'],
  });
}

const item: LtiContentItem = { type: 'ltiResourceLink', url: assignmentTarget, title: 'Devoir 1',
  custom: { assignment_subject: 'subject-17', empty: '' } };

test('a valid deep linking request yields its settings, identity and raw roles', async () => {
  const request = await requestDeepLinking(tool(), {
    name: 'Ada Lovelace', [claim + 'context']: { id: 'course-7', title: 'Formation' },
    [claim + 'custom']: { from_platform: 'x' },
    [dl + 'deep_linking_settings']: settings({ accept_media_types: 'image/*', accept_multiple: false,
      accept_lineitem: true, auto_create: true, title: 'Default title', text: 'Default text', data: 'opaque' }),
  });
  const { claims, ...normalized } = request;
  const { responseToken, ...deepLinking } = request.deepLinking;
  assert.match(responseToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
  assert.equal(claims.sub, 'teacher-3');
  assert.deepEqual({ ...normalized, deepLinking }, {
    messageType: 'LtiDeepLinkingRequest',
    platform: { issuer, clientId: 'client-1', deploymentId: 'deployment-1' },
    user: { id: 'teacher-3', name: 'Ada Lovelace' },
    context: { id: 'course-7', title: 'Formation' },
    custom: { from_platform: 'x' },
    targetLinkUri: target,
    roles: [instructor],
    normalizedRoles: ['membership:Instructor'],
    deepLinking: { returnUrl, acceptTypes: ['ltiResourceLink', 'link'],
      acceptPresentationDocumentTargets: ['iframe', 'window'], acceptMediaTypes: 'image/*',
      acceptMultiple: false, acceptLineItem: true, autoCreate: true, title: 'Default title', text: 'Default text' },
  });
  assert.equal('resourceLink' in request, false);
  assert.equal(JSON.stringify(normalized).includes('opaque'), false, 'data is only available in raw claims');
});

test('roles are optional in a deep linking request but must be an array when present', async () => {
  for (const roles of [undefined, null, []]) {
    const request = await requestDeepLinking(tool(), { [claim + 'roles']: roles });
    assert.deepEqual(request.roles, []);
    assert.deepEqual(request.normalizedRoles, []);
  }
  const unknown = 'https://vendor.example/roles#Teacher';
  assert.deepEqual((await requestDeepLinking(tool(), { [claim + 'roles']: [unknown, instructor] })).roles,
    [unknown, instructor]);
  assert.deepEqual((await requestDeepLinking(tool(), { [claim + 'roles']: ['not a uri', unknown] })).roles,
    ['not a uri', unknown]);
  for (const roles of ['Instructor', 42]) {
    await assert.rejects(requestDeepLinking(tool(), { [claim + 'roles']: roles }), { code: 'INVALID_CLAIMS' });
  }
});

test('a deep linking request with missing or malformed settings is refused', async () => {
  const { deep_link_return_url: _url, ...withoutReturnUrl } = settings();
  for (const [name, value] of [
    ['missing settings', undefined], ['null settings', null], ['array settings', [settings()]],
    ['missing return url', withoutReturnUrl], ['http return url', settings({ deep_link_return_url: 'http://platform.example/dl' })],
    ['relative return url', settings({ deep_link_return_url: '/deep_links' })],
    ['missing accept_types', settings({ accept_types: undefined })],
    ['string accept_types', settings({ accept_types: 'ltiResourceLink' })],
    ['missing targets', settings({ accept_presentation_document_targets: undefined })],
    ['accept_multiple type', settings({ accept_multiple: 'true' })],
    ['auto_create type', settings({ auto_create: 1 })],
    ['accept_lineitem type', settings({ accept_lineitem: 'yes' })],
    ['title type', settings({ title: 42 })],
    ['media types type', settings({ accept_media_types: ['image/*'] })],
  ] as const) {
    await assert.rejects(requestDeepLinking(tool(), { [dl + 'deep_linking_settings']: value }),
      { code: 'INVALID_CLAIMS' }, name);
  }
});

test('the message type must be a supported one and match its claims', async () => {
  for (const changes of [
    { [claim + 'message_type']: 'LtiSubmissionReviewRequest' },
    { [claim + 'message_type']: 'LtiDeepLinkingResponse' },
    { [claim + 'message_type']: 'ltideeplinkingrequest' },
    { [claim + 'message_type']: undefined },
    // A resource link launch carrying deep linking settings still needs its resource link.
    { [claim + 'message_type']: 'LtiResourceLinkRequest' },
  ]) {
    await assert.rejects(launch(tool(), deepLinkingRequest(changes)), { code: 'INVALID_CLAIMS' });
  }
});

test('every launch security check also applies to deep linking requests', async () => {
  const { privateKey: wrongKey } = await generateKeyPair('RS256');
  const cases: { name: string; changes?: Record<string, unknown>; key?: CryptoKey; kid?: string; code: string }[] = [
    { name: 'signature', key: wrongKey, code: 'INVALID_TOKEN' },
    { name: 'unknown kid', kid: 'alien', code: 'JWKS_ERROR' },
    { name: 'expired', changes: { exp: 1 }, code: 'TOKEN_EXPIRED' },
    { name: 'future iat', changes: { iat: Math.floor(Date.now() / 1000) + 600 }, code: 'INVALID_TOKEN' },
    { name: 'issuer', changes: { iss: 'https://alien.example' }, code: 'INVALID_ISSUER' },
    { name: 'audience', changes: { aud: 'alien' }, code: 'INVALID_AUDIENCE' },
    { name: 'azp', changes: { aud: ['client-1', 'other'], azp: 'other' }, code: 'INVALID_AUDIENCE' },
    { name: 'nonce', changes: { nonce: 'other-nonce' }, code: 'INVALID_NONCE' },
    { name: 'deployment', changes: { [claim + 'deployment_id']: 'other' }, code: 'INVALID_DEPLOYMENT' },
    { name: 'missing deployment', changes: { [claim + 'deployment_id']: undefined }, code: 'INVALID_DEPLOYMENT' },
    { name: 'target', changes: { [claim + 'target_link_uri']: 'https://evil.example/launch' }, code: 'INVALID_CLAIMS' },
    { name: 'missing target', changes: { [claim + 'target_link_uri']: undefined }, code: 'INVALID_CLAIMS' },
    { name: 'version', changes: { [claim + 'version']: '1.2.0' }, code: 'INVALID_CLAIMS' },
    { name: 'subject', changes: { sub: undefined }, code: 'INVALID_CLAIMS' },
    { name: 'subject type', changes: { sub: 42 }, code: 'INVALID_CLAIMS' },
  ];
  for (const scenario of cases) {
    const lti = tool();
    const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
    const id_token = await sign(url.searchParams.get('nonce')!, deepLinkingRequest(scenario.changes),
      scenario.key, scenario.kid);
    await assert.rejects(lti.validate({ state: url.searchParams.get('state'), id_token }), (error: unknown) => {
      assert.ok(error instanceof LtiError, scenario.name);
      assert.equal(error.code, scenario.code, scenario.name);
      return true;
    });
  }
});

test('deep linking requests are bound to state, cannot be replayed and respect the deployment hint', async () => {
  const lti = tool();
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  const state = url.searchParams.get('state')!;
  const id_token = await sign(url.searchParams.get('nonce')!, deepLinkingRequest());
  await assert.rejects(lti.validate({ state: 'unknown', id_token }), { code: 'INVALID_STATE' });
  const outcomes = await Promise.allSettled([lti.validate({ state, id_token }), lti.validate({ state, id_token })]);
  assert.equal(outcomes.filter(outcome => outcome.status === 'fulfilled').length, 1);
  await assert.rejects(lti.validate({ state, id_token }), { code: 'INVALID_STATE' });

  await assert.rejects(launch(tool(), deepLinkingRequest(), { lti_deployment_id: 'deployment-2' }),
    { code: 'INVALID_DEPLOYMENT' });
  await assert.rejects(tool().initiate({ iss: issuer, login_hint: 'hint', target_link_uri: 'https://evil.example/dl' }),
    { code: 'INVALID_TARGET' });
});

test('the signed response is verifiable with the tool JWKS and holds exactly the expected claims', async () => {
  for (const data of ['csrftoken:c7fb', { nested: [1, 'two'] }, null, undefined]) {
    const lti = tool();
    const request = await requestDeepLinking(lti, {
      [dl + 'deep_linking_settings']: settings(data === undefined ? {} : { data }) });
    const before = Math.floor(Date.now() / 1000);
    const response = await lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]);
    assert.equal(response.returnUrl, returnUrl);
    const { payload, protectedHeader } = await verifyResponse(lti, response.jwt);
    assert.deepEqual(protectedHeader, { alg: 'RS256', kid: 'tool-2025', typ: 'JWT' });
    const { iat, exp, nonce, ...rest } = payload;
    assert.ok(typeof iat === 'number' && iat >= before && iat <= before + 5);
    assert.equal(exp, iat + 300);
    assert.match(String(nonce), /^[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(rest, {
      iss: 'client-1', aud: issuer,
      [claim + 'deployment_id']: 'deployment-1',
      [claim + 'message_type']: 'LtiDeepLinkingResponse',
      [claim + 'version']: '1.3.0',
      [dl + 'content_items']: [{ type: 'ltiResourceLink', url: assignmentTarget, title: 'Devoir 1',
        custom: { assignment_subject: 'subject-17', empty: '' } }],
      ...(data !== undefined && { [dl + 'data']: data }),
    }, JSON.stringify(data));
  }
});

test('each response carries a fresh nonce, optional messages and may be empty', async () => {
  const lti = tool();
  const first = await requestDeepLinking(lti);
  const second = await requestDeepLinking(lti);
  const a = await lti.createDeepLinkingResponse(first.deepLinking.responseToken, [], {
    message: 'Aucun devoir choisi', log: 'cancelled', errorMessage: 'Oops', errorLog: 'trace-1' });
  const b = await lti.createDeepLinkingResponse(second.deepLinking.responseToken, [{ type: 'ltiResourceLink' }]);
  const payloadA = (await verifyResponse(lti, a.jwt)).payload;
  const payloadB = (await verifyResponse(lti, b.jwt)).payload;
  assert.notEqual(payloadA.nonce, payloadB.nonce);
  assert.deepEqual(payloadA[dl + 'content_items'], []);
  assert.equal(payloadA[dl + 'msg'], 'Aucun devoir choisi');
  assert.equal(payloadA[dl + 'log'], 'cancelled');
  assert.equal(payloadA[dl + 'errormsg'], 'Oops');
  assert.equal(payloadA[dl + 'errorlog'], 'trace-1');
  assert.deepEqual(payloadB[dl + 'content_items'], [{ type: 'ltiResourceLink' }]);
  assert.equal(payloadB[dl + 'msg'], undefined);
});

test('a response token is single use, opaque and cannot be forged', async () => {
  const lti = tool();
  const request = await requestDeepLinking(lti);
  const token = request.deepLinking.responseToken;
  const outcomes = await Promise.allSettled([lti.createDeepLinkingResponse(token, [item]),
    lti.createDeepLinkingResponse(token, [item])]);
  assert.equal(outcomes.filter(outcome => outcome.status === 'fulfilled').length, 1);
  await assert.rejects(lti.createDeepLinkingResponse(token, [item]), { code: 'INVALID_DEEP_LINKING_RESPONSE' });

  const fresh = (await requestDeepLinking(lti)).deepLinking.responseToken;
  const [, random] = fresh.split('.');
  const alien = Buffer.from(JSON.stringify(['https://alien.example', 'client-1'])).toString('base64url');
  const forged = Buffer.from(JSON.stringify([issuer, 'client-1'])).toString('base64url') + '.' + 'A'.repeat(43);
  for (const candidate of ['', 'garbage', `${alien}.${random}`, forged, `${fresh}x`, fresh.split('.')[1]!]) {
    await assert.rejects(Reflect.apply(lti.createDeepLinkingResponse, lti, [candidate, [item]]),
      (error: unknown) => error instanceof LtiError &&
        ['INVALID_DEEP_LINKING_RESPONSE', 'INVALID_CONFIGURATION'].includes(error.code), candidate);
  }
  await assert.rejects(Reflect.apply(lti.createDeepLinkingResponse, lti, [42, [item]]),
    { code: 'INVALID_DEEP_LINKING_RESPONSE' });
  // The forged attempts did not consume the genuine token.
  assert.ok((await lti.createDeepLinkingResponse(fresh, [item])).jwt);
  // A launch state is not a response token, and a response token is not a launch state.
  await assert.rejects(lti.validate({ state: fresh, id_token: 'x' }), { code: 'INVALID_STATE' });
});

test('a response token expires after the configured lifetime', async () => {
  const lti = tool({ deepLinkingResponseLifetimeMs: 1 });
  const request = await requestDeepLinking(lti);
  await new Promise(resolve => setTimeout(resolve, 5));
  await assert.rejects(lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]),
    { code: 'INVALID_DEEP_LINKING_RESPONSE' });
  for (const deepLinkingResponseLifetimeMs of [0, -1, 1.5, Number.NaN, Infinity]) {
    assert.throws(() => tool({ deepLinkingResponseLifetimeMs }), { code: 'INVALID_CONFIGURATION' });
  }
});

test('malformed content items are refused without consuming the response token', async () => {
  const lti = tool();
  const token = (await requestDeepLinking(lti)).deepLinking.responseToken;
  for (const items of [
    'not an array', [null], [{ type: 'link', url: 'https://example.org' }], [{ title: 'No type' }],
    [{ type: 'ltiResourceLink', custom: { n: 42 } }], [{ type: 'ltiResourceLink', custom: { n: null } }],
    [{ type: 'ltiResourceLink', custom: ['a'] }], [{ type: 'ltiResourceLink', custom: { '': 'x' } }],
    [{ type: 'ltiResourceLink', url: 'https://evil.example/launch' }],
    [{ type: 'ltiResourceLink', url: target + '#x' }], [{ type: 'ltiResourceLink', title: 7 }],
    [{ type: 'ltiResourceLink', lineItem: { scoreMaximum: 10 } }],
  ]) {
    await assert.rejects(Reflect.apply(lti.createDeepLinkingResponse, lti, [token, items]),
      { code: 'INVALID_CONTENT_ITEMS' }, JSON.stringify(items));
  }
  await assert.rejects(Reflect.apply(lti.createDeepLinkingResponse, lti, [token, [item], { msg: 'x' }]),
    { code: 'INVALID_CONTENT_ITEMS' });
  await assert.rejects(Reflect.apply(lti.createDeepLinkingResponse, lti, [token, [item], { message: 1 }]),
    { code: 'INVALID_CONTENT_ITEMS' });
  assert.ok((await lti.createDeepLinkingResponse(token, [item])).jwt);
});

test('items refused by accept_types or accept_multiple fail and consume the token', async () => {
  for (const [changes, items] of [
    [{ accept_types: ['link'] }, [item]],
    [{ accept_multiple: false }, [item, item]],
    [{}, [item, item]],
  ] as const) {
    const lti = tool();
    const token = (await requestDeepLinking(lti, { [dl + 'deep_linking_settings']: settings(changes) }))
      .deepLinking.responseToken;
    await assert.rejects(lti.createDeepLinkingResponse(token, items), { code: 'INVALID_CONTENT_ITEMS' });
    await assert.rejects(lti.createDeepLinkingResponse(token, [item]), { code: 'INVALID_DEEP_LINKING_RESPONSE' });
  }
  const lti = tool();
  const token = (await requestDeepLinking(lti, { [dl + 'deep_linking_settings']: settings({ accept_multiple: true }) }))
    .deepLinking.responseToken;
  const { payload } = await verifyResponse(lti, (await lti.createDeepLinkingResponse(token, [item, item])).jwt);
  assert.equal((payload[dl + 'content_items'] as unknown[]).length, 2);
});

test('custom parameters returned by deep linking come back in the next resource link launch', async () => {
  const lti = tool();
  const request = await requestDeepLinking(lti);
  const response = await lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]);
  // Fake platform: verify the response, persist the item, then launch a learner on it.
  const { payload } = await verifyResponse(lti, response.jwt);
  const [created] = payload[dl + 'content_items'] as { url: string; custom: Record<string, string> }[];
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'learner', target_link_uri: created!.url })).url);
  const learner = asResourceLink(await lti.validate({ state: url.searchParams.get('state'),
    id_token: await signLaunch({ privateKey: platformKey, kid: 'platform-key', issuer, audience: 'client-1',
      subject: 'learner-9', nonce: url.searchParams.get('nonce')!, deploymentId: 'deployment-1',
      targetLinkUri: created!.url, resourceLinkId: 'created-link-1',
      roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
      changes: { [claim + 'custom']: created!.custom } }) }));
  assert.deepEqual(learner.custom, { assignment_subject: 'subject-17', empty: '' });
  assert.equal(learner.targetLinkUri, assignmentTarget);
});

test('a response omits deployment_id only when the request had none', async () => {
  const lti = tool({}, { deploymentIdRequired: false, deployments: [] });
  const request = await requestDeepLinking(lti, { [claim + 'deployment_id']: undefined });
  assert.equal(request.platform.deploymentId, undefined);
  const { payload } = await verifyResponse(lti,
    (await lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item])).jwt);
  assert.equal(Object.hasOwn(payload, claim + 'deployment_id'), false);
});

test('the tool JWKS publishes the signing key and rotation keys, never private members', async () => {
  const jwks = tool().jwks();
  assert.deepEqual(jwks.keys.map(key => key.kid), ['tool-2025', 'tool-2026']);
  for (const key of jwks.keys) {
    assert.deepEqual(Object.keys(key).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
    assert.equal(key.alg, 'RS256');
    assert.equal(key.use, 'sig');
  }
  assert.equal(jwks.keys[0]!.n, (tool1.publicKey.export({ format: 'jwk' }) as { n: string }).n);
  assert.ok(Object.isFrozen(jwks) && Object.isFrozen(jwks.keys));

  // After rotation, a response signed with the next key verifies against the same published set.
  const rotated = tool({ toolKeys: { signing: { kid: 'tool-2026', privateKey: tool2.privateKey },
    publicKeys: [{ ...tool1.publicKey.export({ format: 'jwk' }) as { kty: 'RSA'; n: string; e: string }, kid: 'tool-2025' }] } });
  const request = await requestDeepLinking(rotated);
  const { jwt } = await rotated.createDeepLinkingResponse(request.deepLinking.responseToken, [item]);
  assert.equal(decodeProtectedHeader(jwt).kid, 'tool-2026');
  await jwtVerify(jwt, createLocalJWKSet({ keys: [...jwks.keys] }), { issuer: 'client-1', audience: issuer });
});

test('responses signed with each private key form verify against the published JWKS', async () => {
  const keys = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['sign', 'verify']);
  const webPublicJwk = await exportJWK(keys.publicKey) as { kty: 'RSA'; n: string; e: string };
  for (const [name, signing] of [
    ['KeyObject', { kid: 'node', privateKey: tool1.privateKey }],
    ['private JWK', { kid: 'jwk', privateKey: tool1.privateKey.export({ format: 'jwk' }) }],
    ['non-extractable CryptoKey', { kid: 'web', privateKey: keys.privateKey, publicJwk: webPublicJwk }],
  ] as const) {
    const lti = tool({ toolKeys: { signing } as unknown as ToolKeys });
    const request = await requestDeepLinking(lti);
    const { jwt } = await lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]);
    assert.equal(decodeProtectedHeader(jwt).kid, signing.kid, name);
    await verifyResponse(lti, jwt);
  }
});

test('a CryptoKey published with another public JWK fails closed when signing', async () => {
  const keys = await webcrypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['sign']);
  const otherJwk = tool2.publicKey.export({ format: 'jwk' }) as { kty: 'RSA'; n: string; e: string };
  const lti = tool({ toolKeys: { signing: { kid: 'web', privateKey: keys.privateKey, publicJwk: otherJwk } } });
  const request = await requestDeepLinking(lti);
  await assert.rejects(lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]),
    { code: 'INVALID_CONFIGURATION' });
});

test('invalid tool keys are refused without ever revealing the private key', async () => {
  const privateJwk = tool1.privateKey.export({ format: 'jwk' }) as Record<string, string>;
  const privatePem = tool1.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  const small = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const pss = (await webcrypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['sign'])).privateKey;
  const publicJwk = tool2.publicKey.export({ format: 'jwk' }) as { kty: 'RSA'; n: string; e: string };
  for (const [name, keys] of [
    ['pem string', { signing: { kid: 'k', privateKey: privatePem } }],
    ['public key', { signing: { kid: 'k', privateKey: tool1.publicKey } }],
    ['small key', { signing: { kid: 'k', privateKey: small } }],
    ['ec key', { signing: { kid: 'k', privateKey: ec } }],
    ['pss key', { signing: { kid: 'k', privateKey: pss, publicJwk } }],
    ['missing kid', { signing: { privateKey: tool1.privateKey } }],
    ['duplicate kid', { signing: { kid: 'k', privateKey: tool1.privateKey }, publicKeys: [{ ...publicJwk, kid: 'k' }] }],
    ['private rotation key', { signing: { kid: 'k', privateKey: tool1.privateKey },
      publicKeys: [{ ...privateJwk, kid: 'leak' }] }],
    ['rotation key alg', { signing: { kid: 'k', privateKey: tool1.privateKey },
      publicKeys: [{ ...publicJwk, kid: 'x', alg: 'RS512' }] }],
    ['rotation key not a list', { signing: { kid: 'k', privateKey: tool1.privateKey }, publicKeys: publicJwk }],
  ] as const) {
    assert.throws(() => tool({ toolKeys: keys as unknown as ToolKeys }), (error: unknown) => {
      assert.ok(error instanceof LtiError, name);
      assert.equal(error.code, 'INVALID_CONFIGURATION', name);
      assert.equal(error.cause, undefined, name);
      const rendered = `${inspect(error, { depth: 10 })} ${JSON.stringify(error)} ${String(error)}`;
      assert.equal(rendered.includes(privateJwk.d!), false, name);
      assert.equal(rendered.includes('PRIVATE KEY'), false, name);
      return true;
    }, name);
  }
  const rendered = inspect(tool(), { depth: 10, showHidden: true }) + JSON.stringify(tool().jwks());
  assert.equal(rendered.includes(privateJwk.d!), false);
});

test('without tool keys, deep linking requests validate but responses and JWKS are unavailable', async () => {
  const lti = tool({ toolKeys: undefined });
  const request = await requestDeepLinking(lti);
  assert.throws(() => lti.jwks(), { code: 'INVALID_CONFIGURATION' });
  await assert.rejects(lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]),
    { code: 'INVALID_CONFIGURATION' });
});

test('store failures around the response token are normalized and reported', async () => {
  const diagnostics: LtiDiagnostic[] = [];
  const memory = new MemoryOneTimeStore();
  let failPut = false;
  let failTake = false;
  const store: OneTimeStore = {
    async put(key, value, expiresAt) {
      if (failPut && key.includes('.')) throw new Error('redis down');
      return memory.put(key, value, expiresAt);
    },
    async take(key) {
      if (failTake && key.includes('.')) throw new Error('redis down');
      return memory.take(key);
    },
  };
  const lti = tool({ store, onDiagnostic: diagnostic => diagnostics.push(diagnostic) });
  failPut = true;
  await assert.rejects(requestDeepLinking(lti), { code: 'STORE_ERROR' });
  failPut = false;
  const request = await requestDeepLinking(lti);
  failTake = true;
  await assert.rejects(lti.createDeepLinkingResponse(request.deepLinking.responseToken, [item]),
    { code: 'STORE_ERROR' });
  assert.deepEqual(diagnostics, [
    { code: 'DEEP_LINKING_RESPONSE_PUT_FAILED', errorCode: 'STORE_ERROR' },
    { code: 'DEEP_LINKING_RESPONSE_TAKE_FAILED', errorCode: 'STORE_ERROR' },
  ]);
});
