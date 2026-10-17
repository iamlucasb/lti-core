import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { inspect } from 'node:util';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type {
  LtiErrorCode, LtiErrorReason, LtiTool, LtiToolConfig, Registration, ToolKeys,
} from '../src/index.js';
import { asDeepLinking } from './fixtures/launch-kind.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';
const dl = 'https://purl.imsglobal.org/spec/lti-dl/claim/';
const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
const redirectUri = 'https://tool.example/callback';
const instructor = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor';
const toolKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
const toolKeys: ToolKeys = { signing: { kid: 'tool-key', privateKey: toolKey.privateKey } };
let jwksUri: string;
let platformKey: CryptoKey;
let server: Server;

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

function registration(changes: Partial<Registration> = {}): Registration {
  return { issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
    deployments: ['deployment-1', 'deployment-2'], allowedTargetLinkUris: [target], ...changes };
}

function tool(overrides: Record<string, unknown> = {}, registrations = () => [registration()]): LtiTool {
  return createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? registrations() : []; } },
    redirectUri, store: new MemoryOneTimeStore(), toolKeys, ...overrides,
  } as LtiToolConfig);
}

/** Matches an LtiError carrying `code` and `reason`, with the `CODE: reason` message. */
function failure(code: LtiErrorCode, reason: LtiErrorReason) {
  return (error: unknown) => {
    assert.ok(error instanceof LtiError, reason);
    assert.equal(error.code, code, reason);
    assert.equal(error.reason, reason);
    assert.equal(error.message, `${code}: ${reason}`);
    return true;
  };
}

async function initiation(lti: LtiTool, login: Record<string, unknown> = {}) {
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target, ...login })).url);
  return { state: url.searchParams.get('state')!, nonce: url.searchParams.get('nonce')! };
}

function sign(nonce: string, changes: Record<string, unknown> = {}, kid = 'platform-key') {
  return signLaunch({ privateKey: platformKey, kid, issuer, audience: 'client-1', subject: 'user-1', nonce,
    deploymentId: 'deployment-1', targetLinkUri: target, resourceLinkId: 'resource-1',
    roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'], changes });
}

async function launch(lti: LtiTool, changes: Record<string, unknown> = {}, login: Record<string, unknown> = {}) {
  const { state, nonce } = await initiation(lti, login);
  return lti.validate({ state, id_token: await sign(nonce, changes) });
}

const deepLinkingRequest = (settings: Record<string, unknown> = {}) => ({
  [claim + 'message_type']: 'LtiDeepLinkingRequest', [claim + 'resource_link']: undefined,
  [claim + 'roles']: [instructor],
  [dl + 'deep_linking_settings']: { deep_link_return_url: 'https://platform.example/return',
    accept_types: ['ltiResourceLink'], accept_presentation_document_targets: ['iframe'], ...settings },
});

async function responseToken(lti: LtiTool, settings: Record<string, unknown> = {}) {
  return asDeepLinking(await launch(lti, deepLinkingRequest(settings))).deepLinking.responseToken;
}

test('configuration errors name the invalid option', () => {
  const cases: [Record<string, unknown>, LtiErrorReason][] = [
    [{ redirectUri: 'http://tool.example/callback' }, 'config:redirectUri'],
    [{ redirectUri: 'https://tool.example/callback#fragment' }, 'config:redirectUri'],
    [{ resolver: {} }, 'config:resolver'],
    [{ resolver: undefined }, 'config:resolver'],
    [{ store: { put() {} } }, 'config:store'],
    [{ onDiagnostic: 'log' }, 'config:onDiagnostic'],
    [{ deepLinkingResponseLifetimeMs: 0 }, 'config:deepLinkingResponseLifetimeMs'],
    [{ clockToleranceSeconds: -1 }, 'config:clockToleranceSeconds'],
    [{ jwks: { timeoutMs: 0 } }, 'config:jwks'],
    [{ toolKeys: { signing: { kid: 'tool-key', privateKey: toolKey.publicKey } } }, 'config:toolKeys'],
  ];
  for (const [overrides, reason] of cases) {
    assert.throws(() => tool(overrides), failure('INVALID_CONFIGURATION', reason));
  }
  assert.throws(() => createLtiTool(null as unknown as LtiToolConfig), failure('INVALID_CONFIGURATION', 'config:invalid'));
  assert.throws(() => tool({ toolKeys: undefined }).jwks(), failure('INVALID_CONFIGURATION', 'config:toolKeys_missing'));
});

test('login errors name the invalid initiation parameter, target, registration or deployment', async () => {
  const lti = tool();
  await assert.rejects(lti.initiate(null as never), failure('INVALID_LOGIN', 'login:invalid'));
  const cases: [Record<string, unknown>, LtiErrorReason][] = [
    [{ iss: '' }, 'login:iss'],
    [{ login_hint: undefined }, 'login:login_hint'],
    [{ target_link_uri: 42 }, 'login:target_link_uri'],
    [{ client_id: '' }, 'login:client_id'],
    [{ lti_message_hint: 7 }, 'login:lti_message_hint'],
    [{ lti_deployment_id: '' }, 'login:lti_deployment_id'],
  ];
  for (const [login, reason] of cases) {
    await assert.rejects(initiation(lti, login), failure('INVALID_LOGIN', reason));
  }
  await assert.rejects(initiation(lti, { client_id: 'client-2' }), failure('INVALID_LOGIN', 'registration:not_found'));
  await assert.rejects(initiation(lti, { target_link_uri: 'https://tool.example/other' }),
    failure('INVALID_TARGET', 'target:not_allowed'));
  await assert.rejects(initiation(lti, { lti_deployment_id: 'deployment-9' }),
    failure('INVALID_DEPLOYMENT', 'deployment:unknown'));
  const shared = tool({}, () => [registration(), registration({ clientId: 'client-2' })]);
  await assert.rejects(initiation(shared), failure('INVALID_LOGIN', 'registration:ambiguous'));
});

test('state and store errors name the failed step', async () => {
  const lti = tool();
  await assert.rejects(lti.validate({ id_token: 'token' }), failure('INVALID_STATE', 'state:missing'));
  await assert.rejects(lti.validate({ state: 'unknown', id_token: 'token' }), failure('INVALID_STATE', 'state:unknown'));
  const { state } = await initiation(lti);
  await assert.rejects(lti.validate({ state }), failure('INVALID_TOKEN', 'token:missing'));
  const failing = tool({ store: { async put() { throw new Error('down'); }, async take() { throw new Error('down'); } } });
  await assert.rejects(initiation(failing), failure('STORE_ERROR', 'store:put'));
  await assert.rejects(failing.validate({ state: 'state', id_token: 'token' }), failure('STORE_ERROR', 'store:take'));
});

test('token errors name the failed verification', async () => {
  const lti = tool();
  const now = Math.floor(Date.now() / 1000);
  let attempt = await initiation(lti);
  await assert.rejects(lti.validate({ state: attempt.state, id_token: 'not-a-jwt' }),
    failure('INVALID_TOKEN', 'token:malformed'));
  attempt = await initiation(lti);
  const unsignedKid = await new SignJWT({ iss: issuer, aud: 'client-1', sub: 'user-1', iat: now, exp: now + 300,
    nonce: attempt.nonce }).setProtectedHeader({ alg: 'RS256' }).sign(platformKey);
  await assert.rejects(lti.validate({ state: attempt.state, id_token: unsignedKid }), failure('INVALID_TOKEN', 'token:kid'));
  attempt = await initiation(lti);
  const hmac = await new SignJWT({ nonce: attempt.nonce }).setProtectedHeader({ alg: 'HS256', kid: 'platform-key' })
    .sign(new Uint8Array(32));
  await assert.rejects(lti.validate({ state: attempt.state, id_token: hmac }), failure('INVALID_TOKEN', 'token:alg'));
  attempt = await initiation(lti);
  await assert.rejects(lti.validate({ state: attempt.state, id_token: await sign(attempt.nonce, {}, 'unknown-key') }),
    failure('JWKS_ERROR', 'jwks:no_matching_key'));
  await assert.rejects(launch(lti, { nbf: now + 600 }), failure('INVALID_TOKEN', 'token:nbf'));
  await assert.rejects(launch(lti, { exp: undefined }), failure('INVALID_TOKEN', 'token:exp'));
  await assert.rejects(launch(lti, { exp: 1 }), failure('TOKEN_EXPIRED', 'token:exp'));
  await assert.rejects(launch(lti, { azp: 'client-2' }), failure('INVALID_AUDIENCE', 'token:azp'));
  await assert.rejects(launch(lti, { aud: ['client-1', 'client-2'] }), failure('INVALID_AUDIENCE', 'token:aud'));
  attempt = await initiation(lti);
  await assert.rejects(lti.validate({ state: attempt.state, id_token: await sign('other-nonce') }),
    failure('INVALID_NONCE', 'token:nonce'));
  const unreachable = tool({}, () => [registration({ jwksUri: 'https://127.0.0.1:1/keys' })]);
  await assert.rejects(launch(unreachable), failure('JWKS_ERROR', 'jwks:unavailable'));
});

test('claim and deployment errors name the failed claim', async () => {
  const lti = tool();
  const cases: [Record<string, unknown>, LtiErrorCode, LtiErrorReason][] = [
    [{ [claim + 'context']: 'course' }, 'INVALID_CLAIMS', 'claim:context'],
    [{ [claim + 'context']: { title: 'Course' } }, 'INVALID_CLAIMS', 'claim:context.id'],
    [{ [claim + 'roles']: 'Learner' }, 'INVALID_CLAIMS', 'claim:roles'],
    [{ [claim + 'resource_link']: 'resource' }, 'INVALID_CLAIMS', 'claim:resource_link'],
    [{ [claim + 'message_type']: 'LtiSubmissionReviewRequest' }, 'INVALID_CLAIMS', 'claim:message_type'],
    [deepLinkingRequest({ accept_types: 'ltiResourceLink' }), 'INVALID_CLAIMS', 'claim:deep_linking_settings'],
    [{ [claim + 'deployment_id']: 42 }, 'INVALID_DEPLOYMENT', 'deployment:malformed'],
    [{ [claim + 'deployment_id']: 'deployment-9' }, 'INVALID_DEPLOYMENT', 'deployment:unknown'],
  ];
  for (const [changes, code, reason] of cases) {
    await assert.rejects(launch(lti, changes), failure(code, reason));
  }
  await assert.rejects(launch(lti, {}, { lti_deployment_id: 'deployment-2' }),
    failure('INVALID_DEPLOYMENT', 'deployment:hint_mismatch'));
});

test('registration errors name the resolver failure or the registration lookup', async () => {
  await assert.rejects(initiation(tool({}, () => { throw new Error('down'); })),
    failure('INVALID_CONFIGURATION', 'registration:resolution_failed'));
  await assert.rejects(initiation(tool({}, () => [registration({ jwksUri: 'http://platform.example/keys' })])),
    failure('INVALID_CONFIGURATION', 'registration:invalid'));
  let current = [registration()];
  const lti = tool({}, () => current);
  let attempt = await initiation(lti);
  current = [];
  await assert.rejects(lti.validate({ state: attempt.state, id_token: 'token' }),
    failure('INVALID_CONFIGURATION', 'registration:not_found'));
  current = [registration()];
  attempt = await initiation(lti);
  current = [registration(), registration()];
  await assert.rejects(lti.validate({ state: attempt.state, id_token: 'token' }),
    failure('INVALID_CONFIGURATION', 'registration:ambiguous'));
  current = [registration()];
  attempt = await initiation(lti);
  current = [registration({ allowedTargetLinkUris: ['https://tool.example/other'] })];
  await assert.rejects(lti.validate({ state: attempt.state, id_token: 'token' }),
    failure('INVALID_TARGET', 'target:not_allowed'));
});

test('deep linking response errors name the failed content item, option or token check', async () => {
  const lti = tool();
  const token = await responseToken(lti);
  const item = { type: 'ltiResourceLink' };
  const cases: [unknown, LtiErrorReason][] = [
    ['item', 'content_items:array'],
    [[null], 'content_items:item'],
    [[{ type: 'link' }], 'content_items:type'],
    [[{ ...item, icon: {} }], 'content_items:property'],
    [[{ ...item, url: 'https://tool.example/other' }], 'content_items:url'],
    [[{ ...item, title: 1 }], 'content_items:title'],
    [[{ ...item, text: 1 }], 'content_items:text'],
    [[{ ...item, custom: { key: 1 } }], 'content_items:custom'],
  ];
  for (const [items, reason] of cases) {
    await assert.rejects(lti.createDeepLinkingResponse(token, items as never),
      failure('INVALID_CONTENT_ITEMS', reason));
  }
  await assert.rejects(lti.createDeepLinkingResponse(token, [], { msg: 'x' } as never),
    failure('INVALID_CONTENT_ITEMS', 'content_items:options'));
  await assert.rejects(lti.createDeepLinkingResponse('not-a-token', []),
    failure('INVALID_DEEP_LINKING_RESPONSE', 'response_token:malformed'));
  await lti.createDeepLinkingResponse(token, []);
  await assert.rejects(lti.createDeepLinkingResponse(token, []),
    failure('INVALID_DEEP_LINKING_RESPONSE', 'response_token:unknown'));
  await assert.rejects(lti.createDeepLinkingResponse(await responseToken(lti), [item, item] as never),
    failure('INVALID_CONTENT_ITEMS', 'content_items:accept_multiple'));
  await assert.rejects(lti.createDeepLinkingResponse(await responseToken(lti, { accept_types: ['link'] }),
    [item] as never), failure('INVALID_CONTENT_ITEMS', 'content_items:accept_types'));
  await assert.rejects(tool({ toolKeys: undefined }).createDeepLinkingResponse(token, []),
    failure('INVALID_CONFIGURATION', 'config:toolKeys_missing'));
});

test('reasons and messages never reveal key material, tokens, state, nonce or claim values', async () => {
  const privateJwk = toolKey.privateKey.export({ format: 'jwk' });
  const secrets: string[] = [privateJwk.d!, privateJwk.p!, privateJwk.q!, privateJwk.n!];
  const errors: unknown[] = [];
  const collect = async (operation: () => unknown) => {
    try {
      await operation();
      assert.fail('expected an LtiError');
    } catch (error) {
      errors.push(error);
    }
  };
  await collect(() => tool({ toolKeys: { signing: { kid: 'tool-key', privateKey: { ...privateJwk, alg: 'HS256' } } } }));
  await collect(() => tool({ toolKeys: { signing: { kid: 'tool-key', privateKey: { ...privateJwk, kty: 'EC' } } } }));
  const lti = tool();
  for (const changes of [{ sub: 'secret-user@example.org', [claim + 'version']: '9.9' },
    { [claim + 'deployment_id']: 'secret-deployment' }, { aud: 'secret-audience' }, { iss: 'https://secret.example' }]) {
    const { state, nonce } = await initiation(lti);
    const idToken = await sign(nonce, changes);
    secrets.push(state, nonce, idToken, ...Object.values(changes).map(String));
    await collect(() => lti.validate({ state, id_token: idToken }));
  }
  const { state, nonce } = await initiation(lti);
  secrets.push(state, nonce);
  await collect(() => lti.validate({ state, id_token: 'secret-malformed-token' }));
  await collect(() => lti.validate({ state, id_token: 'secret-replayed-token' }));
  secrets.push('secret-malformed-token', 'secret-replayed-token');

  assert.equal(errors.length, 8);
  for (const error of errors) {
    assert.ok(error instanceof LtiError);
    assert.match(error.reason ?? '', /^[a-z_]+:[A-Za-z_.]+$/);
    const rendered = `${error.message} ${error.reason} ${String(error)} ${JSON.stringify(error)} ${inspect(error)}`;
    for (const secret of secrets) assert.equal(rendered.includes(secret), false, error.message);
  }
});
