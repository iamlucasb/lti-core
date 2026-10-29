import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import type { TestContext } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type { LtiTool, ToolKeys } from '../src/index.js';
import { createTestPlatform } from '../src/testing.js';
import type { TestPlatform, TestPlatformOptions } from '../src/testing.js';
import { asDeepLinking, asResourceLink } from './fixtures/launch-kind.js';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';
const target = 'https://tool.example/launch';
const learner = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
const instructor = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor';

let toolKeys: ToolKeys;
let otherToolKeys: ToolKeys;

async function testToolKeys(kid: string): Promise<ToolKeys> {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const { n, e } = await exportJWK(publicKey);
  if (n === undefined || e === undefined) throw new Error('No RSA key');
  return { signing: { kid, privateKey, publicJwk: { kty: 'RSA', n, e } } };
}

before(async () => {
  toolKeys = await testToolKeys('tool-key');
  otherToolKeys = await testToolKeys('other-tool-key');
});

async function platformWithFetch(t: TestContext, options: Partial<TestPlatformOptions> = {}): Promise<TestPlatform> {
  const platform = await createTestPlatform({ targetLinkUri: target, ...options });
  t.after(platform.installFetch());
  return platform;
}

function toolFor(platform: TestPlatform, keys = toolKeys): LtiTool {
  return createLtiTool({
    resolver: { async resolve(issuer) { return issuer === platform.issuer ? [platform.registration()] : []; } },
    redirectUri: platform.redirectUri, store: new MemoryOneTimeStore(), toolKeys: keys, jwks: { cooldownMs: 0 },
  });
}

async function launch(platform: TestPlatform, tool: LtiTool, launchOptions: Parameters<TestPlatform['authorize']>[1] = {}) {
  const { url } = await tool.initiate(platform.loginRequest());
  return tool.validate(await platform.authorize(url, launchOptions));
}

test('a resource link launch through the test platform is validated by the tool', async t => {
  const platform = await platformWithFetch(t);
  const validated = asResourceLink(await launch(platform, toolFor(platform), { subject: 'user-17',
    claims: { [claim + 'custom']: { section: 'A' } } }));
  assert.deepEqual(validated.platform, { issuer: 'https://platform.test', clientId: 'test-client',
    deploymentId: 'test-deployment' });
  assert.deepEqual(validated.user, { id: 'user-17' });
  assert.deepEqual(validated.resourceLink, { id: 'test-resource-link' });
  assert.deepEqual(validated.roles, [learner]);
  assert.deepEqual(validated.custom, { section: 'A' });
  assert.equal(validated.targetLinkUri, target);
});

test('a deep linking round trip: the platform reads the signed response of the tool', async t => {
  const platform = await platformWithFetch(t);
  const tool = toolFor(platform);
  const validated = asDeepLinking(await launch(platform, tool, { messageType: 'LtiDeepLinkingRequest',
    deepLinking: { data: 'opaque-data', acceptMultiple: true } }));
  assert.deepEqual(validated.roles, [instructor]);
  assert.equal(validated.deepLinking.returnUrl, 'https://platform.test/deep-linking/return');
  assert.deepEqual(validated.deepLinking.acceptTypes, ['ltiResourceLink']);
  assert.deepEqual(validated.deepLinking.acceptPresentationDocumentTargets, ['iframe', 'window']);
  assert.equal(validated.deepLinking.acceptMultiple, true);

  const response = await tool.createDeepLinkingResponse(validated.deepLinking.responseToken,
    [{ type: 'ltiResourceLink', url: target, title: 'Lesson', custom: { lesson: '7' } }]);
  const seen = await platform.readDeepLinkingResponse(response, tool.jwks());
  assert.equal(seen.kid, 'tool-key');
  assert.deepEqual(seen.contentItems, [{ type: 'ltiResourceLink', url: target, title: 'Lesson', custom: { lesson: '7' } }]);
  assert.equal(seen.claims['https://purl.imsglobal.org/spec/lti-dl/claim/data'], 'opaque-data');
  assert.equal(seen.claims[claim + 'deployment_id'], 'test-deployment');
});

test('deploymentId null plays a platform that omits deployment_id, with a matching registration', async t => {
  const platform = await platformWithFetch(t, { deploymentId: null });
  assert.equal(platform.deploymentId, undefined);
  assert.equal(platform.registration().deploymentIdRequired, false);
  assert.deepEqual(platform.registration().deployments, []);
  assert.equal('lti_deployment_id' in platform.loginRequest(), false);
  const tool = toolFor(platform);
  assert.equal(asResourceLink(await launch(platform, tool)).platform.deploymentId, undefined);

  const validated = asDeepLinking(await launch(platform, tool, { messageType: 'LtiDeepLinkingRequest' }));
  assert.equal(validated.platform.deploymentId, undefined);
  const response = await tool.createDeepLinkingResponse(validated.deepLinking.responseToken, []);
  const seen = await platform.readDeepLinkingResponse(response, tool.jwks());
  assert.equal(claim + 'deployment_id' in seen.claims, false);
  assert.deepEqual(seen.contentItems, []);
});

test('default roles are configurable per message type', async t => {
  const platform = await platformWithFetch(t, { roles: { resourceLink: [instructor], deepLinking: [] } });
  const tool = toolFor(platform);
  assert.deepEqual((await launch(platform, tool)).roles, [instructor]);
  assert.deepEqual((await launch(platform, tool, { messageType: 'LtiDeepLinkingRequest' })).roles, []);
  assert.deepEqual((await launch(platform, tool, { roles: [learner] })).roles, [learner]);
});

test('claims override the token, and undefined removes a claim', async t => {
  const platform = await platformWithFetch(t);
  const tool = toolFor(platform);
  await assert.rejects(launch(platform, tool, { claims: { [claim + 'roles']: undefined } }),
    (error: unknown) => error instanceof LtiError && error.reason === 'claim:roles');
  await assert.rejects(launch(platform, tool, { claims: { [claim + 'deployment_id']: 'other-deployment' } }),
    (error: unknown) => error instanceof LtiError && error.code === 'INVALID_DEPLOYMENT');
});

test('a token signed by another test platform is refused by the tool', async t => {
  const platform = await platformWithFetch(t);
  const impostor = await createTestPlatform({ targetLinkUri: target });
  const tool = toolFor(platform);
  const { url } = await tool.initiate(platform.loginRequest());
  await assert.rejects(tool.validate(await impostor.authorize(url)),
    (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR');
});

test('authorize checks the authorization request like a platform', async t => {
  const platform = await platformWithFetch(t);
  const { url } = await toolFor(platform).initiate(platform.loginRequest());
  const changed = (name: string, value: string | null) => {
    const changedUrl = new URL(url);
    if (value === null) changedUrl.searchParams.delete(name);
    else changedUrl.searchParams.set(name, value);
    return changedUrl.href;
  };
  const refused = [
    changed('redirect_uri', 'https://tool.example/elsewhere'), changed('client_id', 'other-client'),
    changed('scope', 'profile'), changed('response_type', 'code'), changed('response_mode', 'query'),
    changed('prompt', 'login'), changed('nonce', null), changed('state', null), changed('login_hint', null),
    url.replace('https://platform.test/authorize', 'https://platform.test/other'),
  ];
  for (const authorizationUrl of refused) {
    await assert.rejects(platform.authorize(authorizationUrl), /^Error: Test platform: /);
  }
  const { state } = await platform.authorize(url);
  assert.equal(state, new URL(url).searchParams.get('state'));
});

test('readDeepLinkingResponse refuses a response the platform would refuse', async t => {
  const platform = await platformWithFetch(t);
  const tool = toolFor(platform);
  const respond = async () => {
    const validated = asDeepLinking(await launch(platform, tool, { messageType: 'LtiDeepLinkingRequest' }));
    return tool.createDeepLinkingResponse(validated.deepLinking.responseToken, []);
  };
  const response = await respond();
  const [header, payload, signature] = response.jwt.split('.');
  const tampered = `${header}.${payload}.${signature!.startsWith('A') ? 'B' : 'A'}${signature!.slice(1)}`;
  const otherKeys = createLtiTool({ resolver: { async resolve() { return []; } }, redirectUri: target,
    store: new MemoryOneTimeStore(), toolKeys: otherToolKeys }).jwks();
  const otherClient = await createTestPlatform({ targetLinkUri: target, clientId: 'other-client' });
  const otherDeployment = await createTestPlatform({ targetLinkUri: target, deploymentId: 'other-deployment' });

  await assert.rejects(platform.readDeepLinkingResponse({ ...response, jwt: tampered }, tool.jwks()), /signature/);
  await assert.rejects(platform.readDeepLinkingResponse(response, otherKeys), /signature/);
  await assert.rejects(platform.readDeepLinkingResponse({ ...response, returnUrl: 'https://platform.test/x' },
    tool.jwks()), /return URL/);
  await assert.rejects(otherClient.readDeepLinkingResponse(response, tool.jwks()), /iss/);
  await assert.rejects(otherDeployment.readDeepLinkingResponse(response, tool.jwks()), /deployment_id/);
  assert.deepEqual((await platform.readDeepLinkingResponse(await respond(), tool.jwks())).contentItems, []);
});

test('the fetch stub serves only the JWKS URI and restores the previous fetch', async () => {
  const platform = await createTestPlatform({ targetLinkUri: target, issuer: 'https://lms.test' });
  assert.equal(platform.jwksUri, 'https://lms.test/jwks');
  assert.equal(platform.respond('https://lms.test/other'), undefined);
  assert.deepEqual(await platform.respond(platform.jwksUri)!.json(), platform.jwks);
  assert.equal('d' in platform.jwks.keys[0]!, false);

  const original = globalThis.fetch;
  const seen: string[] = [];
  const previous = async (input: string | URL | Request) => {
    seen.push(String(input));
    return new Response('passed through');
  };
  globalThis.fetch = previous;
  try {
    const restore = platform.installFetch();
    assert.deepEqual(await (await fetch(new URL(platform.jwksUri))).json(), platform.jwks);
    assert.deepEqual(await (await fetch(new Request(platform.jwksUri))).json(), platform.jwks);
    assert.equal(await (await fetch('https://elsewhere.test/')).text(), 'passed through');
    assert.deepEqual(seen, ['https://elsewhere.test/']);
    restore();
    assert.equal(globalThis.fetch, previous);
  } finally {
    globalThis.fetch = original;
  }
});

test('createTestPlatform refuses non-HTTPS URLs', async () => {
  await assert.rejects(createTestPlatform({ targetLinkUri: 'http://tool.example/launch' }), TypeError);
  await assert.rejects(createTestPlatform({ targetLinkUri: target, issuer: 'platform.test' }), TypeError);
});
