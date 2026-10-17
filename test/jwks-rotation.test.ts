import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type { LtiJwksConfig, LtiTool } from '../src/index.js';
import { asResourceLink } from './fixtures/launch-kind.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
let server: Server;
let jwksUri: string;
let publishedKeys: Record<string, unknown>[];
let requests = 0;
let foreignKeys: Record<string, unknown>[] = [];
let jwksUnavailable = false;
let malformedJwks: 'invalid-json' | 'invalid-keys' | null = null;
before(async () => {
  publishedKeys = [];
  server = createServer(tlsOptions, (request, response) => {
    requests++;
    if (jwksUnavailable && request.url === '/keys') {
      response.writeHead(503).end('unavailable');
      return;
    }
    if (malformedJwks && request.url === '/keys') {
      response.setHeader('content-type', 'application/json');
      response.end(malformedJwks === 'invalid-json' ? '{' : JSON.stringify({ keys: 'not-an-array' }));
      return;
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: request.url === '/foreign' ? foreignKeys : publishedKeys }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  jwksUri = `https://127.0.0.1:${address.port}/keys`;
});
after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

async function keyPair(kid: string) {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  return { privateKey, jwk: { ...await exportJWK(publicKey), kid, alg: 'RS256', use: 'sig' } };
}

function tool(uri = jwksUri, registeredIssuer = issuer, jwks: LtiJwksConfig = { cooldownMs: 0 }) {
  return createLtiTool({ jwks,
    resolver: { async resolve(requestedIssuer: string) { return requestedIssuer === registeredIssuer ? [
      { issuer: registeredIssuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
        jwksUri: uri, deployments: ['deployment-1'], allowedTargetLinkUris: [target] },
    ] : []; } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore(),
  });
}
async function launch(lti: LtiTool, key: CryptoKey, kid: string, tokenIssuer = issuer) {
  const url = new URL((await lti.initiate({ iss: tokenIssuer, login_hint: 'hint', target_link_uri: target })).url);
  const id_token = await signLaunch({ privateKey: key, kid, issuer: tokenIssuer, audience: 'client-1',
    subject: 'user-17', nonce: url.searchParams.get('nonce')!, deploymentId: 'deployment-1',
    targetLinkUri: target, resourceLinkId: 'resource-42', roles: [] });
  return lti.validate({ state: url.searchParams.get('state'), id_token });
}

test('without cooldown a registration accepts a rotated signing key immediately and reuses known keys', async () => {
  const first = await keyPair('first');
  const second = await keyPair('second');
  publishedKeys = [first.jwk];
  const lti = tool();
  const start = requests;
  assert.equal((await launch(lti, first.privateKey, 'first')).user.id, 'user-17');
  assert.equal(requests, start + 1);
  assert.equal(asResourceLink(await launch(lti, first.privateKey, 'first')).resourceLink.id, 'resource-42');
  assert.equal(requests, start + 1);

  publishedKeys = [second.jwk];
  assert.equal((await launch(lti, second.privateKey, 'second')).platform.issuer, issuer);
  assert.equal(requests, start + 2);
  assert.equal((await launch(lti, second.privateKey, 'second')).user.id, 'user-17');
  assert.equal(requests, start + 2);
});

test('a missing kid after refresh, a bad signature, and a foreign key never authenticate', async () => {
  const trusted = await keyPair('shared');
  const foreign = await keyPair('shared');
  publishedKeys = [trusted.jwk];
  foreignKeys = [foreign.jwk];
  const lti = tool();
  assert.equal((await launch(tool(jwksUri.replace('/keys', '/foreign'), 'https://foreign.example'),
    foreign.privateKey, 'shared', 'https://foreign.example')).platform.issuer, 'https://foreign.example');
  assert.equal((await launch(lti, trusted.privateKey, 'shared')).user.id, 'user-17');
  const start = requests;
  await assert.rejects(launch(lti, trusted.privateKey, 'unpublished'),
    (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR' &&
      error.message === 'JWKS_ERROR: jwks:no_matching_key');
  assert.equal(requests, start + 1);
  await assert.rejects(launch(lti, foreign.privateKey, 'shared'),
    (error: unknown) => error instanceof LtiError && error.code === 'INVALID_TOKEN' &&
      error.message === 'INVALID_TOKEN: token:signature');
});

test('a failed JWKS refresh refuses the new key even with an older key cached', async () => {
  const first = await keyPair('old');
  const rotated = await keyPair('new');
  publishedKeys = [first.jwk];
  const lti = tool();
  assert.equal((await launch(lti, first.privateKey, 'old')).user.id, 'user-17');
  publishedKeys = [rotated.jwk];
  jwksUnavailable = true;
  try {
    await assert.rejects(launch(lti, rotated.privateKey, 'new'),
      (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR' &&
        error.message === 'JWKS_ERROR: jwks:unavailable');
  } finally {
    jwksUnavailable = false;
  }
  assert.equal((await launch(lti, rotated.privateKey, 'new')).user.id, 'user-17');
});

test('malformed JWKS responses fail without caching and recover on a later fetch', async () => {
  const signing = await keyPair('recovered');
  publishedKeys = [signing.jwk];

  for (const malformed of ['invalid-json', 'invalid-keys'] as const) {
    const lti = tool();
    const start = requests;
    malformedJwks = malformed;
    try {
      await assert.rejects(launch(lti, signing.privateKey, 'recovered'),
        (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR' &&
        error.message === 'JWKS_ERROR: jwks:unavailable');
    } finally {
      malformedJwks = null;
    }

    assert.equal(requests, start + 1);
    assert.equal((await launch(lti, signing.privateKey, 'recovered')).user.id, 'user-17');
    assert.equal(requests, start + 2);
  }
});

test('the default JWKS cooldown refuses a rotated key until it elapses, without refetching', async () => {
  const first = await keyPair('before-rotation');
  const second = await keyPair('after-rotation');
  publishedKeys = [first.jwk];
  const lti = tool(jwksUri, issuer, {});
  const start = requests;
  assert.equal((await launch(lti, first.privateKey, 'before-rotation')).user.id, 'user-17');
  publishedKeys = [second.jwk];
  await assert.rejects(launch(lti, second.privateKey, 'after-rotation'),
    (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR');
  assert.equal(requests, start + 1);
});

test('a configured JWKS cooldown delays the refetch of an unknown kid', async () => {
  const first = await keyPair('cooled');
  const second = await keyPair('rotated-after-cooldown');
  publishedKeys = [first.jwk];
  const lti = tool(jwksUri, issuer, { cooldownMs: 100 });
  const start = requests;
  assert.equal((await launch(lti, first.privateKey, 'cooled')).user.id, 'user-17');
  publishedKeys = [second.jwk];
  await assert.rejects(launch(lti, second.privateKey, 'rotated-after-cooldown'),
    (error: unknown) => error instanceof LtiError && error.code === 'JWKS_ERROR');
  assert.equal(requests, start + 1);
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal((await launch(lti, second.privateKey, 'rotated-after-cooldown')).user.id, 'user-17');
  assert.equal(requests, start + 2);
});

test('a JWKS cache max age refetches known keys once elapsed', async () => {
  const signing = await keyPair('aging');
  publishedKeys = [signing.jwk];
  const lti = tool(jwksUri, issuer, { cacheMaxAgeMs: 100 });
  const start = requests;
  assert.equal((await launch(lti, signing.privateKey, 'aging')).user.id, 'user-17');
  assert.equal((await launch(lti, signing.privateKey, 'aging')).user.id, 'user-17');
  assert.equal(requests, start + 1);
  await new Promise(resolve => setTimeout(resolve, 150));
  assert.equal((await launch(lti, signing.privateKey, 'aging')).user.id, 'user-17');
  assert.equal(requests, start + 2);
});

test('the JWKS cache keeps at most 100 key sets and evicts the least recently used', async () => {
  const signing = await keyPair('bounded');
  publishedKeys = [signing.jwk];
  const issuers = Array.from({ length: 101 }, (_, index) => `https://platform-${index}.example`);
  const lti = createLtiTool({
    resolver: { async resolve(requestedIssuer: string) { return issuers.includes(requestedIssuer) ? [
      { issuer: requestedIssuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
        jwksUri: `${jwksUri}?issuer=${encodeURIComponent(requestedIssuer)}`, deployments: ['deployment-1'],
        allowedTargetLinkUris: [target] },
    ] : []; } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore(),
  });
  const start = requests;
  for (const platform of issuers.slice(0, 100)) await launch(lti, signing.privateKey, 'bounded', platform);
  assert.equal(requests, start + 100);
  await launch(lti, signing.privateKey, 'bounded', issuers[0]!);
  assert.equal(requests, start + 100);
  await launch(lti, signing.privateKey, 'bounded', issuers[100]!);
  assert.equal(requests, start + 101);
  await launch(lti, signing.privateKey, 'bounded', issuers[0]!);
  assert.equal(requests, start + 101);
  await launch(lti, signing.privateKey, 'bounded', issuers[1]!);
  assert.equal(requests, start + 102);
});
