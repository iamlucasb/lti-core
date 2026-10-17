import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, MemoryOneTimeStore } from '../src/index.js';
import type { LtiTool } from '../src/index.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
let jwksUri: string;
let privateKey: CryptoKey;
let server: Server;

before(async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  privateKey = keys.privateKey;
  const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'clock-key', alg: 'RS256', use: 'sig' };
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

function tool(clockToleranceSeconds?: number): LtiTool {
  return createLtiTool({
    resolver: { async resolve() { return [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
      deployments: ['deployment-1'], allowedTargetLinkUris: [target] }]; } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore(),
    ...(clockToleranceSeconds !== undefined && { clockToleranceSeconds }),
  });
}

async function launch(lti: LtiTool, changes: Record<string, unknown>) {
  const { url, state } = await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target });
  const id_token = await signLaunch({ privateKey, kid: 'clock-key', issuer, audience: 'client-1',
    subject: 'user-17', nonce: new URL(url).searchParams.get('nonce')!, deploymentId: 'deployment-1',
    targetLinkUri: target, resourceLinkId: 'resource-42', roles: [], changes });
  return lti.validate({ state, id_token });
}

const now = () => Math.floor(Date.now() / 1000);

test('the default clock tolerance accepts a few seconds of skew on iat, nbf and exp', async () => {
  const lti = tool();
  assert.equal((await launch(lti, { iat: now() + 3 })).user.id, 'user-17');
  assert.equal((await launch(lti, { nbf: now() + 3 })).user.id, 'user-17');
  assert.equal((await launch(lti, { exp: now() - 3 })).user.id, 'user-17');
});

test('the default clock tolerance refuses skew beyond five seconds', async () => {
  const lti = tool();
  await assert.rejects(launch(lti, { iat: now() + 30 }), { code: 'INVALID_TOKEN' });
  await assert.rejects(launch(lti, { nbf: now() + 30 }), { code: 'INVALID_TOKEN' });
  await assert.rejects(launch(lti, { exp: now() - 30 }), { code: 'TOKEN_EXPIRED' });
});

test('a configured clock tolerance widens or removes the accepted skew', async () => {
  const lenient = tool(60);
  assert.equal((await launch(lenient, { iat: now() + 30 })).user.id, 'user-17');
  assert.equal((await launch(lenient, { exp: now() - 30 })).user.id, 'user-17');
  await assert.rejects(launch(lenient, { iat: now() + 120 }), { code: 'INVALID_TOKEN' });
  await assert.rejects(launch(lenient, { exp: now() - 120 }), { code: 'TOKEN_EXPIRED' });

  const strict = tool(0);
  await assert.rejects(launch(strict, { iat: now() + 3 }), { code: 'INVALID_TOKEN' });
  await assert.rejects(launch(strict, { nbf: now() + 3 }), { code: 'INVALID_TOKEN' });
  await assert.rejects(launch(strict, { exp: now() - 3 }), { code: 'TOKEN_EXPIRED' });
});
