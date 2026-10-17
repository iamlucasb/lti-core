import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createLtiTool, MemoryOneTimeStore } from '../src/index.js';
import type { LtiToolConfig, Registration } from '../src/index.js';

const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
const redirectUri = 'https://tool.example/callback';
const login = { iss: issuer, login_hint: 'hint', target_link_uri: target };

function registration(changes: Partial<Registration> = {}): Registration {
  return { issuer, clientId: 'client-1', authorizationEndpoint: 'https://platform.example/authorize',
    jwksUri: 'https://platform.example/jwks', deployments: ['deployment-1'], allowedTargetLinkUris: [target],
    ...changes };
}

function config(changes: Record<string, unknown> = {}, registrations = [registration()]): LtiToolConfig {
  return { resolver: { async resolve() { return registrations; } }, redirectUri, store: new MemoryOneTimeStore(),
    ...changes };
}

test('clock tolerance and JWKS settings accept bounded integers and omitted values', () => {
  for (const changes of [
    {}, { clockToleranceSeconds: 0 }, { clockToleranceSeconds: 60 }, { clockToleranceSeconds: 300 },
    { jwks: {} }, { jwks: { timeoutMs: 1, cooldownMs: 0, cacheMaxAgeMs: 1 } },
    { jwks: { timeoutMs: 2_000, cooldownMs: 10_000, cacheMaxAgeMs: 60_000 } },
  ]) assert.doesNotThrow(() => createLtiTool(config(changes)));
});

test('invalid clock tolerance or JWKS settings are rejected when creating the tool', () => {
  for (const changes of [
    { clockToleranceSeconds: -1 }, { clockToleranceSeconds: 1.5 }, { clockToleranceSeconds: Number.NaN },
    { clockToleranceSeconds: Number.POSITIVE_INFINITY }, { clockToleranceSeconds: '5' },
    { clockToleranceSeconds: null }, { clockToleranceSeconds: 301 }, { clockToleranceSeconds: 5_000 },
    { jwks: null }, { jwks: 'fast' }, { jwks: [] },
    { jwks: { timeoutMs: 0 } }, { jwks: { timeoutMs: -1 } }, { jwks: { timeoutMs: 1.5 } },
    { jwks: { timeoutMs: '5000' } },
    { jwks: { cooldownMs: -1 } }, { jwks: { cooldownMs: Number.NaN } }, { jwks: { cooldownMs: '0' } },
    { jwks: { cacheMaxAgeMs: -1 } }, { jwks: { cacheMaxAgeMs: Number.POSITIVE_INFINITY } },
    { jwks: { cacheMaxAgeMs: null } }, { jwks: { cacheMaxAgeMs: 0 } },
  ]) {
    const reason = 'clockToleranceSeconds' in changes ? 'config:clockToleranceSeconds' : 'config:jwks';
    assert.throws(() => createLtiTool(config(changes)),
      { code: 'INVALID_CONFIGURATION', reason, message: `INVALID_CONFIGURATION: ${reason}` }, JSON.stringify(changes));
  }
});

test('initiate returns the authorization URL and the state it carries', async () => {
  const lti = createLtiTool(config());
  const redirect = await lti.initiate(login);
  const url = new URL(redirect.url);
  assert.deepEqual(Object.keys(redirect).sort(), ['state', 'url']);
  assert.equal(url.origin + url.pathname, 'https://platform.example/authorize');
  assert.ok(redirect.state.length >= 43);
  assert.equal(url.searchParams.get('state'), redirect.state);
  assert.notEqual(url.searchParams.get('nonce'), redirect.state);
  assert.notEqual((await lti.initiate(login)).state, redirect.state);
});

test('a registration redirect URI overrides the tool redirect URI in the authorization request', async () => {
  const override = 'https://tool.example/platform-a/callback?tenant=a';
  const overridden = createLtiTool(config({}, [registration({ redirectUri: override })]));
  assert.equal(new URL((await overridden.initiate(login)).url).searchParams.get('redirect_uri'), override);
  const inherited = createLtiTool(config());
  assert.equal(new URL((await inherited.initiate(login)).url).searchParams.get('redirect_uri'), redirectUri);
});

test('an invalid registration redirect URI fails closed as invalid configuration', async () => {
  for (const invalid of ['http://tool.example/callback', 'https://tool.example/callback#fragment',
    'https:tool.example/callback', '/callback', '', 42, null]) {
    const lti = createLtiTool(config({}, [{ ...registration(), redirectUri: invalid } as never]));
    await assert.rejects(lti.initiate(login),
      { code: 'INVALID_CONFIGURATION', message: 'INVALID_CONFIGURATION: registration:invalid' },
      String(invalid));
  }
});
