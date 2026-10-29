import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { inspectPlatformJwks, LtiError } from '../src/index.js';
import type { PlatformJwksInspectionOptions } from '../src/index.js';
import { createTestPlatform } from '../src/testing.js';

const jwksUri = 'https://platform.example/jwks';

function rsaPublicJwk(modulusLength = 2048): Record<string, unknown> {
  return generateKeyPairSync('rsa', { modulusLength }).publicKey.export({ format: 'jwk' });
}

interface SeenRequest {
  url: string;
  method: string | undefined;
  redirect: string | undefined;
}

function fakeFetch(answer: () => Response | Promise<Response>) {
  const requests: SeenRequest[] = [];
  const fetch: NonNullable<PlatformJwksInspectionOptions['fetch']> = async (url, init) => {
    requests.push({ url, method: init.method, redirect: init.redirect });
    return answer();
  };
  return { fetch, requests };
}

test('summarizes a JWKS with the key selection rules of launch validation', async () => {
  const usable = { ...rsaPublicJwk(), kid: 'usable', alg: 'RS256', use: 'sig' };
  const privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'jwk' });
  const keys = [
    usable,
    { ...rsaPublicJwk(), kid: 'no-alg' },
    { ...rsaPublicJwk(), kid: 'verify-op', key_ops: ['verify'] },
    { ...rsaPublicJwk() },
    { ...rsaPublicJwk(), kid: 'rs512', alg: 'RS512' },
    { ...rsaPublicJwk(), kid: 'encryption', use: 'enc' },
    { ...rsaPublicJwk(), kid: 'sign-op', key_ops: ['sign'] },
    { ...rsaPublicJwk(1024), kid: 'short' },
    { ...privateKey, kid: 'private' },
    { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', kid: 'ec' },
    { kty: 'RSA', n: 'not-a-key', e: 'AQAB', kid: 'broken' },
  ];
  const network = fakeFetch(() => Response.json({ keys }));
  assert.deepEqual(await inspectPlatformJwks(jwksUri, { fetch: network.fetch }), {
    fetched: true, keyCount: 11,
    kids: ['usable', 'no-alg', 'verify-op', 'rs512', 'encryption', 'sign-op', 'short', 'private', 'ec', 'broken'],
    usableKids: ['usable', 'no-alg', 'verify-op'],
    exposesPrivateKeyMembers: true,
  });
  assert.deepEqual(network.requests, [{ url: jwksUri, method: 'GET', redirect: 'manual' }]);
});

test('reports a JWKS without a usable key and without private members', async () => {
  const network = fakeFetch(() => Response.json({ keys: [] }));
  assert.deepEqual(await inspectPlatformJwks(jwksUri, { fetch: network.fetch }),
    { fetched: true, keyCount: 0, kids: [], usableKids: [], exposesPrivateKeyMembers: false });
});

test('agrees with the test platform key accepted by launch validation', async () => {
  const platform = await createTestPlatform({ targetLinkUri: 'https://tool.example/launch' });
  const fetch = async (url: string) => platform.respond(url) ?? new Response(null, { status: 404 });
  const inspection = await inspectPlatformJwks(platform.jwksUri, { fetch });
  assert.equal(inspection.fetched, true);
  assert.deepEqual(inspection.fetched && inspection.usableKids, [platform.jwks.keys[0]!.kid]);
});

test('names the problem when the JWKS cannot be read, without following redirects', async () => {
  const scenarios: { answer: () => Response | Promise<Response>; expected: unknown }[] = [
    { answer: () => new Response(null, { status: 302, headers: { location: 'https://elsewhere.example/jwks' } }),
      expected: { fetched: false, problem: 'http_status', httpStatus: 302 } },
    { answer: () => new Response('down', { status: 503 }),
      expected: { fetched: false, problem: 'http_status', httpStatus: 503 } },
    { answer: () => new Response('<html>'), expected: { fetched: false, problem: 'invalid_json' } },
    { answer: () => Response.json({ nokeys: true }), expected: { fetched: false, problem: 'invalid_jwks' } },
    { answer: () => Response.json({ keys: ['not-a-key'] }), expected: { fetched: false, problem: 'invalid_jwks' } },
    { answer: () => Promise.reject(new TypeError('fetch failed')), expected: { fetched: false, problem: 'unreachable' } },
  ];
  for (const { answer, expected } of scenarios) {
    const network = fakeFetch(answer);
    assert.deepEqual(await inspectPlatformJwks(jwksUri, { fetch: network.fetch }), expected);
    assert.equal(network.requests.length, 1);
  }
});

test('reports a timeout', async () => {
  const fetch: NonNullable<PlatformJwksInspectionOptions['fetch']> = (_url, init) => new Promise((_, reject) => {
    init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
  });
  // A real request keeps the event loop alive with its socket; this one has none, and the timeout timer
  // does not hold the loop on Node 20 and 22.
  const keepAlive = setInterval(() => undefined, 1_000);
  try {
    assert.deepEqual(await inspectPlatformJwks(jwksUri, { fetch, timeoutMs: 20 }), { fetched: false, problem: 'timeout' });
  } finally {
    clearInterval(keepAlive);
  }
});

test('sends no request for a URI that is not an absolute HTTPS URL', async () => {
  for (const uri of ['http://platform.example/jwks', 'platform.example/jwks', '']) {
    const network = fakeFetch(() => Response.json({ keys: [] }));
    assert.deepEqual(await inspectPlatformJwks(uri, { fetch: network.fetch }), { fetched: false, problem: 'invalid_uri' });
    assert.deepEqual(network.requests, []);
  }
});

test('refuses invalid options with INVALID_CONFIGURATION', async () => {
  const invalid: unknown[] = [{ timeoutMs: 0 }, { timeoutMs: 1.5 }, { timeoutMs: '5000' }, { fetch: 'fetch' }];
  for (const options of invalid) {
    await assert.rejects(inspectPlatformJwks(jwksUri, options as PlatformJwksInspectionOptions),
      (error: unknown) => error instanceof LtiError && error.code === 'INVALID_CONFIGURATION' &&
        error.reason === 'config:jwks');
  }
});
