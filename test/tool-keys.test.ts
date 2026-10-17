import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { inspect } from 'node:util';
import { test } from 'node:test';
import { base64url } from 'jose';
import { createLtiTool, LtiError, MemoryOneTimeStore } from '../src/index.js';
import type { LtiJwks, ToolKeys } from '../src/index.js';

type RsaJwk = { kty: 'RSA'; n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string };

const pkcs1 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

function rsaKey(modulusLength: number) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength });
  const privateJwk = privateKey.export({ format: 'jwk' }) as RsaJwk;
  const { kty, n, e } = privateJwk;
  return { keyObject: privateKey, publicKeyObject: publicKey, privateJwk, publicJwk: { kty, n, e } };
}

async function cryptoKey(privateJwk: RsaJwk, algorithm: Parameters<typeof webcrypto.subtle.importKey>[2] = pkcs1) {
  return webcrypto.subtle.importKey('jwk', privateJwk, algorithm, false, ['sign']);
}

function jwks(toolKeys: unknown): LtiJwks {
  return createLtiTool({
    resolver: { async resolve() { return []; } }, redirectUri: 'https://tool.example/callback',
    store: new MemoryOneTimeStore(), toolKeys: toolKeys as ToolKeys,
  }).jwks();
}

/** Prepends zero bytes to a base64url big-endian integer without changing its value. */
function withLeadingZero(value: string): string {
  const bytes = base64url.decode(value);
  const padded = new Uint8Array(bytes.length + 1);
  padded.set(bytes, 1);
  return base64url.encode(padded);
}

const key2048 = rsaKey(2048);
const key1024 = rsaKey(1024);
const key2047 = rsaKey(2047);

test('a KeyObject, a private JWK and a WebCrypto key with its public JWK publish the same JWKS', async () => {
  const fromKeyObject = jwks({ signing: { kid: 'tool', privateKey: key2048.keyObject } });
  const fromJwk = jwks({ signing: { kid: 'tool', privateKey: key2048.privateJwk } });
  const fromCryptoKey = jwks({ signing: { kid: 'tool', privateKey: await cryptoKey(key2048.privateJwk),
    publicJwk: key2048.publicJwk } });
  assert.deepEqual(fromKeyObject, {
    keys: [{ kty: 'RSA', n: key2048.publicJwk.n, e: key2048.publicJwk.e, kid: 'tool', alg: 'RS256', use: 'sig' }],
  });
  assert.deepEqual(fromJwk, fromKeyObject);
  assert.deepEqual(fromCryptoKey, fromKeyObject);
  for (const published of [fromKeyObject, fromJwk, fromCryptoKey]) {
    assert.ok(Object.isFrozen(published) && Object.isFrozen(published.keys) && Object.isFrozen(published.keys[0]));
  }
});

test('the ToolKeys type accepts each private key form', async () => {
  const forms: ToolKeys[] = [
    { signing: { kid: 'tool', privateKey: key2048.keyObject } },
    { signing: { kid: 'tool', privateKey: key2048.privateJwk } },
    { signing: { kid: 'tool', privateKey: await cryptoKey(key2048.privateJwk), publicJwk: key2048.publicJwk } },
  ];
  for (const toolKeys of forms) assert.equal(jwks(toolKeys).keys[0]!.kid, 'tool');
});

test('a private JWK is copied: later changes by the caller do not affect the published key', () => {
  const privateJwk = { ...key2048.privateJwk };
  const published = jwks({ signing: { kid: 'tool', privateKey: privateJwk } });
  privateJwk.n = key1024.privateJwk.n;
  assert.equal(published.keys[0]!.n, key2048.publicJwk.n);
});

test('the modulus length is read from n, ignoring leading zero bytes', () => {
  const rotation = { ...key2048.publicJwk, n: withLeadingZero(key2048.publicJwk.n), kid: 'next' };
  assert.equal(jwks({ signing: { kid: 'tool', privateKey: key2048.keyObject }, publicKeys: [rotation] })
    .keys[1]!.n, rotation.n);
  assert.throws(() => jwks({ signing: { kid: 'tool', privateKey: key2048.keyObject },
    publicKeys: [{ ...key1024.publicJwk, n: withLeadingZero(key1024.publicJwk.n), kid: 'next' }] }),
  { code: 'INVALID_CONFIGURATION' });
});

test('invalid tool keys are refused for every private key form without revealing the private key', async () => {
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
  const ecJwk = ec.export({ format: 'jwk' });
  const ed25519 = generateKeyPairSync('ed25519').privateKey;
  const pssKeyObject: KeyObject = generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).privateKey;
  const ecdsa = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']))
    .privateKey;
  const { publicJwk } = key2048;
  const signingCryptoKey = await cryptoKey(key2048.privateJwk);
  const sha512CryptoKey = await cryptoKey(key2048.privateJwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' });
  const pssCryptoKey = await cryptoKey(key2048.privateJwk, { name: 'RSA-PSS', hash: 'SHA-256' });
  const verifyOnlyKey = await webcrypto.subtle.importKey('jwk', publicJwk, pkcs1, true, ['verify']);
  const { qi: _qi, ...withoutQi } = key2048.privateJwk;
  for (const [name, toolKeys] of [
    ['KeyObject below 2048 bits', { signing: { kid: 'k', privateKey: key1024.keyObject } }],
    ['KeyObject of 2047 bits', { signing: { kid: 'k', privateKey: key2047.keyObject } }],
    ['private JWK below 2048 bits', { signing: { kid: 'k', privateKey: key1024.privateJwk } }],
    ['private JWK of 2047 bits', { signing: { kid: 'k', privateKey: key2047.privateJwk } }],
    ['CryptoKey below 2048 bits', { signing: { kid: 'k', privateKey: await cryptoKey(key1024.privateJwk),
      publicJwk: key1024.publicJwk } }],
    ['CryptoKey of 2047 bits', { signing: { kid: 'k', privateKey: await cryptoKey(key2047.privateJwk),
      publicJwk: key2047.publicJwk } }],
    ['CryptoKey with a smaller public JWK', { signing: { kid: 'k', privateKey: signingCryptoKey,
      publicJwk: key1024.publicJwk } }],
    ['CryptoKey with another exponent', { signing: { kid: 'k', privateKey: signingCryptoKey,
      publicJwk: { ...publicJwk, e: 'Aw' } } }],
    ['CryptoKey without public JWK', { signing: { kid: 'k', privateKey: signingCryptoKey } }],
    ['CryptoKey with a private public JWK', { signing: { kid: 'k', privateKey: signingCryptoKey,
      publicJwk: key2048.privateJwk } }],
    ['CryptoKey with another kid', { signing: { kid: 'k', privateKey: signingCryptoKey,
      publicJwk: { ...publicJwk, kid: 'other' } } }],
    ['CryptoKey for SHA-512', { signing: { kid: 'k', privateKey: sha512CryptoKey, publicJwk } }],
    ['CryptoKey for RSA-PSS', { signing: { kid: 'k', privateKey: pssCryptoKey, publicJwk } }],
    ['ECDSA CryptoKey', { signing: { kid: 'k', privateKey: ecdsa, publicJwk } }],
    ['public CryptoKey', { signing: { kid: 'k', privateKey: verifyOnlyKey, publicJwk } }],
    ['EC KeyObject', { signing: { kid: 'k', privateKey: ec } }],
    ['Ed25519 KeyObject', { signing: { kid: 'k', privateKey: ed25519 } }],
    ['RSA-PSS KeyObject', { signing: { kid: 'k', privateKey: pssKeyObject } }],
    ['public KeyObject', { signing: { kid: 'k', privateKey: key2048.publicKeyObject } }],
    ['EC private JWK', { signing: { kid: 'k', privateKey: ecJwk } }],
    ['public JWK as private key', { signing: { kid: 'k', privateKey: publicJwk } }],
    ['private JWK without qi', { signing: { kid: 'k', privateKey: withoutQi } }],
    ['multi-prime private JWK', { signing: { kid: 'k', privateKey: { ...key2048.privateJwk, oth: [] } } }],
    ['private JWK for RS512', { signing: { kid: 'k', privateKey: { ...key2048.privateJwk, alg: 'RS512' } } }],
    ['private JWK for encryption', { signing: { kid: 'k', privateKey: { ...key2048.privateJwk, use: 'enc' } } }],
    ['private JWK with a public JWK', { signing: { kid: 'k', privateKey: key2048.privateJwk, publicJwk } }],
    ['KeyObject with a public JWK', { signing: { kid: 'k', privateKey: key2048.keyObject, publicJwk } }],
  ] as const) {
    assert.throws(() => jwks(toolKeys), (error: unknown) => {
      assert.ok(error instanceof LtiError, name);
      assert.equal(error.code, 'INVALID_CONFIGURATION', name);
      assert.equal(error.cause, undefined, name);
      const rendered = `${inspect(error, { depth: 10 })} ${JSON.stringify(error)} ${String(error)}`;
      assert.equal(rendered.includes(key2048.privateJwk.d), false, name);
      return true;
    }, name);
  }
});

test('the configured private key is never enumerable or serialized', async () => {
  for (const toolKeys of [
    { signing: { kid: 'tool', privateKey: key2048.keyObject } },
    { signing: { kid: 'tool', privateKey: key2048.privateJwk } },
    { signing: { kid: 'tool', privateKey: await cryptoKey(key2048.privateJwk), publicJwk: key2048.publicJwk } },
  ]) {
    const lti = createLtiTool({
      resolver: { async resolve() { return []; } }, redirectUri: 'https://tool.example/callback',
      store: new MemoryOneTimeStore(), toolKeys: toolKeys as ToolKeys,
    });
    const rendered = inspect(lti, { depth: 10, showHidden: true }) + JSON.stringify(lti) + JSON.stringify(lti.jwks());
    assert.equal(rendered.includes(key2048.privateJwk.d), false);
  }
});

test('a published rotation key needs an odd public exponent of at least 3', () => {
  const signing = { kid: 'tool', privateKey: key2048.keyObject };
  for (const e of [base64url.encode(Uint8Array.of(1)), base64url.encode(Uint8Array.of(0, 1)),
    base64url.encode(Uint8Array.of(2)), base64url.encode(Uint8Array.of(1, 0, 0))]) {
    assert.throws(() => jwks({ signing, publicKeys: [{ ...key2048.publicJwk, e, kid: 'next' }] }),
      { code: 'INVALID_CONFIGURATION' }, e);
  }
  assert.equal(jwks({ signing, publicKeys: [{ ...key2048.publicJwk, e: base64url.encode(Uint8Array.of(3)),
    kid: 'next' }] }).keys.length, 2);
});
