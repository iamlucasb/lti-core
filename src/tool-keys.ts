import { base64url, compactVerify, SignJWT } from 'jose';
import { isRecord, nonEmpty } from './validation.js';

/** RSA public key published in the tool's JWKS. */
export interface LtiPublicJwk {
  readonly kty: 'RSA';
  readonly n: string;
  readonly e: string;
  readonly kid: string;
  readonly alg?: 'RS256';
  readonly use?: 'sig';
}

export interface LtiJwks {
  readonly keys: readonly (LtiPublicJwk & { readonly alg: 'RS256'; readonly use: 'sig' })[];
}

/** Private RSA JWK (RFC 7518, section 6.3) with its CRT members; multi-prime keys are not supported. */
export interface LtiPrivateJwk {
  readonly kty: 'RSA';
  readonly n: string;
  readonly e: string;
  readonly d: string;
  readonly p: string;
  readonly q: string;
  readonly dp: string;
  readonly dq: string;
  readonly qi: string;
  readonly alg?: 'RS256';
  readonly use?: 'sig';
}

/** Node.js `KeyObject`, described structurally so that the core does not import the Node.js crypto module. */
export interface NodeKeyObjectLike {
  readonly type: string;
  readonly asymmetricKeyType?: string | undefined;
  export(options: { format: 'jwk' }): unknown;
}

export interface ToolKeys {
  /**
   * Key used to sign tool-originating messages. Provided by the application; never generated or stored.
   * The RSA private key has at least 2048 bits. A WebCrypto key (RSASSA-PKCS1-v1_5, SHA-256, `sign` usage)
   * cannot be exported synchronously, so its public JWK is supplied alongside it; a private JWK or a
   * Node.js `KeyObject` carries its public part.
   */
  readonly signing:
    | { readonly kid: string; readonly privateKey: CryptoKey; readonly publicJwk: Omit<LtiPublicJwk, 'kid'> }
    | { readonly kid: string; readonly privateKey: LtiPrivateJwk | NodeKeyObjectLike; readonly publicJwk?: never };
  /** Additional public keys published for rotation (next or previous signing key). */
  readonly publicKeys?: readonly LtiPublicJwk[];
}

type PublishedKey = LtiJwks['keys'][number];

const privateJwkMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const base64urlPattern = /^[A-Za-z0-9_-]+$/;
const minimumModulusBits = 2048;

function withoutLeadingZeros(bytes: Uint8Array): Uint8Array {
  const start = bytes.findIndex(byte => byte !== 0);
  return start === -1 ? new Uint8Array() : bytes.subarray(start);
}

/** Big-endian unsigned integer bytes of a base64url JWK member, without leading zero bytes. */
function unsignedBytes(value: string): Uint8Array {
  return withoutLeadingZeros(base64url.decode(value));
}

function modulusBits(n: string): number {
  const bytes = unsignedBytes(n);
  return bytes.length === 0 ? 0 : (bytes.length - 1) * 8 + 32 - Math.clz32(bytes[0]!);
}

/** An RSA public exponent must be odd and at least 3; e = 1 would make every signature valid. */
function isUsableExponent(e: string): boolean {
  const bytes = unsignedBytes(e);
  return bytes.length > 0 && (bytes[bytes.length - 1]! & 1) === 1 && !(bytes.length === 1 && bytes[0]! < 3);
}

function isBase64url(value: unknown): value is string {
  return nonEmpty(value) && base64urlPattern.test(value);
}

function publishedKey(jwk: unknown): PublishedKey {
  if (!isRecord(jwk) || jwk.kty !== 'RSA' || !nonEmpty(jwk.kid) || !isBase64url(jwk.n) || !isBase64url(jwk.e) ||
      jwk.alg !== undefined && jwk.alg !== 'RS256' || jwk.use !== undefined && jwk.use !== 'sig' ||
      privateJwkMembers.some(member => Object.hasOwn(jwk, member)) ||
      modulusBits(jwk.n) < minimumModulusBits || !isUsableExponent(jwk.e)) throw new Error();
  return { kty: 'RSA', n: jwk.n, e: jwk.e, kid: jwk.kid, alg: 'RS256', use: 'sig' };
}

/** Returns a copy holding only the RSA members, so later changes by the caller have no effect. */
function privateJwk(jwk: unknown): LtiPrivateJwk {
  if (!isRecord(jwk) || jwk.kty !== 'RSA' || Object.hasOwn(jwk, 'oth') ||
      jwk.alg !== undefined && jwk.alg !== 'RS256' || jwk.use !== undefined && jwk.use !== 'sig') throw new Error();
  const { n, e, d, p, q, dp, dq, qi } = jwk;
  if (!isBase64url(n) || !isBase64url(e) || !isBase64url(d) || !isBase64url(p) || !isBase64url(q) ||
      !isBase64url(dp) || !isBase64url(dq) || !isBase64url(qi)) throw new Error();
  return { kty: 'RSA', n, e, d, p, q, dp, dq, qi };
}

function isNodeKeyObject(value: unknown): value is NodeKeyObjectLike {
  return isRecord(value) && typeof value.type === 'string' && typeof value.export === 'function';
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Returns the key handed to JOSE for signing and the public JWK to publish for it. */
function signingKey(signing: Record<string, unknown>): { key: CryptoKey | LtiPrivateJwk; publicJwk: unknown } {
  const { privateKey, publicJwk } = signing;
  if (typeof CryptoKey === 'function' && privateKey instanceof CryptoKey) {
    const algorithm: unknown = privateKey.algorithm;
    if (privateKey.type !== 'private' || !privateKey.usages.includes('sign') || !isRecord(algorithm) ||
        algorithm.name !== 'RSASSA-PKCS1-v1_5' || !isRecord(algorithm.hash) || algorithm.hash.name !== 'SHA-256' ||
        !(algorithm.publicExponent instanceof Uint8Array) || !isRecord(publicJwk) ||
        publicJwk.kid !== undefined && publicJwk.kid !== signing.kid) throw new Error();
    const published = publishedKey({ ...publicJwk, kid: signing.kid });
    if (algorithm.modulusLength !== modulusBits(published.n) ||
        !sameBytes(unsignedBytes(published.e), withoutLeadingZeros(algorithm.publicExponent))) throw new Error();
    return { key: privateKey, publicJwk: published };
  }
  if (publicJwk !== undefined) throw new Error();
  let key: LtiPrivateJwk;
  if (isNodeKeyObject(privateKey)) {
    if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') throw new Error();
    key = privateJwk(privateKey.export({ format: 'jwk' }));
  } else {
    key = privateJwk(privateKey);
  }
  return { key, publicJwk: { kty: 'RSA', n: key.n, e: key.e, kid: signing.kid } };
}

/**
 * Holds the signing key in a private field: it is never enumerable, serialized or included in errors.
 * The constructor throws an Error without detail on invalid configuration.
 */
export class ToolKeyring {
  readonly #signingKey: CryptoKey | LtiPrivateJwk;
  readonly #signingPublicKey: PublishedKey;
  readonly #jwks: LtiJwks;

  constructor(config: unknown) {
    if (!isRecord(config) || !isRecord(config.signing) || !nonEmpty(config.signing.kid) ||
        config.publicKeys !== undefined && !Array.isArray(config.publicKeys)) throw new Error();
    const { key, publicJwk } = signingKey(config.signing);
    const keys = [publishedKey(publicJwk), ...(config.publicKeys ?? []).map((jwk: unknown) => publishedKey(jwk))];
    if (new Set(keys.map(published => published.kid)).size !== keys.length) throw new Error();
    this.#signingKey = key;
    this.#jwks = Object.freeze({ keys: Object.freeze(keys.map(published => Object.freeze(published))) });
    this.#signingPublicKey = this.#jwks.keys[0]!;
  }

  jwks(): LtiJwks {
    return this.#jwks;
  }

  /**
   * Each signature is verified with the published signing key before release, so a private key that
   * does not match its public JWK fails closed. Throws an Error without detail if signing fails.
   */
  async sign(claims: Record<string, unknown>): Promise<string> {
    try {
      const jwt = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: this.#signingPublicKey.kid, typ: 'JWT' })
        .sign(this.#signingKey);
      await compactVerify(jwt, this.#signingPublicKey, { algorithms: ['RS256'] });
      return jwt;
    } catch {
      throw new Error('Signing failed');
    }
  }
}
