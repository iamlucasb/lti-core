import { createLocalJWKSet, createRemoteJWKSet, customFetch, errors } from 'jose';
import type { FetchImplementation, JSONWebKeySet } from 'jose';
import { LtiError } from './errors.js';
import { defaultJwksTimeoutMs } from './token-verifier.js';
import { isRecord, nonEmpty, parseHttpsUrl } from './validation.js';

/**
 * Why a platform JWKS could not be read: `invalid_uri` (not an absolute HTTPS URL, no request sent),
 * `timeout`, `unreachable` (network error), `http_status` (any status but 200, redirects included: they are
 * not followed), `invalid_json` or `invalid_jwks` (not an object with a `keys` array of objects).
 */
export type PlatformJwksProblem =
  'invalid_uri' | 'timeout' | 'unreachable' | 'http_status' | 'invalid_json' | 'invalid_jwks';

/** Key counts and key IDs of a platform JWKS; never key material. */
export interface PlatformJwksSummary {
  readonly fetched: true;
  readonly keyCount: number;
  /** `kid` of every key that has one, in JWKS order. */
  readonly kids: readonly string[];
  /** `kid` of the keys that can verify an RS256 ID token, with the rules applied by launch validation. */
  readonly usableKids: readonly string[];
  /** A key publishes a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`). */
  readonly exposesPrivateKeyMembers: boolean;
}

export interface PlatformJwksFailure {
  readonly fetched: false;
  readonly problem: PlatformJwksProblem;
  /** Received HTTP status, for `http_status`. */
  readonly httpStatus?: number;
}

export type PlatformJwksInspection = PlatformJwksSummary | PlatformJwksFailure;

export interface PlatformJwksInspectionOptions {
  /** Timeout of the request. Positive integer, defaults to 5 000 ms like the tool's `jwks.timeoutMs`. */
  readonly timeoutMs?: number;
  /** `fetch` implementation. Defaults to `globalThis.fetch`. */
  readonly fetch?: (url: string, init: RequestInit) => Promise<Response>;
}

const privateJwkMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
const minimumModulusBits = 2048;

/**
 * Same selection and import as launch validation: a key the token's `kid` (required) and RS256 can select,
 * importable as a public key of at least 2048 bits.
 */
async function isUsableKey(jwk: Record<string, unknown>): Promise<boolean> {
  if (!nonEmpty(jwk.kid)) return false;
  try {
    const key = await createLocalJWKSet({ keys: [jwk] })({ alg: 'RS256', kid: jwk.kid });
    const algorithm: unknown = key.algorithm;
    return isRecord(algorithm) && typeof algorithm.modulusLength === 'number' &&
      algorithm.modulusLength >= minimumModulusBits;
  } catch {
    return false;
  }
}

async function summary(jwks: JSONWebKeySet): Promise<PlatformJwksSummary> {
  const keys: Record<string, unknown>[] = jwks.keys.filter(isRecord);
  const usable = await Promise.all(keys.map(isUsableKey));
  return {
    fetched: true,
    keyCount: keys.length,
    kids: keys.flatMap(key => nonEmpty(key.kid) ? [key.kid] : []),
    usableKids: keys.flatMap((key, index) => usable[index] && nonEmpty(key.kid) ? [key.kid] : []),
    exposesPrivateKeyMembers: keys.some(key => privateJwkMembers.some(member => Object.hasOwn(key, member))),
  };
}

/**
 * Fetches a platform JWKS the way launch validation does (one GET, redirects not followed, HTTP 200 only,
 * same timeout) and summarizes it, for example to check a registration before a first launch. Never throws
 * for a platform problem: the result names it. Throws INVALID_CONFIGURATION (`config:jwks`) for invalid options.
 */
export async function inspectPlatformJwks(jwksUri: string,
  options: PlatformJwksInspectionOptions = {}): Promise<PlatformJwksInspection> {
  const timeoutMs = options.timeoutMs ?? defaultJwksTimeoutMs;
  const fetchImplementation = options.fetch ?? globalThis.fetch;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || typeof fetchImplementation !== 'function') {
    throw new LtiError('INVALID_CONFIGURATION', 'config:jwks');
  }
  const url = parseHttpsUrl(jwksUri);
  if (!url) return { fetched: false, problem: 'invalid_uri' };

  let httpStatus: number | undefined;
  const recordingFetch: FetchImplementation = async (input, init) => {
    const response = await fetchImplementation(input, init);
    httpStatus = response.status;
    return response;
  };
  const remote = createRemoteJWKSet(url, { timeoutDuration: timeoutMs, [customFetch]: recordingFetch });
  try {
    await remote.reload();
  } catch (error) {
    if (error instanceof errors.JWKSTimeout) return { fetched: false, problem: 'timeout' };
    if (httpStatus === undefined) return { fetched: false, problem: 'unreachable' };
    if (httpStatus !== 200) return { fetched: false, problem: 'http_status', httpStatus };
    return { fetched: false, problem: error instanceof errors.JWKSInvalid ? 'invalid_jwks' : 'invalid_json' };
  }
  const jwks = remote.jwks();
  if (!jwks) return { fetched: false, problem: 'invalid_jwks' };
  return summary(jwks);
}
