import { createRemoteJWKSet, errors, jwtVerify } from 'jose';
import type { JWTVerifyResult, JWTPayload, RemoteJWKSet } from 'jose';
import { LtiError } from './errors.js';

interface VerificationRegistration {
  readonly issuer: string;
  readonly clientId: string;
  readonly jwksUri: string;
}

/** Default timeout of a platform JWKS request, in milliseconds. */
export const defaultJwksTimeoutMs = 5_000;

/** Validated verification settings; defaults are applied by createLtiTool. */
export interface TokenVerifierOptions {
  /** Allowed clock skew, in seconds, for exp, nbf and iat. */
  readonly clockToleranceSeconds: number;
  /** Abort a JWKS request after this delay. */
  readonly jwksTimeoutMs: number;
  /**
   * Minimum delay after a JWKS fetch before a token with an unknown kid triggers a refetch. During this
   * window a freshly rotated key is refused with JWKS_ERROR; afterwards the first launch signed with it
   * refetches the JWKS and succeeds. The cooldown bounds the requests a forged kid can send to the platform.
   */
  readonly jwksCooldownMs: number;
  /** Age after which cached keys are refetched before verification, even when the kid is known. */
  readonly jwksCacheMaxAgeMs: number;
}

/** Translates a JOSE or network error into an LtiError with its reason, without attaching it as a cause. */
function translatedError(error: unknown): LtiError {
  if (error instanceof errors.JWTExpired) return new LtiError('TOKEN_EXPIRED', 'token:exp');
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'iss') return new LtiError('INVALID_ISSUER', 'token:iss');
    if (error.claim === 'aud') return new LtiError('INVALID_AUDIENCE', 'token:aud');
    if (error.claim === 'sub') return new LtiError('INVALID_CLAIMS', 'claim:sub');
    if (error.claim === 'nonce') return new LtiError('INVALID_NONCE', 'token:nonce');
  }
  if (error instanceof errors.JWKSNoMatchingKey) return new LtiError('JWKS_ERROR', 'jwks:no_matching_key');
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid ||
      error instanceof errors.JOSEError && error.constructor === errors.JOSEError ||
      !(error instanceof errors.JOSEError)) return new LtiError('JWKS_ERROR', 'jwks:unavailable');
  if (error instanceof errors.JWSSignatureVerificationFailed) return new LtiError('INVALID_TOKEN', 'token:signature');
  if (error instanceof errors.JOSEAlgNotAllowed) return new LtiError('INVALID_TOKEN', 'token:alg');
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'exp') return new LtiError('INVALID_TOKEN', 'token:exp');
    if (error.claim === 'iat') return new LtiError('INVALID_TOKEN', 'token:iat');
    if (error.claim === 'nbf') return new LtiError('INVALID_TOKEN', 'token:nbf');
  }
  return new LtiError('INVALID_TOKEN', 'token:malformed');
}

/** Bound on cached remote key sets; at most one per registration and JWKS URI. */
const maxCachedJwksSets = 100;

/**
 * Verifies platform ID tokens against the registration's remote JWKS.
 *
 * Key set cache: an entry is created on the first verification for an issuer, client ID and JWKS URI,
 * and moved to the most recent position on each use. When more than 100 entries exist, the least
 * recently used one is evicted; its keys are simply fetched again on its next use. Lookups and
 * insertions are synchronous, so concurrent verifications share one entry. The cache is per process
 * and per LtiTool instance: each instance fetches the JWKS independently.
 */
export class TokenVerifier {
  private readonly jwksSets = new Map<string, RemoteJWKSet>();

  constructor(private readonly options: TokenVerifierOptions) {}

  async verify(token: string, registration: VerificationRegistration): Promise<JWTVerifyResult<JWTPayload>> {
    const jwks = this.jwksFor(registration);
    try {
      return await jwtVerify(token, jwks, {
        issuer: registration.issuer,
        audience: registration.clientId,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub', 'nonce'],
        clockTolerance: this.options.clockToleranceSeconds,
      });
    } catch (error) {
      throw translatedError(error);
    }
  }

  private jwksFor(registration: VerificationRegistration): RemoteJWKSet {
    const cacheKey = JSON.stringify([registration.issuer, registration.clientId, registration.jwksUri]);
    let jwks = this.jwksSets.get(cacheKey);
    if (jwks) {
      this.jwksSets.delete(cacheKey);
    } else {
      jwks = createRemoteJWKSet(new URL(registration.jwksUri), {
        timeoutDuration: this.options.jwksTimeoutMs,
        cooldownDuration: this.options.jwksCooldownMs,
        cacheMaxAge: this.options.jwksCacheMaxAgeMs,
      });
    }
    this.jwksSets.set(cacheKey, jwks);
    if (this.jwksSets.size > maxCachedJwksSets) {
      const oldest = this.jwksSets.keys().next();
      if (!oldest.done) this.jwksSets.delete(oldest.value);
    }
    return jwks;
  }
}
