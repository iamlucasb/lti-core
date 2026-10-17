import type { LtiContentItem, LtiDeepLinkingResponse, LtiDeepLinkingResponseOptions } from './deep-linking.js';
import { DeepLinkingResponses } from './deep-linking-responses.js';
import { LtiError } from './errors.js';
import type { DiagnosticReporter, LtiDiagnostic, LtiErrorReason } from './errors.js';
import type { LtiLaunch } from './launch-claims.js';
import { LaunchFlow } from './launch-flow.js';
import type { LaunchResponse, LoginRequest, LtiAuthorizationRedirect } from './launch-flow.js';
import { OneTimeEntries } from './one-time-store.js';
import type { OneTimeStore } from './one-time-store.js';
import { RegistrationDirectory } from './registrations.js';
import type { RegistrationResolver } from './registrations.js';
import type { TokenVerifierOptions } from './token-verifier.js';
import { ToolKeyring } from './tool-keys.js';
import type { LtiJwks, ToolKeys } from './tool-keys.js';
import { isRecord, parseHttpsUrl } from './validation.js';

export type {
  LtiDeepLinkingLaunch, LtiDocumentTarget, LtiLaunch, LtiResourceLinkLaunch, NormalizedLtiRole,
} from './launch-claims.js';
export type {
  LtiContentItem, LtiDeepLinking, LtiDeepLinkingResponse, LtiDeepLinkingResponseOptions, LtiDeepLinkingSettings,
  LtiResourceLinkContentItem,
} from './deep-linking.js';
export type { LtiJwks, LtiPrivateJwk, LtiPublicJwk, NodeKeyObjectLike, ToolKeys } from './tool-keys.js';
export { LtiError } from './errors.js';
export type { LtiDiagnostic, LtiDiagnosticCode, LtiErrorCode, LtiErrorReason } from './errors.js';
export type { Registration, RegistrationResolver } from './registrations.js';
export { MemoryOneTimeStore } from './one-time-store.js';
export type { OneTimeStore } from './one-time-store.js';
export type { LaunchResponse, LoginRequest, LtiAuthorizationRedirect } from './launch-flow.js';

const defaultDeepLinkingResponseLifetimeMs = 60 * 60_000;
const defaultClockToleranceSeconds = 5;
const defaultJwksTimeoutMs = 5_000;
const defaultJwksCooldownMs = 30_000;
const defaultJwksCacheMaxAgeMs = 10 * 60_000;

export interface LtiTool {
  /**
   * Handles an OIDC third-party initiation and stores a single-use `state` and `nonce`. Redirect the
   * browser to `url`; `state` is returned so that the application can bind it to the browser session.
   */
  initiate(login: LoginRequest): Promise<LtiAuthorizationRedirect>;
  /** Validates a resource link launch or a deep linking request; switch on `messageType`. */
  validate(response: LaunchResponse): Promise<LtiLaunch>;
  /**
   * Builds the signed LtiDeepLinkingResponse for a validated deep linking request, identified by its
   * `deepLinking.responseToken`. The token is consumed only once item shapes have been validated.
   */
  createDeepLinkingResponse(responseToken: string, items: readonly LtiContentItem[],
    options?: LtiDeepLinkingResponseOptions): Promise<LtiDeepLinkingResponse>;
  /** Public JWKS of the tool, to be served by the application. */
  jwks(): LtiJwks;
}

/** Remote JWKS fetching of platform keys, applied to every registration. */
export interface LtiJwksConfig {
  /** Timeout of a JWKS request. Positive integer, defaults to 5 000 ms. */
  readonly timeoutMs?: number;
  /**
   * Minimum delay after a JWKS fetch before a token with an unknown kid triggers a refetch. Non-negative
   * integer, defaults to 30 000 ms: a platform key rotation is refused for at most this delay after the
   * previous fetch, in exchange for bounding the JWKS requests that forged kids can cause.
   */
  readonly cooldownMs?: number;
  /** Age after which cached keys are refetched. Positive integer, defaults to 600 000 ms. */
  readonly cacheMaxAgeMs?: number;
}

export interface LtiToolConfig {
  readonly resolver: RegistrationResolver;
  /** Absolute HTTPS launch URL without fragment; a registration's `redirectUri` overrides it. */
  readonly redirectUri: string;
  /** Holds single-use launch states and deep linking response tokens; must be shared across instances. */
  readonly store: OneTimeStore;
  /** Receives normalized operational failures only. Exceptions thrown by this hook are ignored. */
  readonly onDiagnostic?: (diagnostic: LtiDiagnostic) => void;
  /** Required to answer deep linking requests and to publish the tool's JWKS. */
  readonly toolKeys?: ToolKeys;
  /** Time allowed between a deep linking request and its response. Defaults to one hour. */
  readonly deepLinkingResponseLifetimeMs?: number;
  /**
   * Allowed clock skew with platforms, in seconds, for exp, nbf and iat. Integer from 0 to 300, defaults to 5.
   * The upper bound catches a value given in milliseconds by mistake.
   */
  readonly clockToleranceSeconds?: number;
  readonly jwks?: LtiJwksConfig;
}

const maxClockToleranceSeconds = 300;
const isNonNegativeInteger = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

/** Clock tolerance and JWKS settings with defaults applied; throws INVALID_CONFIGURATION naming the invalid one. */
function verificationOptions(config: LtiToolConfig): TokenVerifierOptions {
  const setting = (value: unknown, fallback: number) => value === undefined ? fallback : value;
  const clockToleranceSeconds = setting(config.clockToleranceSeconds, defaultClockToleranceSeconds);
  if (!isNonNegativeInteger(clockToleranceSeconds) || clockToleranceSeconds > maxClockToleranceSeconds) {
    throw new LtiError('INVALID_CONFIGURATION', 'config:clockToleranceSeconds');
  }
  const jwks: unknown = config.jwks === undefined ? {} : config.jwks;
  if (!isRecord(jwks)) throw new LtiError('INVALID_CONFIGURATION', 'config:jwks');
  const jwksTimeoutMs = setting(jwks.timeoutMs, defaultJwksTimeoutMs);
  const jwksCooldownMs = setting(jwks.cooldownMs, defaultJwksCooldownMs);
  const jwksCacheMaxAgeMs = setting(jwks.cacheMaxAgeMs, defaultJwksCacheMaxAgeMs);
  if (!isNonNegativeInteger(jwksTimeoutMs) || jwksTimeoutMs === 0 ||
      !isNonNegativeInteger(jwksCooldownMs) || !isNonNegativeInteger(jwksCacheMaxAgeMs) || jwksCacheMaxAgeMs === 0) {
    throw new LtiError('INVALID_CONFIGURATION', 'config:jwks');
  }
  return { clockToleranceSeconds, jwksTimeoutMs, jwksCooldownMs, jwksCacheMaxAgeMs };
}

export function createLtiTool(config: LtiToolConfig): LtiTool {
  if (!isRecord(config)) throw new LtiError('INVALID_CONFIGURATION', 'config:invalid');
  const { resolver, redirectUri, store, onDiagnostic, toolKeys } = config;
  const deepLinkingLifetimeMs = config.deepLinkingResponseLifetimeMs ?? defaultDeepLinkingResponseLifetimeMs;
  let keyring: ToolKeyring | undefined;
  let verification: TokenVerifierOptions;
  // The check being run names the reason, also when reading a configuration value throws.
  let reason: LtiErrorReason = 'config:invalid';
  try {
    verification = verificationOptions(config);
    reason = 'config:redirectUri';
    if (!parseHttpsUrl(redirectUri) || redirectUri.includes('#')) throw new Error();
    reason = 'config:resolver';
    if (typeof resolver.resolve !== 'function') throw new Error();
    reason = 'config:store';
    if (typeof store.put !== 'function' || typeof store.take !== 'function') throw new Error();
    reason = 'config:onDiagnostic';
    if (onDiagnostic !== undefined && typeof onDiagnostic !== 'function') throw new Error();
    reason = 'config:deepLinkingResponseLifetimeMs';
    if (!Number.isSafeInteger(deepLinkingLifetimeMs) || deepLinkingLifetimeMs <= 0) throw new Error();
    reason = 'config:toolKeys';
    if (toolKeys !== undefined) keyring = new ToolKeyring(toolKeys);
  } catch (error) {
    // No cause is attached: the configuration may hold the tool's private key.
    if (error instanceof LtiError) throw error;
    throw new LtiError('INVALID_CONFIGURATION', reason);
  }

  const report: DiagnosticReporter = (code, errorCode) => {
    try {
      onDiagnostic?.({ code, errorCode });
    } catch {
      // Diagnostics must never change authentication behavior.
    }
  };
  const registrations = new RegistrationDirectory(resolver, report);
  const entries = new OneTimeEntries(store, report);
  const deepLinking = new DeepLinkingResponses(registrations, entries, keyring, deepLinkingLifetimeMs);
  const launches = new LaunchFlow(redirectUri, registrations, entries, deepLinking, report, verification);

  return {
    initiate: login => launches.initiate(login),
    validate: response => launches.validate(response),
    createDeepLinkingResponse: (responseToken, items, options) =>
      deepLinking.respond(responseToken, items, options),
    jwks() {
      if (!keyring) throw new LtiError('INVALID_CONFIGURATION', 'config:toolKeys_missing');
      return keyring.jwks();
    },
  };
}
