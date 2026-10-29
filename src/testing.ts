import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import type { LtiDeepLinkingResponse } from './deep-linking.js';
import { randomToken } from './random.js';
import type { Registration } from './registrations.js';
import type { LtiJwks, LtiPublicJwk } from './tool-keys.js';
import { isRecord, parseHttpsUrl } from './validation.js';

/**
 * Fake LTI 1.3 platform for tests: it plays the platform side of the OIDC launch and of Deep Linking 2.0
 * with a throwaway RS256 key, serves its JWKS through a `fetch` stub and reads the tool's Deep Linking
 * responses as a platform would. Nothing leaves the process. Test use only: it is not a platform implementation.
 */

const ltiClaim = 'https://purl.imsglobal.org/spec/lti/claim/';
const dlClaim = 'https://purl.imsglobal.org/spec/lti-dl/claim/';
const learnerRole = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
const instructorRole = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor';
const idTokenLifetimeSeconds = 300;

export interface TestPlatformOptions {
  /** Tool launch URL registered with the platform: `target_link_uri` of logins and launches. */
  readonly targetLinkUri: string;
  /** Redirect URI registered for the tool. Defaults to `targetLinkUri`. */
  readonly redirectUri?: string;
  /** Defaults to `https://platform.test`. */
  readonly issuer?: string;
  /** Defaults to `test-client`. */
  readonly clientId?: string;
  /**
   * `deployment_id` claim and `lti_deployment_id` login parameter. Defaults to `test-deployment`. `null` plays a
   * platform that omits them (see ADR 0002): `registration()` then declares `deploymentIdRequired: false`.
   */
  readonly deploymentId?: string | null;
  /** Defaults to `<issuer>/authorize`. */
  readonly authorizationEndpoint?: string;
  /** Defaults to `<issuer>/jwks`. */
  readonly jwksUri?: string;
  /** `deep_link_return_url` of deep linking requests. Defaults to `<issuer>/deep-linking/return`. */
  readonly deepLinkReturnUrl?: string;
  /**
   * Roles sent when a launch gives none, per message type. Default: Learner in a resource link launch and
   * Instructor in a deep linking request, as platforms that only grant Instructor in deep linking do.
   */
  readonly roles?: {
    readonly resourceLink?: readonly string[];
    readonly deepLinking?: readonly string[];
  };
}

/** Fields of the OIDC third-party initiation the platform sends to the tool's login URL. */
export interface TestLoginRequest {
  readonly iss: string;
  readonly login_hint: string;
  readonly target_link_uri: string;
  readonly client_id: string;
  readonly lti_deployment_id?: string;
  readonly lti_message_hint?: string;
}

export interface TestLoginOptions {
  /** Defaults to the platform's `targetLinkUri`. */
  readonly targetLinkUri?: string;
  /** Defaults to `test-login-hint`. */
  readonly loginHint?: string;
  readonly messageHint?: string;
}

/** Settings of a deep linking request; absent optional settings are not sent. */
export interface TestDeepLinkingSettings {
  /** Defaults to `['ltiResourceLink']`. */
  readonly acceptTypes?: readonly string[];
  /** Defaults to `['iframe', 'window']`. */
  readonly acceptPresentationDocumentTargets?: readonly string[];
  readonly acceptMultiple?: boolean;
  readonly data?: string;
}

export interface TestLaunch {
  /** Defaults to `LtiResourceLinkRequest`. */
  readonly messageType?: 'LtiResourceLinkRequest' | 'LtiDeepLinkingRequest';
  /** `sub` claim. Defaults to `test-user`. */
  readonly subject?: string;
  /** Defaults to the platform roles for the message type. */
  readonly roles?: readonly string[];
  /** `resource_link.id` of a resource link launch. Defaults to `test-resource-link`. */
  readonly resourceLinkId?: string;
  /** Settings of a deep linking request. */
  readonly deepLinking?: TestDeepLinkingSettings;
  /**
   * Raw claims merged last, to add claims (`context`, `custom`, `name`...) or forge invalid tokens. A claim set
   * to `undefined` is removed from the token.
   */
  readonly claims?: Readonly<Record<string, unknown>>;
}

/** The form the platform posts to the tool's redirect URI. */
export interface TestLaunchForm {
  readonly state: string;
  readonly id_token: string;
}

/** What the platform reads from a verified Deep Linking response. */
export interface TestDeepLinkingResponseContent {
  /** `kid` of the tool key that signed the response. */
  readonly kid: string;
  /** Verified payload. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** `content_items` claim; empty when the response has none. */
  readonly contentItems: readonly Readonly<Record<string, unknown>>[];
}

export interface TestPlatform {
  readonly issuer: string;
  readonly clientId: string;
  /** Undefined when the platform omits `deployment_id`. */
  readonly deploymentId: string | undefined;
  readonly authorizationEndpoint: string;
  readonly jwksUri: string;
  readonly deepLinkReturnUrl: string;
  readonly targetLinkUri: string;
  readonly redirectUri: string;
  /** Public JWKS of the platform, as served at `jwksUri`. */
  readonly jwks: { readonly keys: readonly LtiPublicJwk[] };
  /** Registration of this platform for the tool's resolver; `overrides` replace its fields. */
  registration(overrides?: Partial<Registration>): Registration;
  /** OIDC third-party initiation to pass to `initiate`. */
  loginRequest(options?: TestLoginOptions): TestLoginRequest;
  /** Answers a request to `jwksUri` with the JWKS; `undefined` for any other URL. */
  respond(url: string): Response | undefined;
  /**
   * Replaces `globalThis.fetch` so that `jwksUri` is served locally; other URLs go to the previous `fetch`.
   * Returns the restore function. Restore in reverse order of installation.
   */
  installFetch(): () => void;
  /**
   * Platform side of the OIDC authentication request: checks the tool's authorization URL (endpoint, client ID,
   * redirect URI, OIDC parameters), then signs an ID token with the received nonce. Throws an `Error` otherwise.
   */
  authorize(authorizationUrl: string, launch?: TestLaunch): Promise<TestLaunchForm>;
  /**
   * Platform side of a Deep Linking response: checks the return URL, the RS256 signature against the tool JWKS,
   * `iss`, `aud`, `exp`, `iat`, `nonce`, version, message type and `deployment_id`. Throws an `Error` otherwise.
   */
  readDeepLinkingResponse(response: LtiDeepLinkingResponse, toolJwks: LtiJwks): Promise<TestDeepLinkingResponseContent>;
}

function httpsUrl(value: string, option: string): string {
  if (!parseHttpsUrl(value)) throw new TypeError(`Test platform: ${option} must be an absolute HTTPS URL`);
  return value;
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

function fail(check: string): never {
  throw new Error(`Test platform: ${check}`);
}

/** Checks the OIDC authentication request (LTI 1.3 Security Framework, section 5.1.1.2); returns its parameters. */
function authorizationParameters(authorizationUrl: string, expected: {
  endpoint: string; clientId: string; redirectUri: string;
}): { state: string; nonce: string } {
  const url = new URL(authorizationUrl);
  const param = (name: string) => url.searchParams.get(name) ?? fail(`authorization request without ${name}`);
  if (url.origin + url.pathname !== expected.endpoint) fail('wrong authorization endpoint');
  if (param('scope') !== 'openid') fail('scope is not openid');
  if (param('response_type') !== 'id_token') fail('response_type is not id_token');
  if (param('response_mode') !== 'form_post') fail('response_mode is not form_post');
  if (param('prompt') !== 'none') fail('prompt is not none');
  if (param('client_id') !== expected.clientId) fail('unknown client_id');
  if (param('redirect_uri') !== expected.redirectUri) fail('unregistered redirect_uri');
  param('login_hint');
  return { state: param('state'), nonce: param('nonce') };
}

export async function createTestPlatform(options: TestPlatformOptions): Promise<TestPlatform> {
  const issuer = httpsUrl(options.issuer ?? 'https://platform.test', 'issuer');
  const clientId = options.clientId ?? 'test-client';
  const deploymentId = options.deploymentId === null ? undefined : options.deploymentId ?? 'test-deployment';
  const authorizationEndpoint = httpsUrl(options.authorizationEndpoint ?? `${issuer}/authorize`,
    'authorizationEndpoint');
  const jwksUri = httpsUrl(options.jwksUri ?? `${issuer}/jwks`, 'jwksUri');
  const deepLinkReturnUrl = httpsUrl(options.deepLinkReturnUrl ?? `${issuer}/deep-linking/return`,
    'deepLinkReturnUrl');
  const targetLinkUri = httpsUrl(options.targetLinkUri, 'targetLinkUri');
  const redirectUri = httpsUrl(options.redirectUri ?? targetLinkUri, 'redirectUri');
  const resourceLinkRoles = options.roles?.resourceLink ?? [learnerRole];
  const deepLinkingRoles = options.roles?.deepLinking ?? [instructorRole];

  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const kid = `test-platform-${randomToken(9)}`;
  const { n, e } = await exportJWK(publicKey);
  if (n === undefined || e === undefined) fail('key generation failed');
  const jwks = Object.freeze({ keys: Object.freeze([Object.freeze(
    { kty: 'RSA' as const, n, e, kid, alg: 'RS256' as const, use: 'sig' as const })]) });

  const respond = (url: string) => url === jwksUri ? Response.json(jwks) : undefined;

  function messageClaims(launch: TestLaunch): Record<string, unknown> {
    if (launch.messageType === 'LtiDeepLinkingRequest') {
      const settings = launch.deepLinking ?? {};
      return {
        [ltiClaim + 'message_type']: 'LtiDeepLinkingRequest',
        [ltiClaim + 'roles']: launch.roles ?? deepLinkingRoles,
        [dlClaim + 'deep_linking_settings']: {
          deep_link_return_url: deepLinkReturnUrl,
          accept_types: settings.acceptTypes ?? ['ltiResourceLink'],
          accept_presentation_document_targets: settings.acceptPresentationDocumentTargets ?? ['iframe', 'window'],
          ...(settings.acceptMultiple !== undefined && { accept_multiple: settings.acceptMultiple }),
          ...(settings.data !== undefined && { data: settings.data }),
        },
      };
    }
    return {
      [ltiClaim + 'message_type']: 'LtiResourceLinkRequest',
      [ltiClaim + 'roles']: launch.roles ?? resourceLinkRoles,
      [ltiClaim + 'resource_link']: { id: launch.resourceLinkId ?? 'test-resource-link' },
    };
  }

  return {
    issuer, clientId, deploymentId, authorizationEndpoint, jwksUri, deepLinkReturnUrl, targetLinkUri, redirectUri,
    jwks,
    registration(overrides = {}) {
      return {
        issuer, clientId, authorizationEndpoint, jwksUri,
        deployments: deploymentId === undefined ? [] : [deploymentId],
        allowedTargetLinkUris: [targetLinkUri],
        ...(deploymentId === undefined && { deploymentIdRequired: false }),
        ...overrides,
      };
    },
    loginRequest(login = {}) {
      return {
        iss: issuer, client_id: clientId,
        login_hint: login.loginHint ?? 'test-login-hint',
        target_link_uri: login.targetLinkUri ?? targetLinkUri,
        ...(deploymentId !== undefined && { lti_deployment_id: deploymentId }),
        ...(login.messageHint !== undefined && { lti_message_hint: login.messageHint }),
      };
    },
    respond,
    installFetch() {
      const previous = globalThis.fetch;
      globalThis.fetch = Object.assign(
        async (input: string | URL | Request, init?: RequestInit) => respond(requestUrl(input)) ?? previous(input, init),
        previous,
      );
      return () => {
        globalThis.fetch = previous;
      };
    },
    async authorize(authorizationUrl, launch = {}) {
      const { state, nonce } = authorizationParameters(authorizationUrl,
        { endpoint: authorizationEndpoint, clientId, redirectUri });
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({
        iss: issuer, aud: clientId, sub: launch.subject ?? 'test-user', iat: now,
        exp: now + idTokenLifetimeSeconds, nonce,
        [ltiClaim + 'version']: '1.3.0',
        ...(deploymentId !== undefined && { [ltiClaim + 'deployment_id']: deploymentId }),
        [ltiClaim + 'target_link_uri']: targetLinkUri,
        ...messageClaims(launch),
        ...launch.claims,
      }).setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' }).sign(privateKey);
      return { state, id_token: idToken };
    },
    async readDeepLinkingResponse(response, toolJwks) {
      if (response.returnUrl !== deepLinkReturnUrl) fail('wrong Deep Linking return URL');
      let verified;
      try {
        verified = await jwtVerify(response.jwt, createLocalJWKSet({ keys: [...toolJwks.keys] }), {
          algorithms: ['RS256'], issuer: clientId, audience: issuer, requiredClaims: ['exp', 'iat', 'nonce'],
        });
      } catch {
        fail('Deep Linking response signature or iss, aud, exp, iat, nonce rejected');
      }
      const { payload, protectedHeader } = verified;
      if (protectedHeader.kid === undefined) fail('Deep Linking response without kid');
      if (payload[ltiClaim + 'version'] !== '1.3.0') fail('Deep Linking response version is not 1.3.0');
      if (payload[ltiClaim + 'message_type'] !== 'LtiDeepLinkingResponse') fail('not a Deep Linking response');
      if (payload[ltiClaim + 'deployment_id'] !== deploymentId) fail('wrong deployment_id');
      const items = payload[dlClaim + 'content_items'] ?? [];
      if (!Array.isArray(items) || !items.every(isRecord)) {
        fail('content_items is not an array of objects');
      }
      return { kid: protectedHeader.kid, claims: payload, contentItems: items };
    },
  };
}
