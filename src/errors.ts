export type LtiErrorCode = 'INVALID_LOGIN' | 'INVALID_TARGET' | 'INVALID_STATE' | 'INVALID_NONCE' |
  'INVALID_TOKEN' | 'INVALID_ISSUER' | 'INVALID_AUDIENCE' | 'TOKEN_EXPIRED' |
  'INVALID_DEPLOYMENT' | 'INVALID_CLAIMS' | 'JWKS_ERROR' | 'STORE_ERROR' | 'INVALID_CONFIGURATION' |
  'INVALID_CONTENT_ITEMS' | 'INVALID_DEEP_LINKING_RESPONSE';

/**
 * Stable, machine-readable name of the check that failed. A reason names a check or a field, never a
 * value: it carries no key material, token, state, nonce, claim value, issuer URL or user data.
 */
export type LtiErrorReason =
  /**
   * `createLtiTool` options (INVALID_CONFIGURATION). `config:invalid`: the configuration is not an object
   * or cannot be read. `config:toolKeys`: the tool keys are invalid or signing failed, without detail.
   * `config:toolKeys_missing`: an operation needs tool keys that were not configured.
   */
  | 'config:invalid' | 'config:redirectUri' | 'config:resolver' | 'config:store' | 'config:onDiagnostic'
  | 'config:deepLinkingResponseLifetimeMs' | 'config:clockToleranceSeconds' | 'config:jwks'
  | 'config:toolKeys' | 'config:toolKeys_missing'
  /**
   * Registrations returned by the resolver. `registration:not_found` and `registration:ambiguous` come
   * with INVALID_LOGIN at initiation and INVALID_CONFIGURATION afterwards; the others with
   * INVALID_CONFIGURATION.
   */
  | 'registration:resolution_failed' | 'registration:invalid' | 'registration:not_found'
  | 'registration:ambiguous'
  /** OIDC initiation parameter that is missing or malformed (INVALID_LOGIN); `login:invalid`: not an object. */
  | 'login:invalid' | 'login:iss' | 'login:login_hint' | 'login:target_link_uri' | 'login:client_id'
  | 'login:lti_message_hint' | 'login:lti_deployment_id'
  /** The target link URI is not allowed by the registration (INVALID_TARGET). */
  | 'target:not_allowed'
  /**
   * Launch `state` (INVALID_STATE). `state:unknown`: missing, already consumed, expired or unreadable
   * in the store.
   */
  | 'state:missing' | 'state:unknown'
  /** Single-use store failure (STORE_ERROR). */
  | 'store:put' | 'store:take'
  /** Platform JWKS (JWKS_ERROR): unreachable, invalid or timed out, or no key matches the token. */
  | 'jwks:unavailable' | 'jwks:no_matching_key'
  /**
   * The id_token and its registered JWT claims. Codes: INVALID_TOKEN, except `token:exp` (TOKEN_EXPIRED
   * when expired), `token:iss` (INVALID_ISSUER), `token:aud` and `token:azp` (INVALID_AUDIENCE) and
   * `token:nonce` (INVALID_NONCE).
   */
  | 'token:missing' | 'token:malformed' | 'token:alg' | 'token:signature' | 'token:kid' | 'token:exp'
  | 'token:iat' | 'token:nbf' | 'token:iss' | 'token:aud' | 'token:azp' | 'token:nonce'
  /** Required LTI claim that is missing or invalid (INVALID_CLAIMS). */
  | 'claim:version' | 'claim:message_type' | 'claim:target_link_uri' | 'claim:sub' | 'claim:roles'
  | 'claim:resource_link' | 'claim:resource_link.id' | 'claim:context' | 'claim:context.id'
  | 'claim:deep_linking_settings'
  /**
   * The signed deployment_id claim (INVALID_DEPLOYMENT); `deployment:unknown` also when the initiation
   * hint matches no registration deployment.
   */
  | 'deployment:missing' | 'deployment:malformed' | 'deployment:unknown' | 'deployment:hint_mismatch'
  /**
   * Content Items and options given to `createDeepLinkingResponse` (INVALID_CONTENT_ITEMS).
   * `content_items:accept_types` and `content_items:accept_multiple` refuse items the platform does not accept.
   */
  | 'content_items:array' | 'content_items:item' | 'content_items:type' | 'content_items:property'
  | 'content_items:url' | 'content_items:title' | 'content_items:text' | 'content_items:custom'
  | 'content_items:options' | 'content_items:accept_types' | 'content_items:accept_multiple'
  /**
   * Deep linking response token (INVALID_DEEP_LINKING_RESPONSE). `response_token:unknown`: missing,
   * already consumed, expired or unreadable in the store, or issued for another registration.
   */
  | 'response_token:malformed' | 'response_token:unknown';

/**
 * The only error thrown by the core. Internal modules throw it directly; errors of dependencies
 * (JOSE, network, store, resolver) are translated into a code without being attached as a cause.
 * The message is the code, followed by the reason when there is one: `CODE: reason`.
 */
export class LtiError extends Error {
  constructor(readonly code: LtiErrorCode, readonly reason?: LtiErrorReason) {
    super(reason === undefined ? code : `${code}: ${reason}`);
    this.name = 'LtiError';
  }
}

export type LtiDiagnosticCode = 'REGISTRATION_RESOLUTION_FAILED' | 'REGISTRATION_INVALID' |
  'STATE_PUT_FAILED' | 'STATE_TAKE_FAILED' | 'JWKS_REQUEST_FAILED' |
  'DEEP_LINKING_RESPONSE_PUT_FAILED' | 'DEEP_LINKING_RESPONSE_TAKE_FAILED';

export interface LtiDiagnostic {
  readonly code: LtiDiagnosticCode;
  readonly errorCode: Extract<LtiErrorCode, 'INVALID_CONFIGURATION' | 'STORE_ERROR' | 'JWKS_ERROR'>;
}

/** Reports an operational failure; never throws. */
export type DiagnosticReporter = (code: LtiDiagnosticCode, errorCode: LtiDiagnostic['errorCode']) => void;
