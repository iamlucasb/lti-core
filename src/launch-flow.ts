import type { DeepLinkingResponses } from './deep-linking-responses.js';
import type { DiagnosticReporter } from './errors.js';
import { LtiError } from './errors.js';
import { buildLaunch } from './launch-claims.js';
import type { LtiLaunch } from './launch-claims.js';
import type { OneTimeEntries } from './one-time-store.js';
import { randomToken } from './random.js';
import type { Registration, RegistrationDirectory } from './registrations.js';
import { TokenVerifier } from './token-verifier.js';
import type { TokenVerifierOptions } from './token-verifier.js';
import { isRecord, nonEmpty } from './validation.js';

const initiationLifetimeMs = 5 * 60_000;

export interface LoginRequest {
  readonly iss?: unknown;
  readonly login_hint?: unknown;
  readonly target_link_uri?: unknown;
  readonly client_id?: unknown;
  readonly lti_message_hint?: unknown;
  readonly lti_deployment_id?: unknown;
}

/**
 * Where to send the browser after an OIDC initiation. `state` is also embedded in `url`; the application
 * may bind it to the browser session (for example in a cookie) and check it when the launch comes back.
 */
export interface LtiAuthorizationRedirect {
  readonly url: string;
  readonly state: string;
}

export interface LaunchResponse {
  readonly state?: unknown;
  readonly id_token?: unknown;
}

/**
 * OIDC third-party initiation and launch validation (LTI 1.3 Core, Security Framework 5.1).
 * Every launch consumes its `state` before the token is checked, so a failed attempt cannot be replayed.
 */
export class LaunchFlow {
  private readonly tokenVerifier: TokenVerifier;

  constructor(
    private readonly redirectUri: string,
    private readonly registrations: RegistrationDirectory,
    private readonly entries: OneTimeEntries,
    private readonly deepLinking: DeepLinkingResponses,
    private readonly report: DiagnosticReporter,
    private readonly verification: TokenVerifierOptions,
  ) {
    this.tokenVerifier = new TokenVerifier(verification);
  }

  async initiate(login: LoginRequest): Promise<LtiAuthorizationRedirect> {
    if (!isRecord(login)) throw new LtiError('INVALID_LOGIN', 'login:invalid');
    if (!nonEmpty(login.iss)) throw new LtiError('INVALID_LOGIN', 'login:iss');
    if (!nonEmpty(login.login_hint)) throw new LtiError('INVALID_LOGIN', 'login:login_hint');
    if (!nonEmpty(login.target_link_uri)) throw new LtiError('INVALID_LOGIN', 'login:target_link_uri');
    // Some platforms send empty optional fields: an empty client_id or lti_deployment_id is absent.
    const clientId = login.client_id === '' ? undefined : login.client_id;
    const deploymentHint = login.lti_deployment_id === '' ? undefined : login.lti_deployment_id;
    if (clientId !== undefined && !nonEmpty(clientId)) {
      throw new LtiError('INVALID_LOGIN', 'login:client_id');
    }
    if (login.lti_message_hint !== undefined && typeof login.lti_message_hint !== 'string') {
      throw new LtiError('INVALID_LOGIN', 'login:lti_message_hint');
    }
    if (deploymentHint !== undefined && !nonEmpty(deploymentHint)) {
      throw new LtiError('INVALID_LOGIN', 'login:lti_deployment_id');
    }
    const registration = await this.registrations.select({
      issuer: login.iss, targetLinkUri: login.target_link_uri,
      ...(clientId !== undefined && { clientId }),
      ...(deploymentHint !== undefined && { deploymentHint }),
    });
    const state = randomToken();
    const nonce = randomToken();
    await this.entries.putLaunch(state, {
      nonce, issuer: registration.issuer, clientId: registration.clientId,
      targetLinkUri: login.target_link_uri, expiresAt: Date.now() + initiationLifetimeMs,
      ...(deploymentHint !== undefined ? { deploymentId: deploymentHint } : {}),
    });
    const url = new URL(registration.authorizationEndpoint);
    url.searchParams.set('scope', 'openid');
    url.searchParams.set('response_type', 'id_token');
    url.searchParams.set('response_mode', 'form_post');
    url.searchParams.set('prompt', 'none');
    url.searchParams.set('client_id', registration.clientId);
    url.searchParams.set('redirect_uri', registration.redirectUri ?? this.redirectUri);
    url.searchParams.set('login_hint', login.login_hint);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    if (login.lti_message_hint !== undefined) url.searchParams.set('lti_message_hint', login.lti_message_hint);
    return { url: url.toString(), state };
  }

  async validate(response: LaunchResponse): Promise<LtiLaunch> {
    if (!isRecord(response) || !nonEmpty(response.state)) throw new LtiError('INVALID_STATE', 'state:missing');
    const pending = await this.entries.takeLaunch(response.state);
    if (!pending) throw new LtiError('INVALID_STATE', 'state:unknown');
    if (!nonEmpty(response.id_token)) throw new LtiError('INVALID_TOKEN', 'token:missing');

    const registration = await this.registrations.find(pending.issuer, pending.clientId);
    if (!registration.allowedTargetLinkUris.includes(pending.targetLinkUri)) {
      throw new LtiError('INVALID_TARGET', 'target:not_allowed');
    }
    const payload = await this.verifiedPayload(response.id_token, registration, pending.nonce);

    const validated = buildLaunch(payload, {
      issuer: registration.issuer,
      clientId: registration.clientId,
      deployments: registration.deployments,
      deploymentIdRequired: registration.deploymentIdRequired !== false,
      targetLinkUri: pending.targetLinkUri,
      ...(pending.deploymentId !== undefined ? { deploymentHint: pending.deploymentId } : {}),
    });
    if (validated.messageType === 'LtiResourceLinkRequest') return validated.launch;
    const { launch } = validated;
    const deepLinking = await this.deepLinking.issue(registration, launch.platform.deploymentId,
      validated.deepLinking);
    return { ...launch, deepLinking };
  }

  /**
   * Signature, kid, issuer, audience/azp, iat and nonce (Security Framework 5.1.3). An iat in the future
   * is accepted only within the configured clock tolerance, as exp and nbf are.
   */
  private async verifiedPayload(idToken: string, registration: Registration, nonce: string) {
    let verified;
    try {
      verified = await this.tokenVerifier.verify(idToken, registration);
    } catch (error) {
      if (error instanceof LtiError) {
        if (error.code === 'JWKS_ERROR') this.report('JWKS_REQUEST_FAILED', 'JWKS_ERROR');
        throw error;
      }
      this.report('JWKS_REQUEST_FAILED', 'JWKS_ERROR');
      throw new LtiError('JWKS_ERROR', 'jwks:unavailable');
    }
    const { payload, protectedHeader } = verified;
    const { clientId } = registration;
    if (!nonEmpty(protectedHeader.kid)) throw new LtiError('INVALID_TOKEN', 'token:kid');
    if (payload.iss !== registration.issuer) throw new LtiError('INVALID_ISSUER', 'token:iss');
    const audiences: unknown[] = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (audiences.length === 0 || audiences.some(audience => audience !== clientId)) {
      throw new LtiError('INVALID_AUDIENCE', 'token:aud');
    }
    if (audiences.length > 1 && payload.azp !== clientId || payload.azp !== undefined && payload.azp !== clientId) {
      throw new LtiError('INVALID_AUDIENCE', 'token:azp');
    }
    const latestIssuedAt = Math.floor(Date.now() / 1000) + this.verification.clockToleranceSeconds;
    if (typeof payload.iat !== 'number' || payload.iat > latestIssuedAt) {
      throw new LtiError('INVALID_TOKEN', 'token:iat');
    }
    if (payload.nonce !== nonce) throw new LtiError('INVALID_NONCE', 'token:nonce');
    return payload;
  }
}
