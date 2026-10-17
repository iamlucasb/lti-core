import type { DiagnosticReporter } from './errors.js';
import { LtiError } from './errors.js';
import { isLtiIdentifier, nonEmpty, parseHttpsUrl } from './validation.js';

export interface Registration {
  readonly issuer: string;
  readonly clientId: string;
  readonly authorizationEndpoint: string;
  readonly jwksUri: string;
  readonly deployments: readonly string[];
  readonly allowedTargetLinkUris: readonly string[];
  /**
   * Defaults to true, as required by LTI 1.3. Set to false only for a platform known to omit the
   * deployment_id claim: a launch without it is then accepted, while a present claim is still validated
   * against `deployments` (when non-empty) and the initiation hint. See docs/adr/0002.
   */
  readonly deploymentIdRequired?: boolean;
  /**
   * Overrides the tool's `redirectUri` in the authorization requests of this registration. Must be an
   * absolute HTTPS URL without fragment, registered with the platform for this client.
   */
  readonly redirectUri?: string;
}

/** Return registrations for this issuer; the core refuses non-unique matches. */
export interface RegistrationResolver {
  resolve(issuer: string): Promise<readonly Registration[]>;
}

/** What an OIDC initiation says about the registration it targets. */
export interface InitiationTarget {
  readonly issuer: string;
  readonly clientId?: string;
  readonly targetLinkUri: string;
  /** Unsigned lti_deployment_id hint. */
  readonly deploymentHint?: string;
}

function hasUserInfo(value: string): boolean {
  const authority = value.slice(value.indexOf('://') + 3).split('/', 1)[0]!
    .split('?', 1)[0]!.split('#', 1)[0]!;
  return authority.includes('@');
}

function isValidRegistration(registration: Registration, issuer: string): boolean {
  const issuerUrl = parseHttpsUrl(registration.issuer);
  const jwksUrl = parseHttpsUrl(registration.jwksUri);
  const authorizationUrl = parseHttpsUrl(registration.authorizationEndpoint);
  return !(!issuerUrl || !jwksUrl || !authorizationUrl || registration.issuer !== issuer ||
    issuerUrl.username || issuerUrl.password || hasUserInfo(registration.issuer) ||
    registration.issuer.includes('?') || registration.issuer.includes('#') ||
    !nonEmpty(registration.clientId) ||
    !Array.isArray(registration.deployments) || !registration.deployments.every(isLtiIdentifier) ||
    registration.deploymentIdRequired !== undefined && typeof registration.deploymentIdRequired !== 'boolean' ||
    !Array.isArray(registration.allowedTargetLinkUris) ||
    !registration.allowedTargetLinkUris.every((uri: unknown) =>
      nonEmpty(uri) && parseHttpsUrl(uri) !== undefined && !uri.includes('#')) ||
    registration.authorizationEndpoint.includes('#') ||
    registration.redirectUri !== undefined &&
      (!parseHttpsUrl(registration.redirectUri) || registration.redirectUri.includes('#')));
}

/**
 * Resolves registrations through the application's resolver and validates every one of them before use.
 * Resolver failures and invalid registrations are reported, then fail closed with INVALID_CONFIGURATION.
 * Holds no state: registrations are resolved again on each call, so that revocation takes effect at once.
 */
export class RegistrationDirectory {
  constructor(private readonly resolver: RegistrationResolver, private readonly report: DiagnosticReporter) {}

  /** The single registration selected by an initiation: INVALID_LOGIN, INVALID_TARGET or INVALID_DEPLOYMENT otherwise. */
  async select(target: InitiationTarget): Promise<Registration> {
    const { clientId, targetLinkUri, deploymentHint } = target;
    const byClient = (await this.forIssuer(target.issuer)).filter(registration =>
      clientId === undefined || registration.clientId === clientId);
    if (byClient.length === 0) throw new LtiError('INVALID_LOGIN', 'registration:not_found');
    const byTarget = byClient.filter(registration => registration.allowedTargetLinkUris.includes(targetLinkUri));
    if (byTarget.length === 0) throw new LtiError('INVALID_TARGET', 'target:not_allowed');
    const matches = byTarget.filter(registration => deploymentHint === undefined ||
      registration.deployments.includes(deploymentHint) ||
      registration.deploymentIdRequired === false && registration.deployments.length === 0 &&
        isLtiIdentifier(deploymentHint));
    if (matches.length === 0) throw new LtiError('INVALID_DEPLOYMENT', 'deployment:unknown');
    if (matches.length !== 1) throw new LtiError('INVALID_LOGIN', 'registration:ambiguous');
    return matches[0]!;
  }

  /** The registration identified by issuer and client ID; INVALID_CONFIGURATION unless exactly one matches. */
  async find(issuer: string, clientId: string): Promise<Registration> {
    const matches = (await this.forIssuer(issuer)).filter(registration => registration.clientId === clientId);
    if (matches.length === 0) throw new LtiError('INVALID_CONFIGURATION', 'registration:not_found');
    if (matches.length !== 1) throw new LtiError('INVALID_CONFIGURATION', 'registration:ambiguous');
    return matches[0]!;
  }

  private async forIssuer(issuer: string): Promise<readonly Registration[]> {
    let registrations: readonly Registration[];
    try {
      registrations = await this.resolver.resolve(issuer);
      if (!Array.isArray(registrations)) throw new Error();
    } catch {
      this.report('REGISTRATION_RESOLUTION_FAILED', 'INVALID_CONFIGURATION');
      throw new LtiError('INVALID_CONFIGURATION', 'registration:resolution_failed');
    }
    for (const registration of registrations) {
      let valid: boolean;
      try {
        valid = isValidRegistration(registration, issuer);
      } catch {
        valid = false;
      }
      if (!valid) {
        this.report('REGISTRATION_INVALID', 'INVALID_CONFIGURATION');
        throw new LtiError('INVALID_CONFIGURATION', 'registration:invalid');
      }
    }
    return registrations;
  }
}
