import { base64url } from 'jose';
import { checkAcceptance, normalizeContentItems, normalizeResponseOptions, responseClaims } from './deep-linking.js';
import type {
  LtiDeepLinking, LtiDeepLinkingResponse, ParsedDeepLinkingSettings,
} from './deep-linking.js';
import { LtiError } from './errors.js';
import type { OneTimeEntries } from './one-time-store.js';
import { randomToken } from './random.js';
import type { Registration, RegistrationDirectory } from './registrations.js';
import type { ToolKeyring } from './tool-keys.js';
import { nonEmpty } from './validation.js';

/**
 * The token names its registration so that content items can be checked against it before the
 * single-use entry is consumed. The registration part is not trusted: it is part of the store key,
 * and the stored entry is checked against it.
 */
function createResponseToken(issuer: string, clientId: string): string {
  const registration = base64url.encode(JSON.stringify([issuer, clientId]));
  return `${registration}.${randomToken()}`;
}

function responseTokenRegistration(token: unknown): { issuer: string; clientId: string } | undefined {
  if (!nonEmpty(token) || token.length > 4096) return undefined;
  const parts = token.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]!) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1]!)) {
    return undefined;
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(base64url.decode(parts[0]!)));
    if (!Array.isArray(value) || value.length !== 2 || !nonEmpty(value[0]) || !nonEmpty(value[1])) return undefined;
    return { issuer: value[0], clientId: value[1] };
  } catch {
    return undefined;
  }
}

/**
 * Deep linking responses can only be built from a request validated by this tool: `issue` records the
 * request as a single-use entry and returns its token; `respond` consumes it and signs the response.
 */
export class DeepLinkingResponses {
  constructor(
    private readonly registrations: RegistrationDirectory,
    private readonly entries: OneTimeEntries,
    private readonly keyring: ToolKeyring | undefined,
    private readonly lifetimeMs: number,
  ) {}

  async issue(registration: Registration, deploymentId: string | undefined,
    request: ParsedDeepLinkingSettings): Promise<LtiDeepLinking> {
    const { settings, data } = request;
    const responseToken = createResponseToken(registration.issuer, registration.clientId);
    await this.entries.putDeepLinkingResponse(responseToken, {
      issuer: registration.issuer, clientId: registration.clientId,
      ...(deploymentId !== undefined && { deploymentId }),
      returnUrl: settings.returnUrl, acceptTypes: settings.acceptTypes,
      acceptMultiple: settings.acceptMultiple === true,
      ...(data !== undefined && { data }), expiresAt: Date.now() + this.lifetimeMs,
    });
    return { ...settings, responseToken };
  }

  /**
   * Order matters: malformed tokens, unknown registrations and malformed items or options fail without
   * consuming the token; only accept_types/accept_multiple refusals happen after consumption.
   */
  async respond(responseToken: unknown, items: unknown, options: unknown): Promise<LtiDeepLinkingResponse> {
    if (!this.keyring) throw new LtiError('INVALID_CONFIGURATION', 'config:toolKeys_missing');
    const reference = responseTokenRegistration(responseToken);
    if (!reference) throw new LtiError('INVALID_DEEP_LINKING_RESPONSE', 'response_token:malformed');
    const registration = await this.registrations.find(reference.issuer, reference.clientId);
    const content = normalizeContentItems(items, registration.allowedTargetLinkUris);
    const optionClaims = normalizeResponseOptions(options);

    const pending = await this.entries.takeDeepLinkingResponse(responseToken as string);
    if (!pending || pending.issuer !== reference.issuer || pending.clientId !== reference.clientId) {
      throw new LtiError('INVALID_DEEP_LINKING_RESPONSE', 'response_token:unknown');
    }
    checkAcceptance(pending, content);
    let jwt: string;
    try {
      jwt = await this.keyring.sign(responseClaims(pending, content, optionClaims));
    } catch {
      throw new LtiError('INVALID_CONFIGURATION', 'config:toolKeys');
    }
    return { returnUrl: pending.returnUrl, jwt };
  }
}
