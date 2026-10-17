import { LtiError } from './errors.js';
import type { PendingDeepLinkingResponse } from './one-time-store.js';
import { randomToken } from './random.js';
import { isRecord, nonEmpty, parseHttpsUrl } from './validation.js';

const ltiClaimPrefix = 'https://purl.imsglobal.org/spec/lti/claim/';
const dlClaimPrefix = 'https://purl.imsglobal.org/spec/lti-dl/claim/';
const responseLifetimeSeconds = 5 * 60;

/** Settings of a validated LtiDeepLinkingRequest (LTI Deep Linking 2.0, section 4.4.1). */
export interface LtiDeepLinkingSettings {
  readonly returnUrl: string;
  readonly acceptTypes: readonly string[];
  readonly acceptPresentationDocumentTargets: readonly string[];
  readonly acceptMediaTypes?: string;
  readonly acceptMultiple?: boolean;
  readonly acceptLineItem?: boolean;
  readonly autoCreate?: boolean;
  readonly title?: string;
  readonly text?: string;
}

export interface LtiDeepLinking extends LtiDeepLinkingSettings {
  /** Opaque, single-use reference to this request, required to build the response. */
  readonly responseToken: string;
}

/** LTI Deep Linking 2.0, section 3.2. Other content item types are not supported by the core. */
export interface LtiResourceLinkContentItem {
  readonly type: 'ltiResourceLink';
  /** Must be one of the registration's allowedTargetLinkUris; absent means the tool's base launch URL. */
  readonly url?: string;
  readonly title?: string;
  readonly text?: string;
  readonly custom?: Readonly<Record<string, string>>;
}

export type LtiContentItem = LtiResourceLinkContentItem;

/** Optional plain-text claims of the response (LTI Deep Linking 2.0, sections 4.5.7 to 4.5.10). */
export interface LtiDeepLinkingResponseOptions {
  readonly message?: string;
  readonly log?: string;
  readonly errorMessage?: string;
  readonly errorLog?: string;
}

/** The application POSTs `jwt` as the `JWT` form parameter to `returnUrl`. */
export interface LtiDeepLinkingResponse {
  readonly returnUrl: string;
  readonly jwt: string;
}

/**
 * Request settings with the opaque `data`, which is kept for the response and not exposed in `deepLinking`;
 * its raw signed value stays visible in `launch.claims`, but the response only uses the stored copy.
 */
export interface ParsedDeepLinkingSettings {
  readonly settings: LtiDeepLinkingSettings;
  readonly data: { readonly value: unknown } | undefined;
}

const invalidSettings = Symbol('invalid deep linking settings');

/** An optional setting set to null is treated as absent, like other optional LTI claims. */
function optionalSetting<T>(record: Record<string, unknown>, key: string,
  guard: (value: unknown) => value is T): T | undefined {
  const value = record[key];
  if (value === undefined || value === null) return undefined;
  if (!guard(value)) throw invalidSettings;
  return value;
}

const isString = (value: unknown): value is string => typeof value === 'string';
const isBoolean = (value: unknown): value is boolean => typeof value === 'boolean';
const isNonEmptyStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every(nonEmpty);

/** Returns undefined when the deep_linking_settings claim is missing or malformed. */
export function parseDeepLinkingSettings(claim: unknown): ParsedDeepLinkingSettings | undefined {
  if (!isRecord(claim)) return undefined;
  const returnUrl = claim.deep_link_return_url;
  const acceptTypes = claim.accept_types;
  const targets = claim.accept_presentation_document_targets;
  if (!parseHttpsUrl(returnUrl) || !isNonEmptyStringArray(acceptTypes) || !isNonEmptyStringArray(targets)) {
    return undefined;
  }
  let settings: LtiDeepLinkingSettings;
  try {
    const acceptMediaTypes = optionalSetting(claim, 'accept_media_types', isString);
    const acceptMultiple = optionalSetting(claim, 'accept_multiple', isBoolean);
    const acceptLineItem = optionalSetting(claim, 'accept_lineitem', isBoolean);
    const autoCreate = optionalSetting(claim, 'auto_create', isBoolean);
    const title = optionalSetting(claim, 'title', isString);
    const text = optionalSetting(claim, 'text', isString);
    settings = {
      returnUrl: returnUrl as string, acceptTypes: [...acceptTypes],
      acceptPresentationDocumentTargets: [...targets],
      ...(acceptMediaTypes !== undefined && { acceptMediaTypes }),
      ...(acceptMultiple !== undefined && { acceptMultiple }),
      ...(acceptLineItem !== undefined && { acceptLineItem }),
      ...(autoCreate !== undefined && { autoCreate }),
      ...(title !== undefined && { title }), ...(text !== undefined && { text }),
    };
  } catch (error) {
    if (error === invalidSettings) return undefined;
    throw error;
  }
  // `data` is opaque: any present value, including null, is echoed back unchanged.
  return { settings, data: Object.hasOwn(claim, 'data') && claim.data !== undefined ? { value: claim.data } : undefined };
}

const itemKeys: Readonly<Record<string, true>> = { type: true, url: true, title: true, text: true, custom: true };

/** Shape checks that do not depend on the request; failures never consume the response token. */
export function normalizeContentItems(items: unknown, allowedTargetLinkUris: readonly string[]): LtiContentItem[] {
  if (!Array.isArray(items)) throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:array');
  return items.map((item: unknown) => {
    if (!isRecord(item)) throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:item');
    if (item.type !== 'ltiResourceLink') throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:type');
    if (Object.keys(item).some(key => !Object.hasOwn(itemKeys, key))) {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:property');
    }
    if (item.url !== undefined && (!nonEmpty(item.url) || !allowedTargetLinkUris.includes(item.url))) {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:url');
    }
    if (item.title !== undefined && typeof item.title !== 'string') {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:title');
    }
    if (item.text !== undefined && typeof item.text !== 'string') {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:text');
    }
    if (item.custom !== undefined && (!isRecord(item.custom) ||
        Object.entries(item.custom).some(([key, value]) => key.length === 0 || typeof value !== 'string'))) {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:custom');
    }
    return {
      type: 'ltiResourceLink',
      ...(item.url !== undefined && { url: item.url }),
      ...(item.title !== undefined && { title: item.title as string }),
      ...(item.text !== undefined && { text: item.text as string }),
      ...(item.custom !== undefined && { custom: { ...item.custom as Record<string, string> } }),
    };
  });
}

const optionClaims = { message: 'msg', log: 'log', errorMessage: 'errormsg', errorLog: 'errorlog' } as const;

export function normalizeResponseOptions(options: unknown): Record<string, string> {
  if (options === undefined) return {};
  if (!isRecord(options)) throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:options');
  const claims: Record<string, string> = {};
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined) continue;
    if (!Object.hasOwn(optionClaims, key) || typeof value !== 'string') {
      throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:options');
    }
    claims[dlClaimPrefix + optionClaims[key as keyof typeof optionClaims]] = value;
  }
  return claims;
}

/** Checks that depend on the platform's settings (accept_types, accept_multiple). */
export function checkAcceptance(pending: PendingDeepLinkingResponse, items: readonly LtiContentItem[]): void {
  if (items.length > 1 && !pending.acceptMultiple) {
    throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:accept_multiple');
  }
  if (items.some(item => !pending.acceptTypes.includes(item.type))) {
    throw new LtiError('INVALID_CONTENT_ITEMS', 'content_items:accept_types');
  }
}

/** Claims of the LtiDeepLinkingResponse (LTI Deep Linking 2.0, section 4.5, Security Framework 5.2.2). */
export function responseClaims(pending: PendingDeepLinkingResponse, items: readonly LtiContentItem[],
  options: Readonly<Record<string, string>>): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: pending.clientId,
    aud: pending.issuer,
    iat: now,
    exp: now + responseLifetimeSeconds,
    nonce: randomToken(),
    ...(pending.deploymentId !== undefined && { [ltiClaimPrefix + 'deployment_id']: pending.deploymentId }),
    [ltiClaimPrefix + 'message_type']: 'LtiDeepLinkingResponse',
    [ltiClaimPrefix + 'version']: '1.3.0',
    [dlClaimPrefix + 'content_items']: items,
    ...(pending.data !== undefined && { [dlClaimPrefix + 'data']: pending.data.value }),
    ...options,
  };
}
