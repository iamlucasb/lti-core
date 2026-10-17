import type { JWTPayload } from 'jose';
import { LtiError } from './errors.js';
import { parseDeepLinkingSettings } from './deep-linking.js';
import type { LtiDeepLinking, ParsedDeepLinkingSettings } from './deep-linking.js';
import { readRoles } from './lti-roles.js';
import type { NormalizedLtiRole, SignedRoles } from './lti-roles.js';
import { isLtiIdentifier, isRecord, isUri, parseHttpsUrl } from './validation.js';

export type { NormalizedLtiRole } from './lti-roles.js';

const ltiClaimPrefix = 'https://purl.imsglobal.org/spec/lti/claim/';
const deepLinkingSettingsClaim = 'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings';
const contextTypeNames = ['CourseTemplate', 'CourseOffering', 'CourseSection', 'Group'] as const;
const knownContextTypes: Record<string, true> = {};
// LTI 1.3 Core, appendix A: deprecated simple names MAY be recognized; they map to their LIS v2 URI.
const contextTypesByShortName: Record<string, string> = {};
for (const name of contextTypeNames) {
  const uri = 'http://purl.imsglobal.org/vocab/lis/v2/course#' + name;
  knownContextTypes[uri] = true;
  knownContextTypes['urn:lti:context-type:ims/lis/' + name] = true;
  contextTypesByShortName[name] = uri;
}
export type LtiDocumentTarget = 'frame' | 'iframe' | 'window';
const documentTargets: Readonly<Record<LtiDocumentTarget, true>> = { frame: true, iframe: true, window: true };
const grandfatheredLanguageTags: Readonly<Record<string, true>> = {
  'art-lojban': true, 'cel-gaulish': true, 'en-gb-oed': true, 'i-ami': true, 'i-bnn': true,
  'i-default': true, 'i-enochian': true, 'i-hak': true, 'i-klingon': true, 'i-lux': true,
  'i-mingo': true, 'i-navajo': true, 'i-pwn': true, 'i-tao': true, 'i-tay': true, 'i-tsu': true,
  'no-bok': true, 'no-nyn': true, 'sgn-be-fr': true, 'sgn-be-nl': true, 'sgn-ch-de': true,
  'zh-guoyu': true, 'zh-hakka': true, 'zh-min': true, 'zh-min-nan': true, 'zh-xiang': true,
};
const languageTagPattern = /^(?:[A-Za-z]{2,3}(?:-[A-Za-z]{3}){0,3}|[A-Za-z]{4}|[A-Za-z]{5,8})(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?(?:-(?:[A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(?:-[0-9A-WY-Z](?:-[A-Za-z0-9]{2,8})+)*(?:-x(?:-[A-Za-z0-9]{1,8})+)?$/i;
const privateUseLanguageTagPattern = /^x(?:-[A-Za-z0-9]{1,8})+$/i;

interface LtiLaunchBase {
  readonly platform: { readonly issuer: string; readonly clientId: string;
    /** Absent only when the registration does not require deployment_id and the platform omitted it. */
    readonly deploymentId?: string };
  readonly user: { readonly id: string; readonly name?: string; readonly givenName?: string;
    readonly familyName?: string; readonly email?: string; readonly locale?: string };
  readonly context?: { readonly id: string; readonly label?: string; readonly title?: string;
    readonly type?: readonly string[] };
  readonly launchPresentation?: { readonly documentTarget?: LtiDocumentTarget; readonly width?: number;
    readonly height?: number; readonly returnUrl?: string; readonly locale?: string };
  readonly custom?: Readonly<Record<string, string>>;
  readonly targetLinkUri: string;
  /** Signed role URIs, unchanged. The core never derives application permissions from them. */
  readonly roles: readonly string[];
  readonly normalizedRoles: readonly NormalizedLtiRole[];
  /**
   * Full verified JWT payload: escape hatch for claims the core does not interpret (AGS/NRPS endpoints,
   * tool_platform, lis, vendor extensions). Values are signed by the platform but NOT validated by the core.
   */
  readonly claims: Readonly<Record<string, unknown>>;
}

export interface LtiResourceLinkLaunch extends LtiLaunchBase {
  readonly messageType: 'LtiResourceLinkRequest';
  readonly resourceLink: { readonly id: string; readonly title?: string; readonly description?: string };
}

export interface LtiDeepLinkingLaunch extends LtiLaunchBase {
  readonly messageType: 'LtiDeepLinkingRequest';
  readonly deepLinking: LtiDeepLinking;
}

/** Result of a validated launch, discriminated by `messageType`. */
export type LtiLaunch = LtiResourceLinkLaunch | LtiDeepLinkingLaunch;

interface LaunchBinding {
  readonly issuer: string;
  readonly clientId: string;
  readonly deployments: readonly string[];
  readonly deploymentIdRequired: boolean;
  readonly targetLinkUri: string;
  /** Unsigned lti_deployment_id received at initiation; never exposed. */
  readonly deploymentHint?: string;
}

function signedDeploymentId(payload: JWTPayload, binding: LaunchBinding): string | undefined {
  const deploymentId = payload[ltiClaimPrefix + 'deployment_id'];
  if (deploymentId === undefined && !binding.deploymentIdRequired) return undefined;
  const restricted = binding.deploymentIdRequired || binding.deployments.length > 0;
  if (deploymentId === undefined) throw new LtiError('INVALID_DEPLOYMENT', 'deployment:missing');
  if (!isLtiIdentifier(deploymentId)) throw new LtiError('INVALID_DEPLOYMENT', 'deployment:malformed');
  if (restricted && !binding.deployments.includes(deploymentId)) {
    throw new LtiError('INVALID_DEPLOYMENT', 'deployment:unknown');
  }
  if (binding.deploymentHint !== undefined && binding.deploymentHint !== deploymentId) {
    throw new LtiError('INVALID_DEPLOYMENT', 'deployment:hint_mismatch');
  }
  return deploymentId;
}

/**
 * `context.type` is optional and descriptive: an unusable value is dropped instead of rejecting the launch.
 * Entries that are neither URIs nor known short names are discarded; without any standard type left, the
 * whole claim is ignored, since LTI requires at least one type from its vocabulary.
 */
function contextTypes(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const types: string[] = [];
  for (const entry of value) {
    const type = typeof entry === 'string' && Object.hasOwn(contextTypesByShortName, entry)
      ? contextTypesByShortName[entry] : entry;
    if (isUri(type) && !types.includes(type)) types.push(type);
  }
  return types.some(type => knownContextTypes[type] === true) ? types : undefined;
}

/**
 * Descriptive identifiers (resource link, context) may arrive as JSON integers. Only safe non-negative
 * integers are converted, so that no precision loss can merge two identifiers. Identity and security
 * claims (`sub`, `deployment_id`, ...) never go through this conversion.
 */
function descriptiveIdentifier(value: unknown): string | undefined {
  const id = typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : value;
  return isLtiIdentifier(id) ? id : undefined;
}

/*
 * Descriptive claims (profile, titles, presentation, custom) are tolerant: a value of the wrong JSON type
 * or outside its vocabulary is dropped instead of rejecting the launch. A null value is treated as absent.
 * Security and identity claims, and the identifiers `context.id` and `resource_link.id`, stay strict.
 */

/** The `context` claim carries an identifier, so a present non-object value is rejected. */
function optionalContext(payload: JWTPayload): Record<string, unknown> | undefined {
  const value = payload[ltiClaimPrefix + 'context'];
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) throw new LtiError('INVALID_CLAIMS', 'claim:context');
  return value;
}

function descriptiveRecord(payload: JWTPayload, key: string): Record<string, unknown> | undefined {
  const value = payload[ltiClaimPrefix + key];
  return isRecord(value) ? value : undefined;
}

function descriptiveText(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

function descriptiveDimension(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

/**
 * Some platforms (e.g. Moodle) send POSIX-style locales such as `pt_br`: `_` is read as the BCP 47
 * subtag separator `-`. A value that is still not a language tag, or not a string, is dropped.
 */
function descriptiveLocale(record: Record<string, unknown>, key: string): string | undefined {
  const value = descriptiveText(record, key)?.replaceAll('_', '-');
  return value !== undefined && isLanguageTag(value) ? value : undefined;
}

/** `return_url` is only exposed as an absolute HTTPS URL; any other value is dropped. */
function descriptiveReturnUrl(record: Record<string, unknown>): string | undefined {
  const value = descriptiveText(record, 'return_url');
  return value !== undefined && parseHttpsUrl(value) ? value : undefined;
}

/**
 * Custom parameters are exposed as strings. Platforms may send JSON scalars: finite numbers and booleans
 * are converted with String(); null, objects and arrays are dropped.
 */
function customParameters(payload: JWTPayload): Record<string, string> | undefined {
  const value = descriptiveRecord(payload, 'custom');
  if (value === undefined) return undefined;
  const custom: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string' || typeof entry === 'boolean' ||
        // Integers beyond the safe range are dropped: their decimal form could merge two identifiers.
        typeof entry === 'number' && Number.isFinite(entry) &&
          (!Number.isInteger(entry) || Number.isSafeInteger(entry))) {
      custom[key] = String(entry);
    }
  }
  return custom;
}

function isLanguageTag(value: string): boolean {
  return grandfatheredLanguageTags[value.toLowerCase()] === true || languageTagPattern.test(value) ||
    privateUseLanguageTagPattern.test(value);
}

function isDocumentTarget(value: string): value is LtiDocumentTarget {
  return Object.hasOwn(documentTargets, value);
}

/** A launch whose deep linking response token has not been issued yet. */
export type ValidatedLaunch =
  | { readonly messageType: 'LtiResourceLinkRequest'; readonly launch: LtiResourceLinkLaunch }
  | { readonly messageType: 'LtiDeepLinkingRequest'; readonly launch: Omit<LtiDeepLinkingLaunch, 'deepLinking'>;
      readonly deepLinking: ParsedDeepLinkingSettings };

/** Roles are required in a resource link launch, optional in a deep linking request (LTI DL 2.0, 4.4.9). */
function signedRoles(payload: JWTPayload, required: boolean): SignedRoles {
  const claim = payload[ltiClaimPrefix + 'roles'];
  if (!required && (claim === undefined || claim === null)) return { roles: [], normalizedRoles: [] };
  const roles = readRoles(claim);
  if (!roles) throw new LtiError('INVALID_CLAIMS', 'claim:roles');
  return roles;
}

export function buildLaunch(payload: JWTPayload, binding: LaunchBinding): ValidatedLaunch {
  const deploymentId = signedDeploymentId(payload, binding);
  const messageType = payload[ltiClaimPrefix + 'message_type'];
  if (payload[ltiClaimPrefix + 'version'] !== '1.3.0') throw new LtiError('INVALID_CLAIMS', 'claim:version');
  if (messageType !== 'LtiResourceLinkRequest' && messageType !== 'LtiDeepLinkingRequest') {
    throw new LtiError('INVALID_CLAIMS', 'claim:message_type');
  }
  if (payload[ltiClaimPrefix + 'target_link_uri'] !== binding.targetLinkUri) {
    throw new LtiError('INVALID_CLAIMS', 'claim:target_link_uri');
  }
  if (!isLtiIdentifier(payload.sub)) throw new LtiError('INVALID_CLAIMS', 'claim:sub');

  if (messageType === 'LtiDeepLinkingRequest') {
    const deepLinking = parseDeepLinkingSettings(payload[deepLinkingSettingsClaim]);
    if (deepLinking === undefined) throw new LtiError('INVALID_CLAIMS', 'claim:deep_linking_settings');
    const roles = signedRoles(payload, false);
    return { messageType, deepLinking,
      launch: { messageType, ...commonClaims(payload, binding, deploymentId, roles) } };
  }

  const resource = payload[ltiClaimPrefix + 'resource_link'];
  const roles = signedRoles(payload, true);
  if (!isRecord(resource)) throw new LtiError('INVALID_CLAIMS', 'claim:resource_link');
  const resourceLinkId = descriptiveIdentifier(resource.id);
  if (resourceLinkId === undefined) throw new LtiError('INVALID_CLAIMS', 'claim:resource_link.id');
  const title = descriptiveText(resource, 'title');
  const description = descriptiveText(resource, 'description');
  const common = commonClaims(payload, binding, deploymentId, roles);
  return { messageType, launch: { messageType, ...common,
    resourceLink: { id: resourceLinkId, ...(title !== undefined && { title }),
      ...(description !== undefined && { description }) } } };
}

/** Claims shared by resource link launches and deep linking requests (LTI DL 2.0, 4.4). */
function commonClaims(payload: JWTPayload, binding: LaunchBinding, deploymentId: string | undefined,
  { roles, normalizedRoles }: SignedRoles): LtiLaunchBase {
  const contextClaim = optionalContext(payload);
  let contextId: string | undefined;
  let contextType: string[] | undefined;
  if (contextClaim !== undefined) {
    contextId = descriptiveIdentifier(contextClaim.id);
    if (contextId === undefined) throw new LtiError('INVALID_CLAIMS', 'claim:context.id');
    contextType = contextTypes(contextClaim.type);
  }
  const presentation = descriptiveRecord(payload, 'launch_presentation');
  const custom = customParameters(payload);

  const name = descriptiveText(payload, 'name');
  const givenName = descriptiveText(payload, 'given_name');
  const familyName = descriptiveText(payload, 'family_name');
  const email = descriptiveText(payload, 'email');
  const locale = descriptiveLocale(payload, 'locale');
  const label = contextClaim && descriptiveText(contextClaim, 'label');
  const contextTitle = contextClaim && descriptiveText(contextClaim, 'title');
  // Descriptive vocabulary: an unknown target is dropped, like an unusable context type.
  const documentTargetValue = presentation && descriptiveText(presentation, 'document_target');
  const documentTarget = documentTargetValue !== undefined && isDocumentTarget(documentTargetValue)
    ? documentTargetValue : undefined;
  const width = presentation && descriptiveDimension(presentation, 'width');
  const height = presentation && descriptiveDimension(presentation, 'height');
  const returnUrl = presentation && descriptiveReturnUrl(presentation);
  const presentationLocale = presentation && descriptiveLocale(presentation, 'locale');

  return {
    platform: { issuer: binding.issuer, clientId: binding.clientId,
      ...(deploymentId !== undefined && { deploymentId }) },
    user: { id: payload.sub as string, ...(name !== undefined && { name }),
      ...(givenName !== undefined && { givenName }), ...(familyName !== undefined && { familyName }),
      ...(email !== undefined && { email }), ...(locale !== undefined && { locale }) },
    ...(contextClaim !== undefined && contextId !== undefined && { context: { id: contextId,
      ...(label !== undefined && { label }), ...(contextTitle !== undefined && { title: contextTitle }),
      ...(contextType !== undefined && { type: contextType }) } }),
    ...(presentation !== undefined && { launchPresentation: {
      ...(documentTarget !== undefined && { documentTarget }), ...(width !== undefined && { width }),
      ...(height !== undefined && { height }), ...(returnUrl !== undefined && { returnUrl }),
      ...(presentationLocale !== undefined && { locale: presentationLocale }),
    } }),
    ...(custom !== undefined && { custom }),
    targetLinkUri: binding.targetLinkUri,
    roles,
    normalizedRoles,
    claims: Object.freeze({ ...payload }),
  };
}
