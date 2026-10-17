import type { DiagnosticReporter } from './errors.js';
import { LtiError } from './errors.js';
import { isRecord, nonEmpty, parseHttpsUrl } from './validation.js';

/** Shared implementations must make put create-only (no overwrite of live keys),
 * persist the opaque value until expiresAt, and atomically delete-and-return across all instances.
 * take returns undefined for missing, expired or previously consumed keys; never return the same
 * value twice, including under concurrent calls.
 */
export interface OneTimeStore {
  put(key: string, value: string, expiresAt: number): Promise<void>;
  take(key: string): Promise<string | undefined>;
}

/**
 * Only for tests and single-process development; no multi-instance guarantee.
 * Entries are created by put, deleted by take, and expired entries are swept every 64 writes.
 */
export class MemoryOneTimeStore implements OneTimeStore {
  private readonly entries = new Map<string, { value: string; expiresAt: number }>();
  private writesUntilCleanup = 64;

  async put(key: string, value: string, expiresAt: number): Promise<void> {
    const now = Date.now();
    this.writesUntilCleanup--;
    if (this.writesUntilCleanup === 0) {
      for (const [storedKey, entry] of this.entries) {
        if (entry.expiresAt <= now) this.entries.delete(storedKey);
      }
      this.writesUntilCleanup = 64;
    }
    const existing = this.entries.get(key);
    if (existing && existing.expiresAt > now) throw new Error('Key already exists');
    if (expiresAt > now) this.entries.set(key, { value, expiresAt });
  }

  async take(key: string): Promise<string | undefined> {
    const entry = this.entries.get(key);
    this.entries.delete(key);
    return entry && entry.expiresAt > Date.now() ? entry.value : undefined;
  }
}

/** An OIDC initiation awaiting its launch, keyed by `state`. */
export interface PendingLaunch {
  readonly nonce: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly targetLinkUri: string;
  /** Unsigned lti_deployment_id hint received at initiation. */
  readonly deploymentId?: string;
  readonly expiresAt: number;
}

/** What a deep linking response needs from its validated request, keyed by the response token. */
export interface PendingDeepLinkingResponse {
  readonly issuer: string;
  readonly clientId: string;
  readonly deploymentId?: string;
  readonly returnUrl: string;
  readonly acceptTypes: readonly string[];
  readonly acceptMultiple: boolean;
  /** Opaque `data` of the request, when present (possibly null). */
  readonly data?: { readonly value: unknown };
  readonly expiresAt: number;
}

const deepLinkingKind = 'lti-core/deep-linking-response';
const isStringArray = (value: unknown): value is string[] => Array.isArray(value) && value.every(nonEmpty);
const isTimestamp = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);

function parseJson(raw: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(raw);
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function parsePendingLaunch(raw: string): PendingLaunch | undefined {
  const value = parseJson(raw);
  if (!value || !nonEmpty(value.nonce) || !nonEmpty(value.issuer) || !nonEmpty(value.clientId) ||
      !nonEmpty(value.targetLinkUri) || !isTimestamp(value.expiresAt) ||
      value.deploymentId !== undefined && !nonEmpty(value.deploymentId)) return undefined;
  return {
    nonce: value.nonce, issuer: value.issuer, clientId: value.clientId,
    targetLinkUri: value.targetLinkUri, expiresAt: value.expiresAt,
    ...(value.deploymentId !== undefined ? { deploymentId: value.deploymentId } : {}),
  };
}

function parsePendingResponse(raw: string): PendingDeepLinkingResponse | undefined {
  const value = parseJson(raw);
  if (!value || value.kind !== deepLinkingKind || !nonEmpty(value.issuer) || !nonEmpty(value.clientId) ||
      value.deploymentId !== undefined && !nonEmpty(value.deploymentId) || !parseHttpsUrl(value.returnUrl) ||
      !isStringArray(value.acceptTypes) || typeof value.acceptMultiple !== 'boolean' ||
      value.data !== undefined && !(isRecord(value.data) && Object.hasOwn(value.data, 'value')) ||
      !isTimestamp(value.expiresAt)) return undefined;
  return {
    issuer: value.issuer, clientId: value.clientId, returnUrl: value.returnUrl as string,
    acceptTypes: value.acceptTypes, acceptMultiple: value.acceptMultiple, expiresAt: value.expiresAt,
    ...(value.deploymentId !== undefined && { deploymentId: value.deploymentId }),
    ...(value.data !== undefined && { data: { value: (value.data as { value: unknown }).value } }),
  };
}

/**
 * Typed single-use entries over the application's opaque OneTimeStore. Owns their serialization,
 * expiry checks and the translation of store failures into STORE_ERROR (reported, without cause).
 * A take returns undefined for a missing, consumed, expired or unreadable entry, and the entry is
 * consumed even then. Launch entries keep their pre-0.3 format; deep linking entries carry a kind
 * tag, so neither can be read as the other.
 */
export class OneTimeEntries {
  constructor(private readonly store: OneTimeStore, private readonly report: DiagnosticReporter) {}

  putLaunch(state: string, pending: PendingLaunch): Promise<void> {
    return this.put(state, JSON.stringify(pending), pending.expiresAt, 'STATE_PUT_FAILED');
  }

  async takeLaunch(state: string): Promise<PendingLaunch | undefined> {
    const raw = await this.take(state, 'STATE_TAKE_FAILED');
    const pending = raw === undefined ? undefined : parsePendingLaunch(raw);
    return pending && pending.expiresAt > Date.now() ? pending : undefined;
  }

  putDeepLinkingResponse(token: string, pending: PendingDeepLinkingResponse): Promise<void> {
    return this.put(token, JSON.stringify({ kind: deepLinkingKind, ...pending }), pending.expiresAt,
      'DEEP_LINKING_RESPONSE_PUT_FAILED');
  }

  async takeDeepLinkingResponse(token: string): Promise<PendingDeepLinkingResponse | undefined> {
    const raw = await this.take(token, 'DEEP_LINKING_RESPONSE_TAKE_FAILED');
    const pending = raw === undefined ? undefined : parsePendingResponse(raw);
    return pending && pending.expiresAt > Date.now() ? pending : undefined;
  }

  private async put(key: string, value: string, expiresAt: number,
    diagnostic: 'STATE_PUT_FAILED' | 'DEEP_LINKING_RESPONSE_PUT_FAILED'): Promise<void> {
    try {
      await this.store.put(key, value, expiresAt);
    } catch {
      this.report(diagnostic, 'STORE_ERROR');
      throw new LtiError('STORE_ERROR', 'store:put');
    }
  }

  private async take(key: string,
    diagnostic: 'STATE_TAKE_FAILED' | 'DEEP_LINKING_RESPONSE_TAKE_FAILED'): Promise<string | undefined> {
    try {
      return await this.store.take(key);
    } catch {
      this.report(diagnostic, 'STORE_ERROR');
      throw new LtiError('STORE_ERROR', 'store:take');
    }
  }
}
