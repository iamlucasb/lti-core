const identifierPattern = /^[\x00-\x7F]+$/;
const uriPattern = /^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]*$/;
const httpsUrlPrefix = /^https:\/\//i;

export function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

export function isLtiIdentifier(value: unknown): value is string {
  return nonEmpty(value) && value.length <= 255 && identifierPattern.test(value);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function parseUri(value: unknown): URL | undefined {
  if (!nonEmpty(value) || !uriPattern.test(value) || /%(?![0-9A-Fa-f]{2})/.test(value)) return undefined;
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

export function parseHttpsUrl(value: unknown): URL | undefined {
  if (typeof value !== 'string' || !httpsUrlPrefix.test(value)) return undefined;
  const url = parseUri(value);
  return url?.protocol === 'https:' ? url : undefined;
}

export function isUri(value: unknown): value is string {
  return parseUri(value) !== undefined;
}
