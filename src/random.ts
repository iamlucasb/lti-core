import { base64url } from 'jose';

/** Returns `bytes` cryptographically random bytes, base64url-encoded without padding. */
export function randomToken(bytes = 32): string {
  return base64url.encode(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}
