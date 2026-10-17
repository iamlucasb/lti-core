import { SignJWT } from 'jose';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';

interface LaunchFixture {
  privateKey: CryptoKey;
  kid: string;
  issuer: string;
  audience: string;
  subject: string;
  nonce: string;
  deploymentId: string;
  targetLinkUri: string;
  resourceLinkId: string;
  roles: string[];
  changes?: Record<string, unknown>;
  algorithm?: string;
}

export async function signLaunch(fixture: LaunchFixture): Promise<string> {
  const { privateKey, kid, issuer, audience, subject, nonce, deploymentId,
    targetLinkUri, resourceLinkId, roles, changes, algorithm = 'RS256' } = fixture;
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: issuer, aud: audience, sub: subject, iat: now, exp: now + 300, nonce,
    [claim + 'version']: '1.3.0', [claim + 'message_type']: 'LtiResourceLinkRequest',
    [claim + 'deployment_id']: deploymentId, [claim + 'target_link_uri']: targetLinkUri,
    [claim + 'resource_link']: { id: resourceLinkId }, [claim + 'roles']: roles,
    ...changes,
  }).setProtectedHeader({ alg: algorithm, kid }).sign(privateKey);
}
