import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:https';
import type { Server } from 'node:https';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair } from 'jose';
import { createLtiTool, MemoryOneTimeStore } from '../src/index.js';
import type { LtiLaunch } from '../src/index.js';
import { asDeepLinking, asResourceLink } from './fixtures/launch-kind.js';
import { signLaunch } from './fixtures/sign-launch.js';
import { tlsOptions } from './fixtures/tls.js';

const claim = 'https://purl.imsglobal.org/spec/lti/claim/';
const issuer = 'https://platform.example';
const target = 'https://tool.example/launch';
const learner = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
const toolKey = generateKeyPairSync('rsa', { modulusLength: 2048 });
let jwksUri: string;
let privateKey: CryptoKey;
let server: Server;

before(async () => {
  const keys = await generateKeyPair('RS256', { extractable: true });
  privateKey = keys.privateKey;
  const publicJwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
  server = createServer(tlsOptions, (_request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ keys: [publicJwk] }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  jwksUri = `https://127.0.0.1:${address.port}/keys`;
});
after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

async function launch(changes: Record<string, unknown> = {}): Promise<LtiLaunch> {
  const lti = createLtiTool({
    resolver: { async resolve(iss: string) { return iss === issuer ? [{ issuer, clientId: 'client-1',
      authorizationEndpoint: 'https://platform.example/authorize', jwksUri,
      deployments: ['deployment-1'], allowedTargetLinkUris: [target] }] : []; } },
    redirectUri: 'https://tool.example/callback', store: new MemoryOneTimeStore(),
    toolKeys: { signing: { kid: 'tool-key', privateKey: toolKey.privateKey } },
  });
  const url = new URL((await lti.initiate({ iss: issuer, login_hint: 'hint', target_link_uri: target })).url);
  return lti.validate({ state: url.searchParams.get('state'),
    id_token: await signLaunch({ privateKey, kid: 'test-key', issuer, audience: 'client-1', subject: 'user-17',
      nonce: url.searchParams.get('nonce')!, deploymentId: 'deployment-1', targetLinkUri: target,
      resourceLinkId: 'resource-42', roles: [learner], changes }) });
}

test('POSIX-style locales are normalized to BCP 47 language tags', async () => {
  for (const [raw, expected] of [['pt_br', 'pt-br'], ['en_US', 'en-US'], ['zh_cn', 'zh-cn'], ['fr', 'fr']]) {
    const context = await launch({ locale: raw, [claim + 'launch_presentation']: { locale: raw } });
    assert.equal(context.user.locale, expected, raw);
    assert.equal(context.launchPresentation?.locale, expected, raw);
  }
});

test('an invalid or mistyped locale is dropped without rejecting the launch', async () => {
  for (const locale of ['not a language', '', '_', 'en__us', 42, true, ['fr'], { tag: 'fr' }]) {
    const context = await launch({ locale, [claim + 'launch_presentation']: { locale, width: 800 } });
    assert.deepEqual(context.user, { id: 'user-17' }, JSON.stringify(locale));
    assert.deepEqual(context.launchPresentation, { width: 800 }, JSON.stringify(locale));
  }
});

test('deprecated simple context role names are normalized and kept verbatim', async () => {
  const names = ['Administrator', 'ContentDeveloper', 'Instructor', 'Learner', 'Mentor', 'Manager', 'Member',
    'Officer'];
  const context = await launch({ [claim + 'roles']: names });
  assert.deepEqual(context.roles, names);
  assert.deepEqual(context.normalizedRoles, names.map(name => 'membership:' + name));
});

test('LIS v1 role URNs are normalized to their LIS v2 equivalents', async () => {
  const roles = [
    'urn:lti:role:ims/lis/Instructor', 'urn:lti:role:ims/lis/Instructor/TeachingAssistant',
    'urn:lti:instrole:ims/lis/Student', 'urn:lti:instrole:ims/lis/Faculty',
    'urn:lti:sysrole:ims/lis/SysAdmin', 'urn:lti:sysrole:ims/lis/User',
    'urn:lti:role:ims/lis/TeachingAssistant', 'urn:lti:instrole:ims/lis/Unknown',
  ];
  const context = await launch({ [claim + 'roles']: roles });
  assert.deepEqual(context.roles, roles);
  assert.deepEqual(context.normalizedRoles, ['membership:Instructor', 'membership:Instructor/TeachingAssistant',
    'institution:Student', 'institution:Faculty', 'system:SysAdmin', 'system:User']);
});

test('equivalent role aliases yield one normalized role', async () => {
  const roles = [learner, 'Learner', 'urn:lti:role:ims/lis/Learner'];
  const context = await launch({ [claim + 'roles']: roles });
  assert.deepEqual(context.roles, roles);
  assert.deepEqual(context.normalizedRoles, ['membership:Learner']);
});

test('unknown and malformed roles are kept verbatim without rejecting the launch', async () => {
  const unknown = ['urn:vendor:unrecognized-role', 'not a URI', 'https://vendor.example/role with space',
    'https://vendor.example/role\u0000suffix', 'urn:vendor:rôle', 'urn:vendor:%zz', 'instructor', ''];
  const alone = await launch({ [claim + 'roles']: unknown });
  assert.deepEqual(alone.roles, unknown);
  assert.deepEqual(alone.normalizedRoles, []);
  const mixed = await launch({ [claim + 'roles']: [learner, ...unknown] });
  assert.deepEqual(mixed.roles, [learner, ...unknown]);
  assert.deepEqual(mixed.normalizedRoles, ['membership:Learner']);
});

test('non-string role entries are dropped', async () => {
  const context = await launch({ [claim + 'roles']: ['role', 42, null, { role: learner }, [learner], learner] });
  assert.deepEqual(context.roles, ['role', learner]);
  assert.deepEqual(context.normalizedRoles, ['membership:Learner']);
});

test('a resource link launch still requires a roles array', async () => {
  for (const roles of [undefined, null, learner, 42, { 0: learner }]) {
    await assert.rejects(launch({ [claim + 'roles']: roles }), { code: 'INVALID_CLAIMS' }, JSON.stringify(roles));
  }
});

test('scalar custom parameters are converted to strings and structured values dropped', async () => {
  const context = await launch({ [claim + 'custom']: {
    text: 'value', empty: '', count: 3, ratio: 1.5, negative: -2, enabled: true, disabled: false,
    absent: null, nested: { a: 1 }, list: ['a'], unsafe: 2 ** 53 + 2,
  } });
  assert.deepEqual(context.custom, { text: 'value', empty: '', count: '3', ratio: '1.5', negative: '-2',
    enabled: 'true', disabled: 'false' });
});

test('a custom or launch_presentation claim that is not an object is dropped', async () => {
  for (const value of ['text', 42, true, ['a']]) {
    const context = await launch({ [claim + 'custom']: value, [claim + 'launch_presentation']: value });
    assert.equal('custom' in context, false, JSON.stringify(value));
    assert.equal('launchPresentation' in context, false, JSON.stringify(value));
  }
});

test('mistyped presentation dimensions and document target are dropped', async () => {
  for (const value of ['800', true, [800], { px: 800 }]) {
    const context = await launch({ [claim + 'launch_presentation']: {
      width: value, height: value, document_target: value, return_url: 'https://platform.example/return' } });
    assert.deepEqual(context.launchPresentation, { returnUrl: 'https://platform.example/return' },
      JSON.stringify(value));
  }
});

test('mistyped optional text claims are dropped', async () => {
  for (const value of [42, true, ['text'], { text: 'text' }]) {
    const context = asResourceLink(await launch({
      name: value, given_name: value, family_name: value, email: value,
      [claim + 'resource_link']: { id: 'resource-42', title: value, description: value },
      [claim + 'context']: { id: 'course-7', label: value, title: value },
    }));
    assert.deepEqual(context.user, { id: 'user-17' }, JSON.stringify(value));
    assert.deepEqual(context.resourceLink, { id: 'resource-42' }, JSON.stringify(value));
    assert.deepEqual(context.context, { id: 'course-7' }, JSON.stringify(value));
  }
});

test('identifiers and security claims stay strict next to tolerant descriptive claims', async () => {
  const tolerated = { locale: 'not a language', name: 42, [claim + 'roles']: ['unknown', 42],
    [claim + 'custom']: { nested: {} }, [claim + 'launch_presentation']: { return_url: 'http://insecure' } };
  for (const [changes, code] of [
    [{ [claim + 'resource_link']: { id: 'resource-42', title: 'T' } }, undefined],
    [{ [claim + 'resource_link']: { title: 'missing id' } }, 'INVALID_CLAIMS'],
    [{ [claim + 'resource_link']: { id: 4.2 } }, 'INVALID_CLAIMS'],
    [{ [claim + 'resource_link']: 'resource-42' }, 'INVALID_CLAIMS'],
    [{ [claim + 'context']: { id: 4.2, title: 'T' } }, 'INVALID_CLAIMS'],
    [{ [claim + 'context']: { label: 'no id' } }, 'INVALID_CLAIMS'],
    [{ [claim + 'context']: 'course-7' }, 'INVALID_CLAIMS'],
    [{ sub: 42 }, 'INVALID_CLAIMS'],
    [{ [claim + 'version']: '1.2.0' }, 'INVALID_CLAIMS'],
    [{ [claim + 'message_type']: 'LtiUnknownRequest' }, 'INVALID_CLAIMS'],
    [{ [claim + 'target_link_uri']: 'https://evil.example/launch' }, 'INVALID_CLAIMS'],
    [{ [claim + 'deployment_id']: 'other' }, 'INVALID_DEPLOYMENT'],
    [{ iss: 'https://alien.example' }, 'INVALID_ISSUER'],
    [{ aud: 'alien' }, 'INVALID_AUDIENCE'],
  ] as const) {
    const result = launch({ ...tolerated, ...changes });
    if (code === undefined) await result;
    else await assert.rejects(result, { code }, JSON.stringify(changes));
  }
});

test('the verified payload is exposed as a frozen copy on both launch types', async () => {
  const lis = { person_sourcedid: 'sis-17' };
  const resource = asResourceLink(await launch({ [claim + 'lis']: lis,
    'https://vendor.example/claim': { extra: [1, 2] }, [claim + 'custom']: { nested: { kept: true } } }));
  assert.equal(Object.isFrozen(resource.claims), true);
  assert.equal(resource.claims.iss, issuer);
  assert.equal(resource.claims.sub, 'user-17');
  assert.deepEqual(resource.claims[claim + 'lis'], lis);
  assert.deepEqual(resource.claims['https://vendor.example/claim'], { extra: [1, 2] });
  assert.deepEqual(resource.claims[claim + 'custom'], { nested: { kept: true } });
  assert.deepEqual(resource.custom, {});

  const deepLinking = asDeepLinking(await launch({
    [claim + 'message_type']: 'LtiDeepLinkingRequest', [claim + 'resource_link']: undefined,
    'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings': {
      deep_link_return_url: 'https://platform.example/deep_links', accept_types: ['ltiResourceLink'],
      accept_presentation_document_targets: ['iframe'] },
  }));
  assert.equal(Object.isFrozen(deepLinking.claims), true);
  assert.equal(deepLinking.claims[claim + 'message_type'], 'LtiDeepLinkingRequest');
  assert.equal(deepLinking.claims.sub, 'user-17');
});
