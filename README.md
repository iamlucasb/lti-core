# lti-core

Framework-agnostic TypeScript library for building LTI 1.3 tools: OIDC launch, Resource Link, Deep Linking 2.0 and tool JWKS.

[![CI](https://github.com/iamlucasb/lti-core/actions/workflows/ci.yml/badge.svg)](https://github.com/iamlucasb/lti-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/lti-core)](https://www.npmjs.com/package/lti-core)
[![license](https://img.shields.io/npm/l/lti-core)](LICENSE)

## Why

- **Framework-agnostic.** No routes, middleware or sessions: two async functions (`initiate`, `validate`) that take plain objects and return plain objects. Use it with Express, Fastify, Hono, Next.js or a bare `Request`/`Response` handler.
- **Storage-agnostic.** Single-use `state`, `nonce` and Deep Linking response tokens go through a two-method `OneTimeStore` port (`put`, `take`) that you implement on Redis, PostgreSQL or anything with an atomic delete-and-return.
- **Strict where it matters, tolerant where it does not.** Signature, issuer, audience, expiry, `state`, `nonce`, deployment, target, `sub` and roles are validated strictly and fail closed. Descriptive claims (names, locale, titles, presentation, custom parameters) that a platform sends with the wrong type are normalized or dropped instead of rejecting the whole launch.
- **Single runtime dependency:** [`jose`](https://github.com/panva/jose). No `node:crypto` or `Buffer` in the library: it relies on Web Crypto.
- **Typed, discriminated results.** `validate` returns a union discriminated by `messageType`; errors are a single `LtiError` with a stable `code` and a machine-readable `reason`.
- **No user model.** The library returns the LTI identity (`issuer`, `clientId`, `sub`) and the raw signed roles. Mapping them to your users and permissions stays in your application.

## Scope

Supported:

- LTI 1.3 Core: OIDC third-party initiation and launch validation for `LtiResourceLinkRequest`;
- LTI Deep Linking 2.0: `LtiDeepLinkingRequest` validation and signed `LtiDeepLinkingResponse`, with `ltiResourceLink` Content Items;
- platform keys resolved from their JWKS URL, with key rotation; tool keys provided by your application and published as a JWKS;
- a platform JWKS check before a first launch (`inspectPlatformJwks`);
- a fake platform for your tests (`lti-core/testing`);
- RS256 only.

Not supported (non-goals for now):

- Assignment and Grade Services (AGS), Names and Role Provisioning Services (NRPS), Dynamic Registration;
- Content Item types other than `ltiResourceLink`;
- the platform (LMS) side of LTI, beyond the fake platform of `lti-core/testing`;
- LTI 1.1.

Claims the library does not interpret (AGS and NRPS endpoints, `tool_platform`, vendor extensions...) remain available, signed but not validated, in `launch.claims`.

## Install

```sh
npm install lti-core
```

Requires Node.js 20 or later. The package is ESM only. It is designed to be runtime-agnostic (Web Crypto, `fetch`), but only Node.js >= 20 is officially supported and tested.

## Quick start

The example uses Web-standard `Request`/`Response` handlers; adapt the two handlers to your HTTP framework.

```ts
import { createLtiTool, LtiError, MemoryOneTimeStore } from 'lti-core';
import type { Registration } from 'lti-core';

const registrations: Registration[] = [{
  issuer: 'https://platform.example',
  clientId: 'tool-client-id',
  authorizationEndpoint: 'https://platform.example/lti/auth',
  jwksUri: 'https://platform.example/lti/jwks',
  deployments: ['deployment-1'],
  allowedTargetLinkUris: ['https://tool.example/lti/launch'],
}];

const tool = createLtiTool({
  resolver: {
    async resolve(issuer) {
      return registrations.filter(registration => registration.issuer === issuer);
    },
  },
  redirectUri: 'https://tool.example/lti/launch',
  store: new MemoryOneTimeStore(), // development only, see "Production checklist"
});

// GET or POST /lti/login: OIDC third-party initiation sent by the platform.
async function login(request: Request): Promise<Response> {
  const params = request.method === 'POST'
    ? new URLSearchParams(await request.text())
    : new URL(request.url).searchParams;
  const { url, state } = await tool.initiate(Object.fromEntries(params));
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      // Bind the attempt to this browser; checked when the platform posts the id_token back.
      'Set-Cookie': `lti_state=${state}; Path=/lti; Max-Age=300; HttpOnly; Secure; SameSite=None`,
    },
  });
}

// POST /lti/launch: the platform posts `state` and `id_token` (form_post).
async function handleLaunch(request: Request): Promise<Response> {
  const form = await request.formData();
  const state = form.get('state');
  if (typeof state !== 'string' || readCookie(request, 'lti_state') !== state) {
    return new Response('Launch session not found', { status: 401 });
  }
  try {
    const launch = await tool.validate({ state, id_token: form.get('id_token') });
    switch (launch.messageType) {
      case 'LtiResourceLinkRequest':
        // launch.platform, launch.user.id, launch.resourceLink.id, launch.roles, launch.custom...
        return startSession(launch);
      case 'LtiDeepLinkingRequest':
        // launch.deepLinking: settings and the single-use responseToken.
        return showContentPicker(launch);
    }
  } catch (error) {
    if (error instanceof LtiError) {
      log.warn({ code: error.code, reason: error.reason });
      return new Response('LTI launch failed', { status: 401 });
    }
    throw error;
  }
}

function readCookie(request: Request, name: string): string | undefined {
  const cookie = request.headers.get('cookie')?.split(/;\s*/).find(entry => entry.startsWith(`${name}=`));
  return cookie?.slice(name.length + 1);
}
```

`startSession`, `showContentPicker` and `log` belong to your application. The LTI identity of the user is the triple `launch.platform.issuer`, `launch.platform.clientId`, `launch.user.id`; `sub` alone is not a global identity.

## Deep Linking

Configure `toolKeys` (an RSA private key provided by your application, with a `kid`) to answer deep linking requests and publish the tool's JWKS:

```ts
import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

const tool = createLtiTool({
  resolver,
  store,
  redirectUri: 'https://tool.example/lti/launch',
  toolKeys: {
    signing: { kid: 'tool-2026-01', privateKey: createPrivateKey(readFileSync('tool-private-key.pem', 'utf8')) },
  },
});

// GET /.well-known/jwks.json: register this URL as the tool's public keyset in the platform.
const jwks = () => Response.json(tool.jwks());

// On the LtiDeepLinkingRequest branch, once the user has picked content:
const { returnUrl, jwt } = await tool.createDeepLinkingResponse(launch.deepLinking.responseToken, [
  { type: 'ltiResourceLink', title: 'Chapter 1', custom: { chapter: '1' } },
]);
// POST `jwt` as the `JWT` form field to `returnUrl` (auto-submitted HTML form).
```

The library never decides who may configure content: check `launch.normalizedRoles` (or `launch.roles`) against your own policy before showing the content picker. Private keys can also be given as a private RSA JWK or a Web Crypto `CryptoKey`; see the [integration guide](docs/integration.md#deep-linking).

## Testing

`lti-core/testing` provides a fake LTI 1.3 platform for your tests: it serves its JWKS through a `fetch` stub, signs launches and deep linking requests, and reads your Deep Linking responses as a platform would. Platform behaviors are options, for example `deploymentId: null` for a platform that omits `deployment_id`.

```ts
import { createTestPlatform } from 'lti-core/testing';

const platform = await createTestPlatform({ targetLinkUri: 'https://tool.example/lti/launch' });
const restoreFetch = platform.installFetch();
// resolver: issuer === platform.issuer ? [platform.registration()] : []
const { url } = await tool.initiate(platform.loginRequest());
const launch = await tool.validate(await platform.authorize(url, { subject: 'user-17' }));
```

See [Testing with a fake platform](docs/integration.md#testing-with-a-fake-platform).

## Production checklist

- **Use a shared, atomic `OneTimeStore`.** `MemoryOneTimeStore` only works within a single process. In production, `put` must be create-only with an expiry and `take` must atomically delete and return, across all instances:
  - Redis: `SET key value NX PXAT expiresAt` to put, `GETDEL key` to take;
  - PostgreSQL: an insert that refuses live keys to put, `DELETE ... WHERE key = $1 RETURNING value` to take.

  Eventually consistent key-value stores (for example Cloudflare Workers KV) are **not** suitable: they cannot guarantee single use. See the [store contract and adapters](docs/integration.md#one-time-store).
- **Bind `state` to the browser session.** `initiate` returns the `state`; store it (for example in an `HttpOnly`, `Secure` cookie) and compare it with the `state` posted back before calling `validate`. The library's store prevents replay; it does not replace this CSRF binding.
- **Keep the tool key stable** across restarts and instances: platforms cache the tool's JWKS.
- **Check each platform JWKS** before the first launch with `inspectPlatformJwks(registration.jwksUri)`.
- **Keep one `LtiTool` instance** per process: it caches platform JWKS key sets.
- **Rate limit the login and launch endpoints.** Each initiation writes to your store, and a token with an unknown `kid` can trigger a JWKS request to the platform.
- **Handle errors by `code` and `reason`**, log them, and show the user a generic message. `LtiError` never contains values, keys, tokens, `state` or `nonce`, but there is no reason to expose details to the browser.
- **Mind third-party cookies.** Platforms often launch tools in an iframe, where browsers increasingly block third-party cookies: a cookie set during initiation may not come back with the launch. Prefer opening the tool in a new window (document target `window`), or use your own state binding strategy that works in your context.
- **Authorize Deep Linking yourself**: a valid deep linking request may carry no instructor role.

## Platform compatibility

`lti-core` follows the 1EdTech specifications and is covered by spec-based tests that sign real tokens and serve JWKS over a local HTTPS server.

It has been used in production with **Dokeos**, which omits the `deployment_id` claim (declare `deploymentIdRequired: false` on its registration), and sends integer identifiers and `null` optional claims (accepted by the tolerance policy).

Other platforms (Moodle, Canvas, Blackboard, Brightspace, Sakai, Schoology...) are covered by spec-based tests only. Reports of successful or failed integrations are very welcome: please [open an issue](https://github.com/iamlucasb/lti-core/issues).

This project is not certified by 1EdTech. LTI® is a trademark of 1EdTech Consortium, Inc.

## Documentation

- [Integration guide](docs/integration.md): configuration reference, store contract, launch shape, tolerance policy, roles, Deep Linking, tool keys, platform JWKS check, testing, errors, migration guides
- [Changelog](CHANGELOG.md)
- [Glossary](CONTEXT.md)
- Architecture decisions: [LTI identity](docs/adr/0001-lti-identity-scope.md), [optional `deployment_id`](docs/adr/0002-optional-deployment-id.md), [Deep Linking response token](docs/adr/0003-deep-linking-response-token.md), [testing entry point](docs/adr/0004-testing-entry-point.md), [architecture review](docs/architecture-review.md)
- [Security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md)

## Development

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run build
npm run check:package
```

`prepack` rebuilds `dist` before `npm pack` or `npm publish`.

## License

[MIT](LICENSE) © [Lucas Bossard](https://lucasbossard.com)
