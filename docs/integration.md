# Integration guide

This document is the consumer contract of `lti-core`: what the library does, what your application must provide, and the exact shape of every input, result and error. The library creates no routes, sessions or application users.

- [Responsibilities](#responsibilities)
- [Requirements](#requirements)
- [Creating the tool](#creating-the-tool)
- [Registrations](#registrations)
- [OIDC initiation](#oidc-initiation)
- [One-time store](#one-time-store)
- [Launch validation](#launch-validation)
- [Returned launch](#returned-launch)
- [Claim tolerance policy](#claim-tolerance-policy)
- [Roles](#roles)
- [Deep Linking](#deep-linking)
- [Errors](#errors)
- [Diagnostics](#diagnostics)
- [Migration guides](#migration-guides)
- [References](#references)

## Responsibilities

Your application provides:

- the LTI registrations, through a `RegistrationResolver`;
- a shared single-use store, through a `OneTimeStore`;
- the OIDC initiation route and the `form_post` launch route;
- the binding of `state` to the browser session;
- the association of the LTI identity and context with its own users and business objects;
- the authorization decision based on LTI roles;
- for Deep Linking: the tool's private key, the route that serves its JWKS, the content selection screen and the form that posts the response back to the platform.

The library handles:

- building the authorization redirect;
- generating and consuming, once, `state` and `nonce`;
- JWT verification against the platform's JWKS, with caching and key rotation;
- validation of Resource Link launches and Deep Linking 2.0 requests;
- building and signing Deep Linking responses;
- publishing the tool's public JWKS;
- normalizing errors, diagnostics and recognized roles.

It makes the outbound HTTPS requests needed to fetch the platforms' JWKS. It accepts no inbound HTTP request by itself.

## Requirements

- Node.js 20 or later (`engines: >=20`), tested on Node.js 20, 22 and 24.
- ESM only: `import { createLtiTool } from 'lti-core'`.
- One runtime dependency: `jose`.

The library uses Web Crypto and `fetch` and never imports `node:crypto` or uses `Buffer`. It is designed to be runtime-agnostic, but only Node.js >= 20 is officially supported; Cloudflare Workers, Deno and Bun are not tested yet.

## Creating the tool

```ts
import { createLtiTool } from 'lti-core';

const tool = createLtiTool({
  resolver,
  store,
  redirectUri: 'https://tool.example/lti/launch',
  onDiagnostic(diagnostic) {
    log.error({ lti: diagnostic.code, errorCode: diagnostic.errorCode });
  },
  toolKeys, // optional: only needed for Deep Linking responses and the tool JWKS
  deepLinkingResponseLifetimeMs: 60 * 60_000,
  clockToleranceSeconds: 5,
  jwks: { timeoutMs: 5_000, cooldownMs: 30_000, cacheMaxAgeMs: 10 * 60_000 },
});
```

Create one instance per process and keep it: it holds the JWKS key set cache. `createLtiTool` validates the whole configuration synchronously and throws `LtiError('INVALID_CONFIGURATION', 'config:<option>')` naming the invalid option.

### Configuration reference

| Option | Type | Default | Constraints and meaning |
| --- | --- | --- | --- |
| `resolver` | `RegistrationResolver` | required | Object with a `resolve(issuer)` function. See [Registrations](#registrations). |
| `redirectUri` | `string` | required | Absolute HTTPS URL without fragment, where the platform posts the `id_token`. A registration's `redirectUri` overrides it. |
| `store` | `OneTimeStore` | required | Object with `put` and `take` functions; must be shared by all instances. See [One-time store](#one-time-store). |
| `onDiagnostic` | `(diagnostic: LtiDiagnostic) => void` | none | Receives normalized operational failures. Exceptions it throws are ignored. See [Diagnostics](#diagnostics). |
| `toolKeys` | `ToolKeys` | none | Tool signing key and rotation keys. Required for `createDeepLinkingResponse` and `jwks()`. See [Tool keys and JWKS](#tool-keys-and-jwks). |
| `deepLinkingResponseLifetimeMs` | `number` | `3600000` (one hour) | Positive integer. How long a deep linking `responseToken` stays usable. |
| `clockToleranceSeconds` | `number` | `5` | Integer from `0` to `300`. Allowed clock skew with platforms, applied to `exp`, `nbf` and `iat`. The upper bound catches a value given in milliseconds by mistake. |
| `jwks.timeoutMs` | `number` | `5000` | Positive integer. Timeout of a platform JWKS request. |
| `jwks.cooldownMs` | `number` | `30000` | Non-negative integer. Minimum delay after a JWKS fetch before a token with an unknown `kid` triggers a new fetch. `0` refetches immediately. |
| `jwks.cacheMaxAgeMs` | `number` | `600000` (ten minutes) | Integer, at least `1`. Age after which cached keys are fetched again, even for a known `kid`. |

All numeric options must be safe integers. `jwks`, when present, must be an object.

## Registrations

```ts
interface Registration {
  readonly issuer: string;
  readonly clientId: string;
  readonly authorizationEndpoint: string;
  readonly jwksUri: string;
  readonly deployments: readonly string[];
  readonly allowedTargetLinkUris: readonly string[];
  readonly deploymentIdRequired?: boolean; // defaults to true
  readonly redirectUri?: string; // overrides the tool's redirectUri for this registration
}

interface RegistrationResolver {
  resolve(issuer: string): Promise<readonly Registration[]>;
}
```

A registration is the relationship between a platform (`issuer`) and the tool (`clientId`); see the [glossary](../CONTEXT.md). The resolver returns every registration of the requested issuer, or an empty array. It is called on every initiation, launch and Deep Linking response: nothing is cached, so a revoked registration stops working immediately. Cache in your resolver if needed.

Every returned registration is validated before use; one invalid registration makes the whole call fail with `INVALID_CONFIGURATION` (`registration:invalid`) and a `REGISTRATION_INVALID` diagnostic. A resolver that throws or does not return an array fails with `INVALID_CONFIGURATION` (`registration:resolution_failed`) and a `REGISTRATION_RESOLUTION_FAILED` diagnostic.

Constraints:

- `issuer`, `authorizationEndpoint` and `jwksUri` are absolute HTTPS URLs;
- `issuer` equals the requested issuer and has no query, fragment or embedded credentials;
- `authorizationEndpoint` has no fragment;
- `clientId` is a non-empty string;
- `deployments` is an array of LTI identifiers (non-empty ASCII strings of at most 255 characters);
- `allowedTargetLinkUris` contains absolute HTTPS URLs without fragment; the launch target must match one of them exactly;
- `deploymentIdRequired`, when present, is a boolean;
- `redirectUri`, when present, is an absolute HTTPS URL without fragment, registered with the platform for this client.

### Registration selection at initiation

At initiation, the library selects the single registration compatible with:

1. `iss`;
2. the optional `client_id`;
3. `target_link_uri`, which must be in `allowedTargetLinkUris`;
4. the optional `lti_deployment_id`, which must be in `deployments` (or be any LTI identifier when the registration has `deploymentIdRequired: false` and an empty `deployments` list).

No match fails with `INVALID_LOGIN` (`registration:not_found`), `INVALID_TARGET` (`target:not_allowed`) or `INVALID_DEPLOYMENT` (`deployment:unknown`); several matches fail with `INVALID_LOGIN` (`registration:ambiguous`). When an issuer has several registrations, they must be distinguishable by `client_id`, target or deployment hint.

### Platforms without `deployment_id`

LTI 1.3 requires the `deployment_id` claim. Some platforms (for example Dokeos) do not send it. For their registrations only, declare `deploymentIdRequired: false` (see [ADR 0002](adr/0002-optional-deployment-id.md)):

- a launch without the `deployment_id` claim is accepted and `platform.deploymentId` is absent;
- `deployments` may be empty;
- a claim that is present is still validated: an LTI identifier, listed in `deployments` when the list is not empty, and equal to the `lti_deployment_id` received at initiation when there was one;
- at initiation, with an empty `deployments` list, any `lti_deployment_id` that is a valid LTI identifier is accepted; otherwise it must be listed;
- the `lti_deployment_id` hint is not signed and is never exposed as `platform.deploymentId`;
- every other check is unchanged.

Without this option, or with `true`, a launch without `deployment_id` is refused with `INVALID_DEPLOYMENT` (`deployment:missing`).

## OIDC initiation

```ts
const { url, state } = await tool.initiate({
  iss,
  login_hint,
  target_link_uri,
  client_id, // optional
  lti_message_hint, // optional
  lti_deployment_id, // optional
});
```

`initiate` accepts the initiation parameters as received (GET query or POST form); every field is typed `unknown` and validated at runtime. `iss`, `login_hint` and `target_link_uri` are required non-empty strings; `client_id` and `lti_deployment_id`, when present, are strings; an empty value of any of these three optional fields is treated as absent (some platforms send empty optional fields); `lti_message_hint`, when present, is a string. Passing `Object.fromEntries(params)` is fine.

It selects the registration, generates a random `state` and `nonce` (32 bytes each, base64url), stores them for **five minutes**, and returns an `LtiAuthorizationRedirect`:

```ts
interface LtiAuthorizationRedirect {
  readonly url: string; // authorization request to redirect the browser to
  readonly state: string; // also embedded in url
}
```

The authorization request carries `scope=openid`, `response_type=id_token`, `response_mode=form_post`, `prompt=none`, `client_id`, `redirect_uri` (the registration's `redirectUri`, or the tool's), `login_hint`, `state`, `nonce` and, when received, `lti_message_hint`.

Redirect the browser to `url` and bind `state` to the browser session (for example an `HttpOnly`, `Secure`, `SameSite=None` cookie), then compare it with the posted `state` before calling `validate`. The library's store protects the attempt and its nonce against replay; it does not replace this CSRF binding. When launches happen in an iframe, browsers that block third-party cookies may not send that cookie back: prefer opening the tool in a new window, or use a binding strategy that works in your context.

## One-time store

```ts
interface OneTimeStore {
  put(key: string, value: string, expiresAt: number): Promise<void>;
  take(key: string): Promise<string | undefined>;
}
```

The store holds launch attempts (keyed by `state`) and Deep Linking response entries (keyed by `responseToken`). `value` is opaque: store and return it unchanged, without interpreting it.

`put`:

- creates a new key and never overwrites a key that is still live;
- keeps the value until `expiresAt`, in Unix milliseconds;
- throws when a live key already exists.

`take`:

- reads and deletes the value atomically, across all instances sharing the store;
- returns the value to at most one caller, including under concurrent calls;
- returns `undefined` for a missing, expired or already consumed key.

A store that throws is translated into `STORE_ERROR` (`store:put` or `store:take`) with a diagnostic. An entry is consumed by `take` even when the library then finds it unreadable or expired.

`MemoryOneTimeStore` implements this contract in a single process (expired entries are swept every 64 writes). Use it for tests and single-process development only.

**Unsuitable stores:** eventually consistent key-value stores (for example Cloudflare Workers KV) cannot guarantee that two concurrent `take` calls do not both return the value, so they cannot enforce single use. Use a store with an atomic delete-and-return (Redis, PostgreSQL, Durable Objects...).

### Redis adapter

With [node-redis](https://github.com/redis/node-redis) v4 or later (Redis >= 6.2 for `GETDEL`):

```ts
import type { OneTimeStore } from 'lti-core';

export const redisStore: OneTimeStore = {
  async put(key, value, expiresAt) {
    // NX: never overwrite a live entry. PXAT: absolute expiry in Unix milliseconds.
    const created = await redis.set(`lti:${key}`, value, { NX: true, PXAT: expiresAt });
    if (created !== 'OK') throw new Error('One-time key already exists');
  },
  async take(key) {
    // GETDEL reads and deletes atomically: only one concurrent caller gets the value.
    return (await redis.getDel(`lti:${key}`)) ?? undefined;
  },
};
```

### PostgreSQL adapter

With [node-postgres](https://node-postgres.com/) and this table:

```sql
CREATE TABLE lti_one_time (
  key text PRIMARY KEY,
  value text NOT NULL,
  expires_at bigint NOT NULL -- Unix milliseconds
);
```

```ts
import type { OneTimeStore } from 'lti-core';

export const postgresStore: OneTimeStore = {
  async put(key, value, expiresAt) {
    // Creates the key, or replaces it only if the existing entry has already expired.
    const result = await pool.query(
      `INSERT INTO lti_one_time (key, value, expires_at) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
       WHERE lti_one_time.expires_at <= $4`,
      [key, value, expiresAt, Date.now()]);
    if (result.rowCount !== 1) throw new Error('One-time key already exists');
  },
  async take(key) {
    // DELETE ... RETURNING is atomic: concurrent calls cannot both return the row.
    const result = await pool.query(
      'DELETE FROM lti_one_time WHERE key = $1 RETURNING value, expires_at > $2 AS live',
      [key, Date.now()]);
    const row = result.rows[0];
    return row !== undefined && row.live === true && typeof row.value === 'string' ? row.value : undefined;
  },
};
```

Delete expired rows periodically, for example `DELETE FROM lti_one_time WHERE expires_at <= $1` with `Date.now()`.

## Launch validation

After checking that the posted `state` matches the one bound to the browser session:

```ts
const launch = await tool.validate({ state: form.get('state'), id_token: form.get('id_token') });

switch (launch.messageType) {
  case 'LtiResourceLinkRequest':
    // launch.resourceLink is available.
    break;
  case 'LtiDeepLinkingRequest':
    // launch.deepLinking is available; see "Deep Linking".
    break;
}
```

`validate` accepts both message types on the same route. Any other `message_type` is refused with `INVALID_CLAIMS` (`claim:message_type`). The result is a union discriminated by `messageType`: TypeScript requires checking it before reading `resourceLink` or `deepLinking`.

The `state` is consumed **before** the token is checked, so an attempt can never be replayed, even after a failure.

### Checks

In order:

1. `state` is a non-empty string that matches a live attempt (`INVALID_STATE`);
2. `id_token` is a non-empty string (`INVALID_TOKEN`, `token:missing`);
3. the registration of the attempt still exists and still allows the target (`INVALID_CONFIGURATION`, `INVALID_TARGET`);
4. the JWT is verified with `jose` against the registration's JWKS: RS256 only, signature, `iss`, `aud`, `exp`, `nbf` (when present) and the presence of `exp`, `iat`, `sub` and `nonce`;
5. the header has a `kid`; `iss` equals the registration issuer; every `aud` entry equals the client ID (an additional audience is refused even when `azp` matches); `azp`, when present or when `aud` has several entries, equals the client ID; `iat` is not in the future beyond the clock tolerance; `nonce` equals the stored nonce;
6. `deployment_id` (see [Registrations](#platforms-without-deployment_id)), LTI `version` `1.3.0`, `message_type`, signed `target_link_uri` equal to the initiated target, `sub`;
7. the message claims: `resource_link` and `roles` for a resource link launch, `deep_linking_settings` for a deep linking request, then the descriptive claims under the [tolerance policy](#claim-tolerance-policy).

These checks are identical for both message types, except for step 7.

### Platform JWKS fetching and cache

Platform key sets are fetched from `jwksUri` and cached per `LtiTool` instance, per issuer, client ID and JWKS URI:

- a request is aborted after `jwks.timeoutMs`;
- cached keys are fetched again once they are older than `jwks.cacheMaxAgeMs`;
- a token with an unknown `kid` triggers a new fetch, but not before `jwks.cooldownMs` has elapsed since the previous fetch. A platform key rotation can therefore be refused (`JWKS_ERROR`, `jwks:no_matching_key`) for up to `cooldownMs` after the previous fetch; the first launch after that delay fetches the new key set and succeeds. The cooldown bounds the JWKS requests that tokens with forged `kid` values can send to the platform. `cooldownMs: 0` restores an immediate refetch;
- at most 100 key sets are cached, least recently used first out. An evicted key set is simply fetched again on its next use. With more than 100 active registrations, eviction also resets their cooldown: rate limit the launch endpoint.

Each instance fetches independently: several processes fetch the same JWKS once each.

## Returned launch

`validate` returns a read-only `LtiLaunch`:

```ts
type LtiLaunch = LtiResourceLinkLaunch | LtiDeepLinkingLaunch;

interface LtiLaunchBase {
  readonly platform: { readonly issuer: string; readonly clientId: string; readonly deploymentId?: string };
  readonly user: { readonly id: string; readonly name?: string; readonly givenName?: string;
    readonly familyName?: string; readonly email?: string; readonly locale?: string };
  readonly context?: { readonly id: string; readonly label?: string; readonly title?: string;
    readonly type?: readonly string[] };
  readonly launchPresentation?: { readonly documentTarget?: 'frame' | 'iframe' | 'window';
    readonly width?: number; readonly height?: number; readonly returnUrl?: string; readonly locale?: string };
  readonly custom?: Readonly<Record<string, string>>;
  readonly targetLinkUri: string;
  readonly roles: readonly string[];
  readonly normalizedRoles: readonly NormalizedLtiRole[];
  readonly claims: Readonly<Record<string, unknown>>;
}

interface LtiResourceLinkLaunch extends LtiLaunchBase {
  readonly messageType: 'LtiResourceLinkRequest';
  readonly resourceLink: { readonly id: string; readonly title?: string; readonly description?: string };
}

interface LtiDeepLinkingLaunch extends LtiLaunchBase {
  readonly messageType: 'LtiDeepLinkingRequest';
  readonly deepLinking: LtiDeepLinking; // see "Deep Linking"
}
```

| Field | Source claim | Notes |
| --- | --- | --- |
| `platform.issuer`, `platform.clientId` | `iss`, `aud` | From the registration, after verification. |
| `platform.deploymentId` | `deployment_id` | Absent only when the registration declares `deploymentIdRequired: false` and the platform omitted it. |
| `user.id` | `sub` | Raw value. |
| `user.name`, `givenName`, `familyName`, `email` | `name`, `given_name`, `family_name`, `email` | Optional; never required. |
| `user.locale` | `locale` | Normalized BCP 47 tag. |
| `context` | `context` | `id`, `label`, `title`, `type`. |
| `launchPresentation` | `launch_presentation` | `document_target`, `width`, `height`, `return_url`, `locale`. |
| `custom` | `custom` | Values as strings. |
| `resourceLink` | `resource_link` | Resource link launches only. `id` is the platform's identifier. |
| `targetLinkUri` | `target_link_uri` | The allowed target of this launch. |
| `roles`, `normalizedRoles` | `roles` | See [Roles](#roles). |
| `claims` | the whole payload | See below. |

The LTI identity is the triple `issuer`, `clientId`, `sub` ([ADR 0001](adr/0001-lti-identity-scope.md)). The deployment describes the integration of the launch, not the identity. An application that associates business objects with an `issuer`/`clientId`/`deploymentId` integration must plan a fallback for registrations without `deployment_id`. `resourceLink.id`, `context.id` and `custom` values belong to the platform: never use them as your business identifiers without checking them.

### `claims`: the verified payload

`launch.claims` is a shallow-frozen copy of the full verified JWT payload. It is the escape hatch for claims the library does not interpret: AGS and NRPS endpoints, `tool_platform`, `lis`, vendor extensions, `deep_linking_settings.data`...

- Values are signed by the platform but **not validated** by the library: validate them at runtime before use.
- Only the top-level object is frozen; nested objects are not.
- The record may contain an own `"__proto__"` key (JSON payloads can). Read the keys you need; **never deep-merge `claims` into another object**.

```ts
const ags = launch.claims['https://purl.imsglobal.org/spec/lti-ags/claim/endpoint'];
const lineItems = typeof ags === 'object' && ags !== null && 'lineitems' in ags &&
  typeof ags.lineitems === 'string' ? ags.lineitems : undefined;
```

## Claim tolerance policy

Platforms do not always send claims with the types the specification describes. The library applies one rule: **security and identity claims are strict; descriptive claims are normalized or dropped instead of rejecting the launch**. A `null` optional claim is always treated as absent. Claims the library does not read never affect validation.

### Strict claims

A missing or invalid value rejects the launch:

| Claim | Rule | Error |
| --- | --- | --- |
| signature, `kid`, `iss`, `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce` | See [Checks](#checks). | `INVALID_TOKEN`, `INVALID_ISSUER`, `INVALID_AUDIENCE`, `TOKEN_EXPIRED`, `INVALID_NONCE` |
| `sub` | LTI identifier: non-empty ASCII string of at most 255 characters. Required for both message types. | `INVALID_CLAIMS` |
| `deployment_id` | LTI identifier string, known to the registration. | `INVALID_DEPLOYMENT` |
| `version` | Exactly `"1.3.0"`. | `INVALID_CLAIMS` |
| `message_type` | `LtiResourceLinkRequest` or `LtiDeepLinkingRequest`. | `INVALID_CLAIMS` |
| `target_link_uri` | Equal to the initiated target. | `INVALID_CLAIMS` |
| `resource_link` | An object (resource link launches). | `INVALID_CLAIMS` |
| `resource_link.id`, `context.id` | LTI identifier string, or a safe non-negative JSON integer converted to its decimal string (`314` becomes `"314"`). Floats, negative or unsafe integers, booleans, objects and `null` are refused. | `INVALID_CLAIMS` |
| `context` | When present and not `null`: an object with a valid `id`. | `INVALID_CLAIMS` |
| `roles` | Resource link launches: an array (possibly empty). Deep linking requests: absent, `null` or an array. | `INVALID_CLAIMS` |
| `deep_linking_settings` | See [Request](#request). | `INVALID_CLAIMS` |

`sub` and `deployment_id` are never converted from numbers.

### Tolerant claims

| Claim | Kept | Dropped |
| --- | --- | --- |
| `name`, `given_name`, `family_name`, `email` | strings | any other type |
| `locale`, `launch_presentation.locale` | strings that are BCP 47 language tags once `_` is replaced by `-` (`pt_BR` becomes `pt-BR`) | anything else |
| `resource_link.title`, `resource_link.description`, `context.label`, `context.title` | strings (an empty string stays an empty string) | any other type |
| `context.type` | URIs, deduplicated; deprecated short names `CourseTemplate`, `CourseOffering`, `CourseSection`, `Group` become `http://purl.imsglobal.org/vocab/lis/v2/course#<Name>` | entries that are neither URIs nor known short names; the whole field when it is not an array or holds no standard type |
| `launch_presentation` | objects | any other value (`launchPresentation` absent) |
| `launch_presentation.document_target` | `frame`, `iframe`, `window` | any other value |
| `launch_presentation.width`, `height` | finite numbers | any other value |
| `launch_presentation.return_url` | absolute HTTPS URLs | anything else |
| `custom` | objects | any other value (`custom` absent) |
| `custom` entries | strings; booleans and finite numbers converted with `String()` (`true` becomes `"true"`, `42` becomes `"42"`) | integers outside the safe range (their decimal form could merge two values), `null`, objects and arrays |
| `roles` entries | every string, verbatim | non-string entries |

A `launch_presentation` or `custom` object whose members are all dropped is exposed as an empty object. The raw values remain available in `launch.claims`.

## Roles

```ts
readonly roles: readonly string[];
readonly normalizedRoles: readonly NormalizedLtiRole[];
```

- `roles` holds every string entry of the signed `roles` claim, verbatim and in order, recognized or not (unknown, vendor or malformed roles included). Non-string entries are dropped.
- `normalizedRoles` holds the standard roles the library recognizes, without duplicates:

| Signed role | Normalized role |
| --- | --- |
| `http://purl.imsglobal.org/vocab/lis/v2/membership#<Role>` | `membership:<Role>` |
| `http://purl.imsglobal.org/vocab/lis/v2/membership/<Role>#<SubRole>` | `membership:<Role>/<SubRole>` |
| `http://purl.imsglobal.org/vocab/lis/v2/institution/person#<Role>` | `institution:<Role>` |
| `http://purl.imsglobal.org/vocab/lis/v2/system/person#<Role>` | `system:<Role>` |
| `http://purl.imsglobal.org/vocab/lti/system/person#TestUser` | `system:TestUser` |
| deprecated simple context role names: `Administrator`, `ContentDeveloper`, `Instructor`, `Learner`, `Mentor`, `Manager`, `Member`, `Officer` (case-sensitive) | `membership:<Role>` |
| LIS v1 URNs: `urn:lti:role:ims/lis/<Role>`, `urn:lti:role:ims/lis/<Role>/<SubRole>` | `membership:<Role>`, `membership:<Role>/<SubRole>` |
| LIS v1 URNs: `urn:lti:instrole:ims/lis/<Role>` | `institution:<Role>` |
| LIS v1 URNs: `urn:lti:sysrole:ims/lis/<Role>` | `system:<Role>` |

Only roles of the LTI 1.3 vocabularies are recognized (`NormalizedLtiRole` lists them as a TypeScript union); equivalent aliases yield a single normalized role. A launch with only `TestUser`, only unknown roles or an empty array is valid.

**Compare roles exactly; never match them by substring.** Sub-roles can contain the name of another principal role: `membership:Learner/Instructor` (`http://purl.imsglobal.org/vocab/lis/v2/membership/Learner#Instructor`) is a learner sub-role, and `role.includes('Instructor')` would wrongly treat that learner as an instructor.

The library never derives application permissions from roles. Decide your own policy, for example:

```ts
if (launch.messageType === 'LtiDeepLinkingRequest' &&
    !launch.normalizedRoles.some(role => role === 'membership:Instructor' || role === 'membership:ContentDeveloper')) {
  return new Response('Forbidden', { status: 403 });
}
```

## Deep Linking

Deep Linking 2.0 lets the platform ask the tool to select or create content, then receive the Content Items to install. The flow:

1. OIDC initiation and `form_post` launch, as for a resource link launch;
2. `validate` returns the `LtiDeepLinkingRequest` branch;
3. your application authorizes the user and shows its selection screen;
4. `createDeepLinkingResponse` produces the signed JWT;
5. your application posts that JWT back to the platform with a form.

### Request

```ts
interface LtiDeepLinking {
  readonly returnUrl: string; // deep_link_return_url, absolute HTTPS URL
  readonly acceptTypes: readonly string[];
  readonly acceptPresentationDocumentTargets: readonly string[];
  readonly acceptMediaTypes?: string;
  readonly acceptMultiple?: boolean;
  readonly acceptLineItem?: boolean;
  readonly autoCreate?: boolean;
  readonly title?: string;
  readonly text?: string;
  readonly responseToken: string; // opaque, single use
}
```

The `deep_linking_settings` claim is required, with `deep_link_return_url` (absolute HTTPS URL), and non-empty string arrays `accept_types` and `accept_presentation_document_targets`. Unlike descriptive claims, a mistyped optional setting is refused: settings drive the response the platform will accept. A setting set to `null` is treated as absent. No `resource_link` claim is required.

The opaque `data` setting is not exposed in `deepLinking`: the library stores it and echoes it back unchanged in the response. Its raw value is visible in `launch.claims`, which is harmless: the browser already carried the `id_token`, and the response uses the stored copy, never a value supplied by the browser ([ADR 0003](adr/0003-deep-linking-response-token.md)).

`sub` is required, although the 2023 revision of the specification allows it to be absent in a deep linking request: the library does not accept anonymous deep linking. `roles` is optional, as the specification allows: absent or `null`, it yields `[]`; present, it follows the same rules as in a resource link launch.

### Authorization is your application's job

The library never decides who may configure content. A valid deep linking request may have empty roles or no instructor role. **Refuse a deep linking request whose roles do not match your policy** (see [Roles](#roles)). Institution roles (`institution:Instructor`) and sub-roles (`membership:Instructor/TeachingAssistant`) are available in `normalizedRoles` if your policy accepts them.

### Response

```ts
const { returnUrl, jwt } = await tool.createDeepLinkingResponse(launch.deepLinking.responseToken, [
  {
    type: 'ltiResourceLink',
    url: 'https://tool.example/lti/launch', // optional; must be one of allowedTargetLinkUris
    title: 'Chapter 1',
    text: 'Optional description',
    custom: { chapter: '1' }, // string values only
  },
], {
  message: 'Chapter 1 added', // optional: message, log, errorMessage, errorLog
});
```

Only `ltiResourceLink` is supported, with `url`, `title`, `text` and `custom`. Any other property (`icon`, `lineItem`...) is refused. An empty list is allowed: always send the user back to the platform, even when they cancel. The options map to the `msg`, `log`, `errormsg` and `errorlog` claims and must be strings.

The response can only be built from a validated request. `validate` stores in the `OneTimeStore` what is needed to answer (registration, deployment, return URL, `accept_types`, `accept_multiple`, `data`, expiry) and returns `responseToken`, an opaque reference to that entry. The return URL, audience and `data` therefore never come from the browser. Keep the token in your session or in a hidden field of your selection screen.

Order of checks:

1. missing tool keys: `INVALID_CONFIGURATION` (`config:toolKeys_missing`);
2. malformed token (`INVALID_DEEP_LINKING_RESPONSE`, `response_token:malformed`) or unknown registration (`INVALID_CONFIGURATION`): the token is not consumed;
3. item and option shapes (type, properties, string `custom` values, `url` in `allowedTargetLinkUris`): `INVALID_CONTENT_ITEMS`, the token is **not** consumed, so a programming error does not force the user to restart deep linking;
4. token consumption: missing, expired or already used gives `INVALID_DEEP_LINKING_RESPONSE` (`response_token:unknown`);
5. `accept_types` and `accept_multiple` (absent means `false`): `INVALID_CONTENT_ITEMS` (`content_items:accept_types`, `content_items:accept_multiple`), the token **is** consumed. Your application already knows these settings from `launch.deepLinking` and should respect them in its screen;
6. signing: a failure gives `INVALID_CONFIGURATION` (`config:toolKeys`), the token is consumed.

The token lives one hour by default (`deepLinkingResponseLifetimeMs`) and is single use. It is not an authentication secret: it designates a store entry, and its prefix only names the registration.

The signed JWT contains exactly:

- `iss`: the tool's client ID; `aud`: the platform issuer;
- `iat`, `exp` (five minutes later) and a fresh `nonce`;
- `https://purl.imsglobal.org/spec/lti/claim/deployment_id`: from the request, omitted only when the request had none (`deploymentIdRequired: false`, see [ADR 0002](adr/0002-optional-deployment-id.md));
- `message_type` `LtiDeepLinkingResponse` and `version` `1.3.0`;
- `https://purl.imsglobal.org/spec/lti-dl/claim/content_items`;
- `https://purl.imsglobal.org/spec/lti-dl/claim/data`, unchanged, when the request had it;
- `msg`, `log`, `errormsg`, `errorlog` when given.

Its header is `alg: RS256`, `typ: JWT` and the `kid` of the signing key.

The platform replays an item's `custom` values in every resource link launch created from it (`launch.custom`). Like `resourceLink.id`, they are platform values: check them before associating them with a business object.

### Return form

The library only returns `returnUrl` and `jwt`. Your application renders an auto-submitted form that POSTs the `JWT` parameter:

```ts
const escape = (value: string) => value.replace(/[&<>"']/g, character =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!);

const html = `<!doctype html>
<form id="deep-linking" method="post" action="${escape(returnUrl)}">
  <input type="hidden" name="JWT" value="${escape(jwt)}">
  <noscript><button type="submit">Continue</button></noscript>
</form>
<script nonce="${cspNonce}">document.getElementById('deep-linking').submit();</script>`;
```

The page's Content Security Policy must allow `form-action` to the origin of `returnUrl` and the auto-submit script (nonce or hash).

### Tool keys and JWKS

```ts
interface ToolKeys {
  readonly signing:
    | { readonly kid: string; readonly privateKey: CryptoKey; readonly publicJwk: Omit<LtiPublicJwk, 'kid'> }
    | { readonly kid: string; readonly privateKey: LtiPrivateJwk | NodeKeyObjectLike; readonly publicJwk?: never };
  readonly publicKeys?: readonly LtiPublicJwk[]; // { kty: 'RSA', n, e, kid, alg?: 'RS256', use?: 'sig' }
}
```

The signing key is provided by your application: the library never generates or stores keys. It accepts three forms:

- a **Node.js `KeyObject`** (`NodeKeyObjectLike` describes it structurally, so the library does not import `node:crypto`): a private RSA key;
- a **private RSA JWK** (`LtiPrivateJwk`): `kty: 'RSA'` with `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`; multi-prime keys (`oth`) are refused. The library keeps its own copy;
- a **Web Crypto `CryptoKey`**: `RSASSA-PKCS1-v1_5` with `SHA-256` and the `sign` usage, extractable or not. Web Crypto cannot export a key synchronously, so its public JWK (`kty`, `n`, `e`) **must** be given as `publicJwk`; its modulus length and exponent must match the key.

Rules:

- RSA keys have at least 2048 bits; published exponents are odd and at least 3. `alg`, when present, is `RS256`; `use`, when present, is `sig`.
- An invalid configuration is refused by `createLtiTool` with `INVALID_CONFIGURATION` (`config:toolKeys`), without cause or detail. The private key never appears in an error, a diagnostic or an enumerable property of the tool.
- Every signed response is verified against the published signing key before it is returned. A `CryptoKey` whose `publicJwk` belongs to another key therefore fails closed with `INVALID_CONFIGURATION` (`config:toolKeys`) at response time, and the response token is consumed.
- `tool.jwks()` returns `{ keys }`: the public key of the signing key, then `publicKeys`, each with `kid`, `alg: 'RS256'` and `use: 'sig'`. `kid` values must be unique, and a rotation key holding a private member (`d`, `p`, `q`...) is refused. The result is frozen.
- Serve that JSON on a public route, for example `/.well-known/jwks.json`, and declare its URL in the platform.
- Without `toolKeys`, deep linking requests are still validated, but `jwks()` and `createDeepLinkingResponse` throw `INVALID_CONFIGURATION` (`config:toolKeys_missing`).

#### From PEM files

```ts
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { exportJWK, importPKCS8, importSPKI } from 'jose';
import type { LtiPrivateJwk, ToolKeys } from 'lti-core';

const privatePem = readFileSync('tool-private-key.pem', 'utf8'); // PKCS#8 "BEGIN PRIVATE KEY"

// 1. Node.js KeyObject (PKCS#1 "BEGIN RSA PRIVATE KEY" is accepted too).
const fromKeyObject: ToolKeys = {
  signing: { kid: 'tool-2026-01', privateKey: createPrivateKey(privatePem) },
};

// 2. Private RSA JWK; the library validates its members at runtime.
const privateJwk = createPrivateKey(privatePem).export({ format: 'jwk' }) as LtiPrivateJwk;
const fromPrivateJwk: ToolKeys = {
  signing: { kid: 'tool-2026-01', privateKey: privateJwk },
};

// 3. Web Crypto CryptoKey (here through jose, on any runtime): the public JWK must be supplied.
const privateKey = await importPKCS8(privatePem, 'RS256');
const publicPem = readFileSync('tool-public-key.pem', 'utf8'); // SPKI "BEGIN PUBLIC KEY"
const { n, e } = await exportJWK(await importSPKI(publicPem, 'RS256', { extractable: true }));
if (n === undefined || e === undefined) throw new Error('Not an RSA public key');
const fromCryptoKey: ToolKeys = {
  signing: { kid: 'tool-2026-01', privateKey, publicJwk: { kty: 'RSA', n, e } },
};
```

Generate a key pair with, for example, `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out tool-private-key.pem` and `openssl pkey -in tool-private-key.pem -pubout -out tool-public-key.pem`. If a platform asks for a PEM public key instead of a JWKS URL, give it `tool-public-key.pem`, or export it with `createPublicKey(privatePem).export({ type: 'spki', format: 'pem' })` (Node.js) or `exportSPKI` (jose).

#### Rotation

Rotate without interruption:

1. publish the next public key in `publicKeys` and let platforms refresh their cache;
2. switch `signing` to the next key and keep the previous public key in `publicKeys`;
3. remove the previous key once the responses signed with it have expired (five minutes) and platform caches have refreshed.

```ts
const nextPublicJwk = createPublicKey(readFileSync('tool-next-public-key.pem', 'utf8')).export({ format: 'jwk' });
if (nextPublicJwk.n === undefined || nextPublicJwk.e === undefined) throw new Error('Not an RSA public key');
const rotating: ToolKeys = {
  signing: { kid: 'tool-2026-01', privateKey: createPrivateKey(privatePem) },
  publicKeys: [{ kty: 'RSA', n: nextPublicJwk.n, e: nextPublicJwk.e, kid: 'tool-2026-07' }],
};
```

## Errors

Every error thrown by the library is an `LtiError`:

```ts
class LtiError extends Error {
  readonly name: 'LtiError';
  readonly code: LtiErrorCode;
  readonly reason?: LtiErrorReason;
  // message: "CODE" or "CODE: reason"
}
```

- `code` is the stable error category; `reason` is a stable, machine-readable name of the check that failed (for example `claim:resource_link.id`, `config:redirectUri`, `token:kid`). The library sets a `reason` on every error it throws.
- Neither `message` nor `reason` ever contains a value: no key material, token, `state`, `nonce`, claim value, issuer URL or user data. Both are safe to log.
- Dependency errors (jose, network, store, resolver) are translated, never attached as a `cause`.
- Match on `code` and `reason`, never on `message`. Do not send details to the browser.

```ts
try {
  return await tool.validate({ state: form.get('state'), id_token: form.get('id_token') });
} catch (error) {
  if (!(error instanceof LtiError)) throw error;
  log.warn({ code: error.code, reason: error.reason }); // safe to log: no values, keys or tokens
  switch (error.code) {
    case 'INVALID_STATE':
    case 'TOKEN_EXPIRED':
      return new Response('Your launch has expired. Please relaunch from the platform.', { status: 401 });
    case 'JWKS_ERROR':
    case 'STORE_ERROR':
      return new Response('Service temporarily unavailable', { status: 503 });
    default:
      return new Response('LTI launch failed', { status: 401 });
  }
}
```

### Error codes

| Code | Raised by | Meaning |
| --- | --- | --- |
| `INVALID_LOGIN` | `initiate` | Missing or malformed initiation parameter; no or ambiguous registration. |
| `INVALID_TARGET` | `initiate`, `validate` | The target link URI is not allowed by the registration. |
| `INVALID_STATE` | `validate` | Missing, unknown, expired or already consumed `state`. |
| `INVALID_NONCE` | `validate` | Missing `nonce`, or not the one issued at initiation. |
| `INVALID_TOKEN` | `validate` | Missing, malformed or wrongly signed `id_token`; disallowed algorithm; missing `kid`; invalid `iat`, `nbf` or malformed `exp`. |
| `INVALID_ISSUER` | `validate` | `iss` is not the registration issuer. |
| `INVALID_AUDIENCE` | `validate` | `aud` or `azp` is not the tool's client ID. |
| `TOKEN_EXPIRED` | `validate` | `exp` is in the past, beyond the clock tolerance. |
| `INVALID_DEPLOYMENT` | `initiate`, `validate` | Missing, malformed or unknown `deployment_id`, or one that contradicts the initiation hint. |
| `INVALID_CLAIMS` | `validate` | A required LTI claim is missing or invalid. |
| `JWKS_ERROR` | `validate` | The platform JWKS is unreachable, invalid or timed out, or has no key for the token. |
| `STORE_ERROR` | `initiate`, `validate`, `createDeepLinkingResponse` | The `OneTimeStore` threw. |
| `INVALID_CONFIGURATION` | all | Invalid tool configuration, failing resolver, invalid or missing registration, missing or unusable tool keys. |
| `INVALID_CONTENT_ITEMS` | `createDeepLinkingResponse` | Invalid Content Items or options, or items the platform does not accept. |
| `INVALID_DEEP_LINKING_RESPONSE` | `createDeepLinkingResponse` | Malformed, unknown, expired or already used response token. |

### Error reasons

`LtiErrorReason` is a TypeScript union of `family:check` names:

| Family | Codes | Reasons |
| --- | --- | --- |
| `config:` | `INVALID_CONFIGURATION` | `config:invalid` (configuration is not an object or cannot be read), `config:redirectUri`, `config:resolver`, `config:store`, `config:onDiagnostic`, `config:deepLinkingResponseLifetimeMs`, `config:clockToleranceSeconds`, `config:jwks`, `config:toolKeys` (invalid tool keys or signing failure, without detail), `config:toolKeys_missing` |
| `registration:` | `INVALID_LOGIN` at initiation, `INVALID_CONFIGURATION` afterwards | `registration:not_found`, `registration:ambiguous`; with `INVALID_CONFIGURATION` only: `registration:resolution_failed`, `registration:invalid` |
| `login:` | `INVALID_LOGIN` | `login:invalid` (not an object), `login:iss`, `login:login_hint`, `login:target_link_uri`, `login:client_id`, `login:lti_message_hint`, `login:lti_deployment_id` |
| `target:` | `INVALID_TARGET` | `target:not_allowed` |
| `state:` | `INVALID_STATE` | `state:missing`, `state:unknown` (missing, consumed, expired or unreadable in the store) |
| `store:` | `STORE_ERROR` | `store:put`, `store:take` |
| `jwks:` | `JWKS_ERROR` | `jwks:unavailable`, `jwks:no_matching_key` |
| `token:` | `INVALID_TOKEN`, except as noted | `token:missing`, `token:malformed`, `token:alg`, `token:signature`, `token:kid`, `token:exp` (`TOKEN_EXPIRED` when expired), `token:iat`, `token:nbf`, `token:iss` (`INVALID_ISSUER`), `token:aud` and `token:azp` (`INVALID_AUDIENCE`), `token:nonce` (`INVALID_NONCE`) |
| `claim:` | `INVALID_CLAIMS` | `claim:version`, `claim:message_type`, `claim:target_link_uri`, `claim:sub`, `claim:roles`, `claim:resource_link`, `claim:resource_link.id`, `claim:context`, `claim:context.id`, `claim:deep_linking_settings` |
| `deployment:` | `INVALID_DEPLOYMENT` | `deployment:missing`, `deployment:malformed`, `deployment:unknown` (also when the initiation hint matches no registration deployment), `deployment:hint_mismatch` |
| `content_items:` | `INVALID_CONTENT_ITEMS` | `content_items:array`, `content_items:item`, `content_items:type`, `content_items:property`, `content_items:url`, `content_items:title`, `content_items:text`, `content_items:custom`, `content_items:options`, `content_items:accept_types`, `content_items:accept_multiple` |
| `response_token:` | `INVALID_DEEP_LINKING_RESPONSE` | `response_token:malformed`, `response_token:unknown` (missing, consumed, expired or unreadable in the store, or issued for another registration) |

The list may grow in future versions: keep a default branch when switching on `reason`.

## Diagnostics

The optional `onDiagnostic` callback receives only normalized operational events, `{ code, errorCode }`:

| Diagnostic code | `errorCode` | When |
| --- | --- | --- |
| `REGISTRATION_RESOLUTION_FAILED` | `INVALID_CONFIGURATION` | The resolver threw or did not return an array. |
| `REGISTRATION_INVALID` | `INVALID_CONFIGURATION` | The resolver returned an invalid registration. |
| `STATE_PUT_FAILED` | `STORE_ERROR` | Storing a launch attempt failed. |
| `STATE_TAKE_FAILED` | `STORE_ERROR` | Consuming a launch attempt failed. |
| `JWKS_REQUEST_FAILED` | `JWKS_ERROR` | Fetching or using the platform JWKS failed. |
| `DEEP_LINKING_RESPONSE_PUT_FAILED` | `STORE_ERROR` | Storing a deep linking response entry failed. |
| `DEEP_LINKING_RESPONSE_TAKE_FAILED` | `STORE_ERROR` | Consuming a deep linking response entry failed. |

Raw network, store and jose errors are never exposed. An exception thrown by the callback never changes the result of authentication.

## Migration guides

### From 0.3.x to 0.4.0

**`initiate` returns `{ url, state }`.** It used to return the URL string.

```ts
// 0.3.x
const authorizationUrl = await tool.initiate(params);
session.ltiState = new URL(authorizationUrl).searchParams.get('state');
redirect(authorizationUrl);

// 0.4.0
const { url, state } = await tool.initiate(params);
session.ltiState = state;
redirect(url);
```

**`MemoryStateStore` is renamed `MemoryOneTimeStore`**, without alias.

```ts
// 0.3.x
import { MemoryStateStore } from 'lti-core';
const store = new MemoryStateStore();

// 0.4.0
import { MemoryOneTimeStore } from 'lti-core';
const store = new MemoryOneTimeStore();
```

**The deprecated `LtiContext` alias is removed.** Use `LtiResourceLinkLaunch`, or `LtiLaunch` for the result of `validate`.

```ts
// 0.3.x
import type { LtiContext } from 'lti-core';
// 0.4.0
import type { LtiResourceLinkLaunch } from 'lti-core';
```

**`LtiError.message` is now `CODE: reason`.** Code that compared `error.message` with a code breaks; compare `error.code` (and `error.reason`) instead.

```ts
// 0.3.x
if (error instanceof LtiError && error.message === 'INVALID_STATE') { /* ... */ }
// 0.4.0
if (error instanceof LtiError && error.code === 'INVALID_STATE') { /* ... */ }
```

**A `CryptoKey` signing key requires `publicJwk`.** `KeyObject` keys work unchanged; private JWKs are now accepted too. Web Crypto cannot export the public part synchronously:

```ts
// 0.3.x
toolKeys: { signing: { kid: 'tool-2026-01', privateKey: cryptoKey } }
// 0.4.0
toolKeys: { signing: { kid: 'tool-2026-01', privateKey: cryptoKey, publicJwk: { kty: 'RSA', n, e } } }
```

Tool key validation is also stricter: published exponents must be odd and at least 3, and every signed response is verified against the published key (a mismatched `CryptoKey`/`publicJwk` fails with `INVALID_CONFIGURATION` when responding).

**JWKS cooldown.** 0.3.x refetched the platform JWKS immediately for every unknown `kid`. 0.4.0 waits `jwks.cooldownMs` (30 seconds by default) after the previous fetch, so a freshly rotated platform key can be refused for up to 30 seconds. To keep the previous behavior:

```ts
createLtiTool({ resolver, redirectUri, store, jwks: { cooldownMs: 0 } });
```

The request timeout (five seconds) and the cache maximum age (ten minutes) keep their previous values and are now configurable (`jwks.timeoutMs`, `jwks.cacheMaxAgeMs`).

**Clock tolerance.** 0.3.x allowed no clock skew. 0.4.0 accepts five seconds on `exp`, `nbf` and `iat` by default. Set `clockToleranceSeconds: 0` to keep the previous behavior.

**Tolerant descriptive claims.** Launches that 0.3.x rejected with `INVALID_CLAIMS` are now accepted, with the offending value dropped or normalized (see [Claim tolerance policy](#claim-tolerance-policy)):

- mistyped `name`, `given_name`, `family_name`, `email`, titles, descriptions, `context.label` and `context.title` are dropped;
- invalid locales are dropped, and `_` is read as `-`;
- a non-HTTPS `return_url`, mistyped `width`/`height`, and a non-object `launch_presentation` or `custom` are dropped;
- non-string `custom` values are converted (booleans, finite numbers) or dropped.

**Roles.** 0.3.x required role URIs and, when the array was not empty, at least one recognized role other than `TestUser`. 0.4.0 accepts any array: every string entry is kept in `roles` (non-strings are dropped), and `normalizedRoles` is deduplicated and also recognizes deprecated simple names (`Instructor`, `Learner`...) and LIS v1 URNs. Code that relied on the library to refuse launches without a recognized role must now check `normalizedRoles` itself. A missing, `null` or non-array `roles` claim is still refused for resource link launches.

**New `launch.claims`.** Every launch carries the full verified payload. If you serialize the whole launch object into a session, store only the fields you need instead.

**Runtime and packaging.** Node.js 20 or later is required (`engines`); the package remains ESM only and no longer imports `node:crypto` or uses `Buffer`.

**New exports:** `LtiAuthorizationRedirect`, `LtiErrorReason`, `LtiJwksConfig`, `LtiPrivateJwk`, `NodeKeyObjectLike`; new options `clockToleranceSeconds`, `jwks` and `Registration.redirectUri`.

### From 0.2.x to 0.3.0

- `validate` returns `LtiLaunch` instead of `LtiContext`. Test `launch.messageType === 'LtiResourceLinkRequest'` before reading `resourceLink`.
- `LtiContext` remained exported as a deprecated alias of `LtiResourceLinkLaunch` (removed in 0.4.0). The resource link launch also contains `messageType`.
- An application that does not handle Deep Linking must explicitly refuse the `LtiDeepLinkingRequest` branch. Previously, the library refused it with `INVALID_CLAIMS`.
- `LtiErrorCode` and `LtiDiagnosticCode` gained new values: an exhaustive `switch` must handle them.

```ts
// 0.2.x
const context: LtiContext = await tool.validate(response);
use(context.resourceLink.id);

// 0.3.0
const launch = await tool.validate(response);
if (launch.messageType !== 'LtiResourceLinkRequest') throw new Error('Deep Linking is not supported');
use(launch.resourceLink.id);
```

### From 0.1.x to 0.2.0

`platform.deploymentId` is now typed `string | undefined`. For a registration without `deploymentIdRequired: false`, it is always present: code can check it explicitly (`if (launch.platform.deploymentId === undefined) ...`) or choose a fallback key at the registration level (`issuer`/`clientId`). `resourceLink.id` is not a business identifier of your application.

## References

- [1EdTech LTI Core 1.3](https://www.imsglobal.org/spec/lti/v1p3)
- [1EdTech LTI Deep Linking 2.0](https://www.imsglobal.org/spec/lti-dl/v2p0)
- [1EdTech Security Framework 1.0](https://www.imsglobal.org/spec/security/v1p0/)
- [jose](https://github.com/panva/jose/tree/main/docs)

LTI® is a trademark of 1EdTech Consortium, Inc. This project is not certified by 1EdTech.
