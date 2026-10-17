# Changelog

All notable changes to this project are documented in this file.

## 0.4.0

First open-source release. Migration: see `docs/integration.md` ("From 0.3.x to 0.4.0").

### Breaking

- `initiate` returns an `LtiAuthorizationRedirect`, `{ url, state }`, instead of the URL string, so that the application can bind `state` to the browser session without parsing the URL.
- `MemoryStateStore` is renamed `MemoryOneTimeStore`, without alias.
- The deprecated `LtiContext` alias is removed: use `LtiResourceLinkLaunch` or `LtiLaunch`.
- `LtiError.message` is now `CODE: reason` (previously `CODE`). Code that matched the message must match `error.code` and `error.reason`.
- A Web Crypto `CryptoKey` signing key requires its `publicJwk`, because Web Crypto cannot export it synchronously.
- Platform JWKS: an unknown `kid` no longer triggers an immediate refetch. The new default cooldown of 30 seconds means a rotated platform key can be refused for up to 30 seconds after the previous fetch; `jwks: { cooldownMs: 0 }` restores the previous behavior.
- A default clock tolerance of five seconds now applies to `exp`, `nbf` and `iat` (previously none); `clockToleranceSeconds: 0` restores the previous behavior.
- Claim tolerance: launches previously rejected with `INVALID_CLAIMS` because of a mistyped descriptive claim are now accepted with that value dropped or normalized. Roles are no longer required to be URIs nor to contain a recognized role: applications that relied on the library to refuse such launches must check `normalizedRoles` themselves.
- Node.js 20 or later is required (`engines`).

### Added

- `clockToleranceSeconds` option: integer from 0 to 300, default 5.
- `jwks` option: `timeoutMs` (default 5 000), `cooldownMs` (default 30 000) and `cacheMaxAgeMs` (default 600 000).
- `Registration.redirectUri`: overrides the tool's `redirectUri` for one registration (absolute HTTPS URL without fragment).
- `launch.claims`: shallow-frozen copy of the full verified JWT payload, for claims the library does not interpret (AGS/NRPS endpoints, `tool_platform`, `lis`, vendor extensions, `deep_linking_settings.data`). Signed by the platform but not validated.
- `LtiError.reason` (`LtiErrorReason`): stable, non-sensitive, machine-readable name of the failed check, such as `claim:resource_link.id`, `config:redirectUri` or `token:kid`.
- Tool signing keys can be a Node.js `KeyObject`, a private RSA JWK (`LtiPrivateJwk`) or a Web Crypto `CryptoKey` with its `publicJwk`.
- Role recognition: deprecated simple context role names (`Instructor`, `Learner`...) and LIS v1 URNs (`urn:lti:role:ims/lis/...`, `urn:lti:instrole:ims/lis/...`, `urn:lti:sysrole:ims/lis/...`) are normalized to their LIS v2 equivalents.
- New exported types: `LtiAuthorizationRedirect`, `LtiErrorReason`, `LtiJwksConfig`, `LtiPrivateJwk`, `NodeKeyObjectLike`.
- `SECURITY.md` and `CONTRIBUTING.md`; documentation in English.

### Changed

- Login initiation: an empty `client_id` or `lti_deployment_id` is treated as absent instead of failing with `INVALID_LOGIN` (some platforms send empty optional fields).
- Tolerance policy: security and identity claims stay strict; descriptive claims are normalized or dropped instead of rejecting the launch:
  - `locale` and `launch_presentation.locale`: `_` is read as `-`, then a value that is not a BCP 47 tag is dropped;
  - mistyped optional text claims (`name`, `given_name`, `family_name`, `email`, titles, descriptions, `context.label`, `context.title`) are dropped;
  - a non-HTTPS `return_url` and mistyped `width`/`height` are dropped;
  - `custom`: strings are kept, booleans and finite numbers are converted to strings (integers outside the safe range are dropped), `null`, objects and arrays are dropped;
  - a non-object `custom` or `launch_presentation` claim is dropped.
- Roles: any array is accepted; every string entry is kept verbatim in `roles`, non-string entries are dropped, and `normalizedRoles` is deduplicated. A launch with only `TestUser` is accepted. A missing, `null` or non-array `roles` claim is still refused for resource link launches.
- Every core error now carries a `reason`.

### Security hardening

- RSA tool keys must have at least 2048 bits and published exponents must be odd and at least 3.
- Every signed Deep Linking response is verified against the published signing key before it is returned: a mismatched key fails closed with `INVALID_CONFIGURATION`.
- The new numeric options are bounded (`clockToleranceSeconds` at most 300 seconds, positive JWKS timeout and cache maximum age), and every invalid option is named in the error reason.
- The JWKS key set cache is bounded to 100 entries (least recently used first out).
- The JWKS cooldown bounds the requests that tokens with forged `kid` values can send to a platform.
- Error messages and reasons never contain values, keys, tokens, `state` or `nonce`.

### Internal

- No more `node:crypto` or `Buffer` in the library: random tokens, encoding and keys use Web Crypto and `jose`. Designed to be runtime-agnostic; officially supported on Node.js >= 20.
- Packaging for npm: package metadata, `exports` of `package.json`, Biome lint, CI matrix on Node.js 20, 22 and 24, `publint` and `@arethetypeswrong/cli` (`npm run check:package`), smoke import of the packed tarball.
- Glossary, ADRs, agent rules and documentation translated to English; the issue tracker moved to GitHub Issues.

## 0.3.0

### Breaking

- `validate` returns `LtiLaunch`, a union discriminated by `messageType`: `LtiResourceLinkLaunch` (`LtiResourceLinkRequest`) or `LtiDeepLinkingLaunch` (`LtiDeepLinkingRequest`). The resource link launch gains the `messageType` field. `LtiContext` remains exported as a deprecated alias of `LtiResourceLinkLaunch`. Migration: see `docs/integration.md` ("From 0.2.x to 0.3.0").
- A valid `LtiDeepLinkingRequest` is no longer refused: an application that does not handle Deep Linking must refuse that branch.
- New `LtiErrorCode` values (`INVALID_CONTENT_ITEMS`, `INVALID_DEEP_LINKING_RESPONSE`) and `LtiDiagnosticCode` values (`DEEP_LINKING_RESPONSE_PUT_FAILED`, `DEEP_LINKING_RESPONSE_TAKE_FAILED`).

### Added

- LTI Deep Linking 2.0: request validation (`deep_linking_settings` required, with an HTTPS return URL, `accept_types` and `accept_presentation_document_targets`), with the same security checks as a resource link launch. `sub` required, `roles` optional and raw.
- `createDeepLinkingResponse(responseToken, items, options?)`: `LtiDeepLinkingResponse` JWT signed with RS256, with `ltiResourceLink` Content Items (`url`, `title`, `text`, `custom`), `data` echoed back unchanged and optional `msg`/`log`/`errormsg`/`errorlog`. `accept_types` and `accept_multiple` are enforced. Single-use response token backed by the `OneTimeStore`.
- `toolKeys` options (private key provided by the application, with a `kid`, and public rotation keys) and `deepLinkingResponseLifetimeMs` (one hour by default).
- `jwks()`: the tool's public JWKS.
- ADR 0003.

### Internal

- The core is split by responsibility: registrations, one-time entries, launch flow, Deep Linking responses and LTI roles each have their own module. Internal modules throw `LtiError` directly. The stored format of a launch attempt is unchanged.

### Unchanged

- Signature, issuer, audience, `state`, `nonce`, replay, deployment, target and version checks of the resource link launch.

## 0.2.1

### Fixed

- `resource_link.id` and `context.id` sent as JSON integers (as Dokeos does) no longer reject the launch: a safe non-negative integer is converted to its decimal string. Floats, negative numbers, unsafe integers, booleans, objects and `null` are still refused.
- `null` on an optional claim (`email`, `name`, `given_name`, `family_name`, `locale`, titles, descriptions, `label`, `context`, `launch_presentation` and its fields, `custom` and its values) is treated as absent. `null` on a required claim is still refused.
- An unknown `launch_presentation.document_target` is ignored instead of rejecting the launch. Names inherited from `Object.prototype` (`constructor`, `toString`...) are no longer taken for valid targets.

### Unchanged

- `sub`, `deployment_id`, `iss`, `aud` and `nonce` remain strict strings. TypeScript contract unchanged.

## 0.2.0

### Breaking

- `LtiContext.platform.deploymentId` is now optional (`string | undefined`). It is only absent for a registration that declares `deploymentIdRequired: false` when the platform does not send the claim. Migration: see `docs/integration.md` ("From 0.1.x to 0.2.0").

### Added

- Registration option `deploymentIdRequired?: boolean` (`true` by default). With `false`, a launch without the `deployment_id` claim is accepted (as sent by Dokeos), `deployments` may be empty, and a claim that is present is still validated (LTI identifier, membership in `deployments` when not empty, consistency with `lti_deployment_id`). See ADR 0002.
- A non-boolean `deploymentIdRequired` is refused with `INVALID_CONFIGURATION`.

### Unchanged

- Without the option, a launch without `deployment_id` is still refused with `INVALID_DEPLOYMENT`. Issuer, audience, signature, `state`, `nonce`, target, version and message type checks are identical.

## 0.1.1

### Fixed

- A `context.type` containing a deprecated short name (`CourseTemplate`, `CourseOffering`, `CourseSection`, `Group`) no longer rejects the launch: the value is normalized to the URI `http://purl.imsglobal.org/vocab/lis/v2/course#<Name>`.
- An unusable `context.type` (not an array, empty, without a standard type) is ignored (`context.type` absent) instead of rejecting the whole launch with `INVALID_CLAIMS`. Entries that are neither URIs nor known short names are discarded, and duplicates removed.
- The `context` claim is still refused when it is not an object, when its `id` is missing or invalid, or when `label`/`title` are not strings.

## 0.1.0

- Initial release: OIDC initiation and validation of LTI 1.3 Resource Link launches.
