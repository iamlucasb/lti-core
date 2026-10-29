# `lti-core` architecture review

This document records the design decisions that came out of the review of the LTI core. The usage contract belongs to the [integration guide](integration.md) and the mandatory contribution rules to [`AGENTS.md`](../AGENTS.md).

## Current structure

```text
src/index.ts
├── public tool contracts
└── configuration and assembly

src/launch-flow.ts
└── OIDC initiation and launch validation

src/one-time-store.ts
├── store contract and one-time in-memory storage
└── typed entries, expiry and store errors

src/deep-linking-responses.ts
└── response token, issuance and response signing

src/errors.ts
└── public error, codes, reasons and diagnostics

src/registrations.ts
├── validation of resolved registrations
└── registration selection and lookup

src/token-verifier.ts
├── JWKS download and cache
├── JOSE verification
└── normalization of cryptographic errors

src/launch-claims.ts
├── Resource Link and Deep Linking claim validation
├── context, presentation and locale vocabularies
└── LtiLaunch construction

src/lti-roles.ts
└── role vocabularies and normalization

src/deep-linking.ts
├── settings and Content Items
└── signed response claims

src/tool-keys.ts
├── tool keys and public JWKS
└── JOSE signing of tool messages

src/platform-jwks-inspection.ts
└── platform JWKS check: fetch and key summary

src/testing.ts
└── fake platform for consumers' tests (`lti-core/testing`)

src/random.ts
└── random tokens with Web Crypto

src/validation.ts
└── shared validation primitives
```

The package exposes `src/index.ts` (`lti-core`) and `src/testing.ts` (`lti-core/testing`). The other modules are internal.

## Main decisions

### Typed store entries

`OneTimeEntries` is the only module that knows the format of stored values: launch attempt (format unchanged since 0.1) and deep linking response (tagged with a `kind`). It checks expiry and translates store failures into `STORE_ERROR` with a diagnostic.

### Opaque one-time store

Storage adapters handle an opaque value rather than the internal model of an attempt. The core can therefore evolve its workflow without imposing its schema on Redis or SQL adapters.

The contract keeps the invariants that truly belong to storage: creation without overwrite, expiry, and atomic single consumption.

### Bounded in-memory lifecycle

`MemoryOneTimeStore` removes consumed values and periodically cleans up expired values. It is deliberately limited to a single process and does not try to emulate distributed storage.

### Precise public types

Validated results stay precise in the TypeScript API: read-only structures, `readonly` collections, and literal unions when the protocol imposes a finite vocabulary.

### A single error, without conversion

Internal modules throw `LtiError` directly. Dependency errors (JOSE, network, store, resolver) are translated at their boundary, with no attached cause. This avoids repeated conversion blocks in the orchestration.

### Registrations behind a single module

`RegistrationDirectory` hides resolution, validation of each registration, and selection rules (client, target, deployment hint, uniqueness). The orchestration only knows `select` (initiation) and `find` (launch return, Deep Linking response). No registration is cached: a revocation takes effect immediately.

### Diagnostics separate from public errors

`LtiError` provides a stable, safe code to the consumer, and a reason naming the failed check without any value. `onDiagnostic` separately provides normalized operational events. Raw JOSE, network and storage errors do not cross the public API.

### Isolated JOSE dependency

JWKS retrieval, caching and translation of cryptographic errors are concentrated in `token-verifier.ts`. Signing of tool messages is concentrated in `tool-keys.ts`, which keeps the private key in a private field. Claim parsing does not depend on JOSE directly. `platform-jwks-inspection.ts` reuses the JOSE remote and local key sets, so that its verdict on a platform JWKS follows the same fetch and key selection rules as launch validation instead of a copy of them.

### Deep Linking response backed by the one-time store

The validated request is stored in the `OneTimeStore` and referenced by an opaque single-use token. The response can therefore only come from a validated request, works across multiple instances, and cannot be replayed. See [ADR 0003](adr/0003-deep-linking-response-token.md).

### Inbound and outbound HTTP kept distinct

The core depends on no inbound HTTP framework and owns neither routes nor sessions. It nevertheless performs the outbound HTTPS requests required to resolve JWKS.

### Test support in its own entry point

The fake platform that consumers need for their tests is published as `lti-core/testing`, generic and configured by documented options, so that production imports never load it. It generates the platform key, never the tool's. See [ADR 0004](adr/0004-testing-entry-point.md).

### Package verified as a product

`prepack` rebuilds `dist`. Changes to the public surface must be verified from an installed tarball, because tests importing `src` do not prove that the published package is usable.

## Deliberately retained choices

- tool interface limited to `initiate`, `validate`, `createDeepLinkingResponse` and `jwks`, plus the standalone `inspectPlatformJwks` check;
- Resource Link, Deep Linking 2.0 (`ltiResourceLink`) and RS256 only;
- no NRPS, AGS or Dynamic Registration extension without an explicit request;
- no user model, application role or application permission;
- real signatures and a local HTTPS JWKS server in tests;
- `jose` as the only runtime dependency.

## Reusable lessons

- stabilize public contracts before multiplying adapters;
- expose opaque values when their schema belongs to the calling module;
- preserve already-validated constraints in types;
- separate public errors from operational diagnostics;
- isolate external libraries behind a local boundary;
- split by reasons to change, not by an arbitrary number of lines;
- define the lifecycle of every in-memory collection;
- test the compiled, installed package, not only the sources.
