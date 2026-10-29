# Code architecture

Read this document before adding or moving a source file, changing a public contract, modifying a component with in-memory state, or touching exports and packaging.

## Responsibility placement

```text
src/index.ts
├── main public entry point (`lti-core`)
├── LtiTool and LtiToolConfig contracts
└── configuration validation and module assembly

src/testing.ts
└── test entry point (`lti-core/testing`): generic fake platform for consumers' tests (ADR 0004)

src/launch-flow.ts
├── OIDC initiation and authorization redirect
└── launch validation: state, JWT verification, claims, deep linking token issuance

src/one-time-store.ts
├── OneTimeStore contract and MemoryOneTimeStore
└── typed entries (launch attempt, deep linking response): format, expiry, store errors

src/deep-linking-responses.ts
├── deep linking response token
└── issuance at validation, consumption and response signing

src/errors.ts
├── LtiError, the only error thrown by the core, used directly by internal modules
└── public error codes, error reasons and diagnostics

src/registrations.ts
├── Registration and RegistrationResolver contracts
├── validation of each resolved registration
└── selection at initiation and lookup by issuer/clientId

src/token-verifier.ts
├── JOSE and JWT verification
├── JWKS retrieval and cache
└── normalization of cryptographic errors

src/launch-claims.ts
├── launch claim validation (Resource Link, Deep Linking request)
├── context, presentation and locale vocabularies
└── LtiLaunch construction

src/lti-roles.ts
├── recognized LIS role vocabularies
└── roles claim parsing: raw URIs preserved, normalized roles

src/deep-linking.ts
├── public Deep Linking types
├── request settings and Content Item shape
└── LtiDeepLinkingResponse claims

src/tool-keys.ts
├── tool keys provided by the application
├── public tool JWKS
└── JOSE signing of tool messages

src/platform-jwks-inspection.ts
└── platform JWKS check before a first launch: fetch and key summary with the launch validation rules

src/random.ts
└── cryptographically random tokens (state, nonce, response tokens) with Web Crypto

src/validation.ts
└── validation primitives used by several modules

test/*.test.ts
└── consumer-visible behavior

test/fixtures/
└── static test resources
```

- Keep a validation used by a single module next to its owner.
- Create a new file only for a cohesive responsibility that belongs to no existing owner.
- Name modules after their responsibility; avoid `utils.ts`, `helpers.ts`, `common.ts` and `manager.ts`.

## Module boundaries

- Organize modules by their independent reasons to change, not by arbitrary technical categories.
- Prefer a deep module: small contract, private invariants and lifecycle details.
- Separate orchestration, protocol, external dependencies and result construction when they fail or evolve independently.
- Isolate an external library when its types, errors or lifecycle would otherwise contaminate the core.
- Use opaque values for infrastructure ports when their schema belongs to the core.
- A file over 300 lines or a function over 50 lines triggers a cohesion review, not an automatic split.

## Public API

- `src/index.ts` (`lti-core`) and `src/testing.ts` (`lti-core/testing`) are the package's only export surfaces. Test support goes in `src/testing.ts`, never in the main entry; `src/index.ts` never imports it.
- A public type may be defined by its owning module, then explicitly re-exported from `src/index.ts`.
- Before exporting, check that the consumer needs it and that it reveals neither an internal workflow nor an internal persistence model.
- Preserve runtime-validated constraints in public types.
- Make properties and collections immutable unless mutation is part of the contract.
- Translate external errors into stable codes without exposing raw dependency errors.
- Internal modules throw `LtiError` directly; do not reintroduce an intermediate error converted in `index.ts`.

## State and lifecycle

Every cache, `Map`, queue, timer or registry fed by external operations explicitly defines:

- how entries are created;
- how they are removed;
- their expiry, eviction or maximum capacity;
- concurrency guarantees;
- single-process or multi-instance limits.

## Tests and package

- Test public behavior and infrastructure boundaries, not internal structure.
- When refactoring a validation, keep the implementation or prove equivalence with the relevant failure tests before simplifying.
- After a change to exports, declarations or the build, create a tarball with `npm pack`, install it in a temporary consumer and import the package by name.

## Documentation

- `README.md`: discovery and quick start.
- `docs/integration.md`: detailed consumer contract.
- `docs/architecture-review.md`: architectural decisions and rationale.
- `CONTEXT.md`: glossary only.
- `docs/adr/`: decisions that are costly to reverse.
- `AGENTS.md`: mandatory contribution rules.
- Specs and issues live in GitHub Issues, never in distributed documentation.
