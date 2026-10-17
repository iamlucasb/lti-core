# LTI protocol and security

Read this document before changing LTI initiation or launch, claims, JWT/JWKS, `state`, `nonce`, deployments, identity or roles.

## Sources

- Consult the current 1EdTech specification for the flow and claims involved.
- Before changing the use of an external library API, use the `find-docs` skill and its current documentation.
- If Context7 is unavailable, use the official documentation and state which source was checked.

## Scope

- Follow LTI 1.3 semantics rather than convenience behavior.
- Supported extensions: Deep Linking 2.0 (request and response, `ltiResourceLink` Content Item only). See [ADR 0003](../adr/0003-deep-linking-response-token.md).
- Do not add NRPS, AGS, Dynamic Registration, other Content Item types or any other extension without an explicit request.
- Keep LMS-specific adaptations out of the generic core.
- Accept unknown vendor claims when they do not invalidate the LTI message.

## Security validation

- Never confuse JWT decoding with JWT validation.
- Validate signatures and sensitive claims at runtime.
- Always validate `state` and `nonce`, then prevent their replay.
- Resolve keys through JWKS and support key rotation.
- Only build a Deep Linking response from a validated request, never from browser data.
- Never generate, store, log or attach to an error the tool's private key.
- Fail closed on authentication or signature errors.
- Do not weaken a global validation to work around an LMS.

## Identity and roles

- Require a valid `sub` for resource launches and for deep linking requests.
- `roles` is required in a resource launch and optional in a deep linking request.
- Do not require optional identity claims such as name or email.
- Preserve raw LTI roles.
- Do not convert LTI roles into application permissions in the library.
- Do not use `resourceLink.id` as a business identifier.

Use the vocabulary of [`CONTEXT.md`](../../CONTEXT.md) and respect the decisions in [`docs/adr/`](../adr/).

## Tests

- Add a failure test for every security validation introduced or changed.
- Never depend on a real LMS.
- Use test keys and fake platforms.
- Cover, when relevant, invalid signatures, claims, state, nonce, replay, deployments and key rotation.

Before finishing, explicitly verify that security validation was not weakened and that no vendor/platform-specific or application business logic entered the core.
