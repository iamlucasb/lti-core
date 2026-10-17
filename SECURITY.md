# Security policy

`lti-core` authenticates users launched from learning platforms, so security reports are taken seriously.

## Supported versions

Only the latest published `0.x` release receives security fixes. Upgrade to the latest version before reporting, when possible.

| Version | Supported |
| --- | --- |
| latest 0.x | yes |
| older releases | no |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through [GitHub Security Advisories](https://github.com/iamlucasb/lti-core/security/advisories/new) ("Report a vulnerability" in the repository's Security tab). Include:

- the affected version;
- a description of the issue and its impact (for example authentication bypass, replay, signature or claim validation weakness, key disclosure);
- steps or a minimal test case to reproduce it, using test keys and a fake platform.

Never include real private keys, platform credentials, tokens or user data in a report.

You will receive an acknowledgement as soon as possible. Once a fix is available, it is released and the advisory published, crediting the reporter unless they prefer otherwise.

## Scope

In scope: the library's validation of OIDC initiation, launches, Deep Linking requests and responses, JWT/JWKS handling, `state`/`nonce` single use, tool key handling and error contents.

Out of scope: vulnerabilities in your application's routes, sessions, `OneTimeStore` adapter or `RegistrationResolver`, and platform-side issues. The [production checklist](README.md#production-checklist) lists the responsibilities that remain with the application.
