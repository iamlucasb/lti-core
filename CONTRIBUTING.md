# Contributing

Thank you for your interest in `lti-core`. Bug reports, platform compatibility reports and pull requests are welcome.

## Before you start

- Open or comment on an [issue](https://github.com/iamlucasb/lti-core/issues) before starting a significant change, so that its scope can be agreed on.
- Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Setup

Node.js 20 or later is required.

```sh
git clone https://github.com/iamlucasb/lti-core.git
cd lti-core
npm ci
```

## Commands

```sh
npm run typecheck      # TypeScript strict mode, sources and tests
npm run lint           # Biome
npm test               # node:test suite, with a local HTTPS JWKS server
npm run build          # compiles dist/
npm run check:package  # publint and @arethetypeswrong/cli on the packed package
```

All of them run in CI on Node.js 20, 22 and 24, followed by a smoke import of the packed tarball. A pull request must pass them all.

## Rules

The mandatory rules are in [AGENTS.md](AGENTS.md) and the documents it references (code architecture, LTI protocol and security, domain). In short:

- keep changes scoped to the task; prefer simple, explicit solutions; no dead code, debug code or commented-out implementations;
- keep the core independent from HTTP frameworks, databases, Redis and specific LMS implementations;
- **no vendor- or platform-specific logic in the core**: platform quirks are handled by explicit, documented, generic options or tolerances;
- no application users, roles, permissions or business identifiers in the core;
- TypeScript strict mode; untrusted input is `unknown` and validated at runtime; avoid `any` and assertions that hide validation problems;
- never weaken a security validation to work around a platform;
- `src/index.ts` is the only public entry point; update `docs/integration.md` and `CHANGELOG.md` when the public contract changes.

## Tests

Every change in behavior comes with tests, and every security validation added or changed comes with a failure test. Tests exercise the public API, use test keys and fake platforms, and never depend on a real LMS.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `build:`, `chore:`..., with `!` (for example `feat!:`) for a breaking change.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
