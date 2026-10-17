# Agent instructions

These rules are mandatory for every change in this repository. Follow every reference below whose trigger matches the task.

## Project rules

### General

- Prefer simple, explicit, maintainable solutions.
- Do not introduce unnecessary abstractions or complexity.
- Keep changes scoped to the requested task and preserve unrelated behavior.
- Never leave debug code, temporary hacks, dead code, or commented-out implementations.

### Scope

- Keep `lti-core` independent from HTTP frameworks, databases, Redis, and specific LMS implementations.
- No vendor/platform-specific or application business logic in the core; platform quirks are handled by explicit, documented, generic options or tolerances.
- Do not add LTI features or extensions outside the requested task.
- Do not introduce application users, roles, permissions, assignments, or business identifiers into the core.

### TypeScript

- TypeScript strict mode is mandatory.
- Use `unknown` for untrusted input and validate it at runtime.
- Avoid `any` and type assertions that hide validation or typing problems.

### Completion

Before completing a task:

- run the typecheck (`npm run typecheck`);
- run lint when configured;
- run the relevant tests (`npm test`) and smoke scenario;
- verify applicable security behavior was not weakened;
- remove temporary and debug code;
- confirm unrelated files and behavior were not changed;
- satisfy every task-specific completion check from the referenced agent documents.

## Agent references

### Code architecture

Before adding or moving source files, changing public contracts, modifying in-memory state, or touching package exports, read `docs/agents/code-architecture.md`.

### LTI protocol and security

Before changing login or launch behavior, claims, JWT/JWKS, state, nonce, deployments, identity, or roles, read `docs/agents/lti-protocol.md`.

### Issue tracker

Issues are tracked in GitHub Issues at https://github.com/iamlucasb/lti-core/issues. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default names as GitHub labels. See `docs/agents/triage-labels.md`.

### Domain docs

Before changing domain terminology or a hard-to-reverse domain decision, read `docs/agents/domain.md`.
