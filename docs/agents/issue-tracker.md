# Issue tracker: GitHub Issues

Issues and specs for this repository live in GitHub Issues: https://github.com/iamlucasb/lti-core/issues.

## Conventions

- One issue per feature request, bug or implementation ticket; a larger effort uses a parent issue that links its child issues.
- Triage state is recorded with one of the labels described in `triage-labels.md`.
- Discussion and decisions are recorded as issue comments.
- Issues never contain secrets, private keys, real platform credentials or user data.

## When a skill says "publish to the issue tracker"

Create a new issue in the repository (for example with `gh issue create`) and apply the `needs-triage` label unless told otherwise.

## When a skill says "fetch the relevant ticket"

Read the referenced issue, including its comments (for example with `gh issue view <number> --comments`). The user will normally pass the issue number or URL directly.
