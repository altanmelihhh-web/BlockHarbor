# Contributing to BlockHarbor

Thanks for your interest. BlockHarbor is open-source under MIT — issues, PRs, and security reports all welcome.

## Quick setup

For local development, follow [Install Option A or B](README.md#install) in the README — both produce a fully working environment in 3 commands. Docker is the easiest for evaluators; native install is the easiest for active development on a Linux workstation.

## Workflow

```bash
composer test          # PHPUnit (unit + integration; needs PG up)
composer stan          # PHPStan level 8 on src/
composer psalm         # Psalm errorLevel 4
composer audit         # composer security advisories
npm run build          # rebuild public/assets/ from resources/
./bin/verify-audit-chain  # smoke-test audit chain
```

CI (`.github/workflows/ci.yml`) runs all of these on every push and pull request to `main`. Your PR should be green before requesting review.

## Branch + commit conventions

- Branch from `main`. Name: `feat/short-topic`, `fix/short-topic`, `docs/short-topic`.
- One logical change per PR. If you find yourself writing "and also" in the summary, split it.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat(scope):` new feature
  - `fix(scope):` bug fix
  - `chore(scope):` non-functional (deps, config)
  - `docs(scope):` documentation
  - `test(scope):` test-only changes
  - `refactor(scope):` no-behaviour-change rewrites
- Scopes match `src/` directories: `auth`, `audit`, `core`, `admin`, `db`, `ci`, etc.
- Body explains **why**, not what — the diff shows what.

## Code style

- PHP: PSR-12, namespace `BlockHarbor\` mapped to `src/`. Every file starts with `<?php declare(strict_types=1);`. `final class` by default; only `abstract` when explicitly designed for subclassing.
- SQL: explicit column lists, parametrised queries, **never** string-interpolate user input. The audit-log table is append-only — never UPDATE/DELETE its rows.
- JS: minimal. Alpine.js for interactions, HTMX for partials. No transpilation in production assets.
- Tests: TDD for new behaviour. Integration tests for anything touching the DB. Unit tests for pure logic.

## What to work on

- Browse [open issues](https://github.com/altanmelihhh-web/BlockHarbor/issues) labelled `good first issue` or `help wanted`.
- The [ROADMAP](ROADMAP.md) outlines releases through `v0.3.x`. PRs that advance these are especially welcome.
- For larger features, open an issue first to discuss the design — saves both of us rework.

## Security vulnerabilities

**Do NOT open a public issue for security bugs.** See [SECURITY.md](SECURITY.md) for the disclosure address.
