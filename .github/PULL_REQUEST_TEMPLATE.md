## Summary

<!-- 1-3 bullet points describing what this PR does -->

## Phase

- [ ] P1 — Foundation + Auth Core
- [ ] P2 — Audit + 2FA + Passkeys
- [ ] P3 — IOC Domain + Pending Workflow
- [ ] P4 — Feeds + CVE + Vendors
- [ ] P5 — Custom Lists + Notifications + Customers + REST API
- [ ] P6 — JSON → DB Import + Cutover
- [ ] P7 — GitHub Readiness + Polish
- [ ] Out-of-phase (bug fix, docs, etc.)

## Test plan

- [ ] `composer test` passes
- [ ] `composer stan` passes (PHPStan level 8)
- [ ] `composer psalm` passes
- [ ] `composer audit` shows no vulnerable packages
- [ ] Manual smoke test for affected feature
- [ ] `bin/doctor.sh` reports green

## Security considerations

<!-- If this touches auth/audit/secrets/DB-schema, describe the threat model
     of the change. Mention any new attack surface or hardening it adds. -->

## Documentation

- [ ] README updated (if user-facing)
- [ ] CHANGELOG.md updated under [Unreleased]
- [ ] Spec/plan docs in `docs/superpowers/` updated if architectural

🤖 Generated with [Claude Code](https://claude.com/claude-code)
