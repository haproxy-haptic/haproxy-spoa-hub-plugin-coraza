<!--
Sync Impact Report
===================
Version change: 0.0.0 → 1.0.0
Modified principles: N/A (initial adoption)
Added sections:
  - Core Principles (4 principles: Code Quality, Testing Standards,
    User Experience Consistency, Performance Requirements)
  - Security & Reliability
  - Development Workflow
  - Governance
Removed sections: None
Templates requiring updates:
  - .specify/templates/plan-template.md — ✅ no updates needed
    (Constitution Check section is dynamically filled)
  - .specify/templates/spec-template.md — ✅ no updates needed
    (success criteria already cover performance/UX)
  - .specify/templates/tasks-template.md — ✅ no updates needed
    (phase structure accommodates all principle-driven tasks)
Follow-up TODOs: None
-->

# HAProxy SPOA Hub Plugin Coraza Constitution

## Core Principles

### I. Code Quality

- All code MUST compile without warnings and pass configured linters
  before merge.
- Functions and methods MUST have a single, clearly defined
  responsibility. Shared logic MUST be extracted rather than
  duplicated.
- Public APIs MUST be documented with purpose, parameters, return
  values, and error conditions. Internal code MUST use clear naming
  that makes intent obvious without comments.
- Dependencies MUST be explicitly justified. Every third-party
  dependency MUST solve a problem that would be unreasonable to
  implement in-project.
- Dead code, unused imports, and unreachable branches MUST be removed
  before merge.

### II. Testing Standards

- Every bug fix MUST include a regression test that fails before the
  fix and passes after.
- New features MUST have tests covering the documented acceptance
  scenarios from the specification.
- Tests MUST be deterministic: no reliance on timing, external
  services, or execution order. Flaky tests MUST be fixed or removed
  immediately.
- Integration tests MUST exercise the actual SPOA protocol
  communication path. Mocking at the protocol boundary is permitted
  only when the real dependency is genuinely unavailable in CI.
- Test names MUST describe the scenario and expected outcome, not the
  implementation detail being exercised.

### III. User Experience Consistency

- Configuration options MUST follow established HAProxy and Coraza
  conventions. Avoid inventing new patterns when existing ones apply.
- Error messages MUST be actionable: state what happened, why, and
  what the operator can do about it.
- Logging MUST use structured fields and consistent severity levels.
  DEBUG for internal state, INFO for operational events, WARN for
  recoverable problems, ERROR for failures requiring attention.
- Breaking changes to configuration or behavior MUST be documented
  in release notes with migration instructions.
- Default values MUST be safe and production-ready. Insecure or
  degraded defaults are not permitted.

### IV. Performance Requirements

- Request processing latency added by the plugin MUST remain below
  1ms at p99 under normal operating conditions.
- The plugin MUST NOT introduce memory leaks. Long-running processes
  MUST maintain stable memory usage over time.
- Resource-intensive operations (rule compilation, configuration
  reload) MUST NOT block request processing.
- Performance-sensitive code paths MUST include benchmarks that run
  in CI. Regressions exceeding 10% MUST be investigated before merge.
- Connection handling MUST support concurrent SPOA sessions without
  serialization bottlenecks.

## Security & Reliability

- All user-supplied input (HTTP headers, request bodies, SPOA
  messages) MUST be treated as untrusted and validated before
  processing.
- The plugin MUST NOT crash on malformed input. Panics in request
  handling paths are treated as severity-1 bugs.
- WAF rule evaluation failures MUST default to a safe posture
  (deny by default when rule engine state is uncertain).
- Secrets and credentials MUST NOT appear in logs, error messages,
  or debug output at any log level.

## Development Workflow

- All changes MUST go through pull request review before merge to
  the main branch.
- Commits MUST follow conventional commit format
  (`type: description`).
- CI MUST pass (build, lint, test, benchmarks) before a PR is
  eligible for merge.
- Each PR SHOULD address a single concern. Unrelated changes MUST
  be split into separate PRs.

## Governance

- This constitution is the authoritative source for project standards.
  When a practice conflicts with a constitution principle, the
  constitution takes precedence.
- Amendments require: (1) a written proposal describing the change
  and rationale, (2) review and approval via pull request, and
  (3) a version bump following semantic versioning.
- Version policy: MAJOR for principle removals or incompatible
  redefinitions, MINOR for new principles or material expansions,
  PATCH for clarifications and wording fixes.
- All pull request reviews MUST verify compliance with these
  principles. Non-compliance MUST be called out and resolved before
  merge.

**Version**: 1.0.0 | **Ratified**: 2026-04-12 | **Last Amended**: 2026-04-12
