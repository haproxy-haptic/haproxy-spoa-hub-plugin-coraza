# Implementation Plan: Coraza WAF Plugin

**Branch**: `001-coraza-waf-plugin` | **Date**: 2026-04-12 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/001-coraza-waf-plugin/spec.md`

## Summary

Implement a haproxy-spoa-hub plugin that embeds the Coraza WAF engine (Go) via
C FFI into a Rust cdylib. The plugin evaluates HTTP requests (and optionally
responses) against OWASP CRS v4 rulesets, returning allow/deny decisions as SPOE
transaction variables. The Go Coraza library is compiled as a `c-archive` and
statically linked into the Rust plugin, eliminating IPC overhead between HAProxy
and the WAF engine.

## Technical Context

**Language/Version**: Rust 1.86 (edition 2024) + Go 1.25+ (for Coraza v3 c-archive)
**Primary Dependencies**: haproxy-spoa-hub-plugin-api 0.1, abi_stable 0.11, coraza/v3, coraza-coreruleset/v4, mergefs
**Storage**: In-memory transaction cache (Go-side TTL map)
**Testing**: cargo test (Rust unit/integration), go test (Go unit), Kubernetes e2e (HAProxy + hub + plugin)
**Target Platform**: Linux (amd64, arm64, armv7)
**Project Type**: Shared library plugin (cdylib)
**Performance Goals**: <1ms p99 request evaluation latency, 10k req/s per core
**Constraints**: Single Go c-archive per process, ~30ns CGo call overhead, Go GC pauses
**Scale/Scope**: Production WAF deployments handling 10k+ req/s

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Evidence |
|-----------|--------|----------|
| I. Code Quality | PASS | Rust clippy + Go vet/staticcheck in CI. Single responsibility: Go wrapper handles WAF, Rust handles SPOE integration. Dependencies justified (Coraza = WAF engine, abi_stable = hub API requirement). |
| II. Testing Standards | PASS | Unit tests for config parsing and FFI wrapper. Integration tests with mock SPOE messages. E2E tests with HAProxy + hub + plugin in Kubernetes (kind cluster). Benchmarks for request evaluation latency. |
| III. User Experience Consistency | PASS | Configuration follows TOML conventions (hub standard). Error messages include file paths and rule IDs. Structured logging via hub's log callback. Migration guide documents variable name mapping from coraza-spoa. |
| IV. Performance Requirements | PASS | <1ms p99 target. Benchmarks in CI with 10% regression threshold. Batched FFI calls minimize CGo overhead. GOGC tuning documented. Non-blocking rule compilation at startup. |
| Security & Reliability | PASS | Deny-by-default on WAF engine errors (FR-008). No panics in request path (catch_unwind via define_plugin! macro + Go defer/recover). Input treated as untrusted (Coraza handles validation). No secrets in logs. |
| Development Workflow | PASS | PR-based workflow. Conventional commits. CI gates: build + lint + test + bench. |

No violations. No complexity tracking entries needed.

## Project Structure

### Documentation (this feature)

```text
specs/001-coraza-waf-plugin/
├── plan.md              # This file
├── research.md          # Phase 0 research findings
├── data-model.md        # Entity definitions
├── quickstart.md        # Getting started guide
├── contracts/
│   ├── ffi-contract.md  # Go↔Rust C FFI boundary
│   └── spoe-variables.md # SPOE message and variable contracts
└── tasks.md             # Phase 2 output (/speckit.tasks)
```

### Source Code (repository root)

```text
src/
├── lib.rs               # Module declarations (pub mod config, mod plugin)
├── plugin.rs            # SpoePlugin trait implementation (define_plugin! macro)
├── config.rs            # PluginConfig parsing from hub TOML + JSON schema
└── ffi.rs               # Rust FFI declarations for Go c-archive functions

go/
├── go.mod               # Go module (coraza/v3, coraza-coreruleset/v4, mergefs)
├── go.sum
├── lib.go               # C-exported FFI functions (coraza_waf_new, etc.)
├── waf.go               # WAF instance management (create, destroy, handle map)
├── transaction.go       # Transaction processing (request, response, batched)
├── cache.go             # TTL transaction cache for response correlation
└── metrics.go           # Lightweight WAF counter metrics

tests/
├── config_test.rs       # Configuration parsing and validation
├── ffi_test.rs          # FFI round-trip tests (create WAF, process request)
└── e2e/
    ├── Dockerfile.hub        # Multi-stage build (Go c-archive + Rust cdylib)
    ├── Makefile              # E2e test orchestration
    ├── run.sh                # Kind cluster test runner (create, deploy, test, teardown)
    └── manifests/
        ├── namespace.yaml        # e2e-coraza namespace
        ├── configmaps.yaml       # HAProxy + hub TOML configs
        ├── backend.yaml          # nginx backend deployment + service
        └── haproxy-hub.yaml      # HAProxy + hub sidecar deployment + NodePort service

benches/
└── waf_bench.rs         # Criterion benchmarks (request evaluation latency)

examples/
├── hub.toml             # Example hub configuration
├── spoe-coraza.conf     # Example HAProxy SPOE configuration
└── haproxy.cfg          # Example HAProxy frontend configuration

build.rs                 # Go c-archive build + Rust FFI generation
Cargo.toml
Cargo.lock
.gitlab-ci.yml
CHANGELOG.md
RELEASING.md
LICENSE
README.md
```

**Structure Decision**: Hybrid Rust+Go project following the fingerprinting
plugin's structure for the Rust side. The `go/` directory contains the Coraza
wrapper built as a `c-archive` by `build.rs`. E2E tests use docker-compose
with HAProxy + hub sidecar + nginx backend in a kind Kubernetes
cluster, testing the full SPOE request flow including SQL injection
and XSS blocking scenarios. Follows the same pattern as the
external-auth plugin's e2e tests.

## Complexity Tracking

> No Constitution Check violations to justify.
