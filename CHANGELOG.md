# Changelog

## [Unreleased]

## [0.4.1] - 2026-05-05

### Fixed

- WAF handle and config now actually swap on every `init()`, not just the first. The plugin previously stored both in `OnceLock`, so the second `init()` (e.g. after a `haproxy-spoa-hub` SIGHUP / file-watch reload) silently dropped the new handle and kept serving requests against the first init's WAF — which the first `Drop` had already freed. Every post-reload request hit the Go-side WAF-engine-error path and came back as `action="deny", rule_id=0`, masquerading a default-deny as a rule decision. State now lives in a single `OnceLock<RwLock<State>>`; `init()` swaps both fields and frees the previous handle in one critical section, and `process()` holds the read lock across the FFI call so a parallel reload waits for in-flight requests to drain before swapping. Surfaced via downstream HAPTIC's per-Ingress `nginx.ingress.kubernetes.io/modsecurity-snippet` integration.

## [0.4.0] - 2026-05-04

### Changed

- **BREAKING**: Bumped `haproxy-spoa-hub-plugin-api` dependency to `0.5` (the hand-rolled `#[repr(C)]` vtable migration). This plugin's `.so` will only load on `haproxy-spoa-hub` v0.5.0 or newer. Older hubs reject the load with a "missing required symbol 'get_plugin_vtable'" error since the entry-symbol naming changed. Plugin source code is unchanged — the `define_plugin!` macro absorbed the FFI shape difference.
- Dropped the direct `abi_stable = "0.11"` dependency. Plugin-api re-exports the abi_stable types this crate uses (`RString`, `RVec`, `RHashMap`, etc.); no direct dep is required.

## [0.3.0] - 2026-05-03

### Added

- `validate()` override on the `SpoePlugin` trait (plugin-api v0.3+).
  The plugin now compiles the operator-supplied SecLang `directives`
  string (and every `applications[].directives` entry) via
  `coraza.NewWAF(WithDirectives(...))`, capturing the parser's
  structured `Warn()`/`Error()` events and returning them as
  `Vec<Diagnostic>` with the line numbers Coraza emits via
  `Int("line", N)`. Per-application diagnostics are prefixed with
  `application '<name>': ` so operators can identify which Ingress's
  modsecurity-snippet is broken when several apps load in the same
  plugin instance. Used by HAPTIC's validator-sidecar mode (hub's
  `--validate-socket`) to reject Ingress changes carrying broken
  Coraza directives at admission time, with line numbers highlighted
  in the webhook response. Spec at `specs/003-validate-override/`.
- One new exported FFI symbol `coraza_validate_directives` returning a
  JSON-encoded `[{severity,line,message},...]` slice. Caller MUST free
  via `coraza_free_string`. Internal to the crate's Rust+Go co-build.

### Changed

- Bumped `haproxy-spoa-hub-plugin-api` dependency from `0.2` to `0.3`
  (additive trait method `validate()` with default empty-vec impl;
  pre-v0.3 plugins continue to build).
- Added `serde` and `serde_json` as runtime dependencies (used by
  `validate()` to deserialise the JSON-encoded diagnostics returned
  from the Go side).

## [0.2.0] - 2026-05-03

### Added

- Per-message `detect-only` override on the request-side `check-request`
  message. When `detect-only=true` is set on the SPOE message, the WAF
  evaluates rules normally but coerces the verdict to `action=allow` while
  keeping `rule_id`, `anomaly_score`, `rules_hit`, and `data` populated;
  the metric increment is reclassified from `metricsBlocked` to
  `metricsAllowed`. Mirrors the existing response-side override of the
  same name. Spec at `specs/002-detect-only-request/`.

### Changed

- The C ABI of `coraza_process_request` gains one trailing `c_int
  detect_only` parameter. The FFI is private to this crate's build
  (Rust and Go are co-built) so this is not an externally observable ABI
  change.

### Fixed

- Metrics: CRS anomaly-scoring blocks (rules 949110/949111 inbound,
  959100/959101 outbound) are now correctly counted as `metricsBlocked`
  instead of `metricsAllowed`. The previous code keyed off the local
  `interrupted` boolean, which is set only by the Coraza interruption
  path; the CRS anomaly-scoring branch in `buildResult` populates the
  result with `actionDeny` and `status=403` without setting
  `interrupted`. The new condition uses `result.status != 0` as the
  canonical deny indicator, capturing both branches. Operators
  monitoring these counters will see `metricsBlocked` increase and
  `metricsAllowed` decrease for traffic that triggers CRS anomaly
  thresholds.
- Transaction cache: blocked requests (including the CRS anomaly path
  above) no longer cache the transaction for the response phase. Under
  the previous condition, CRS-anomaly-blocked transactions were cached
  even though the request was denied and no response phase would run,
  leaking the cached transaction until TTL eviction.

## [0.1.1] - 2026-04-28

### Added

- Release artifacts (plugin `.so` files) published to the GitLab Generic
  Package Registry under `packages/generic/coraza/<tag>/` with stable URLs
- Per-file `<artifact>.sha256` sidecars and a combined `SHA256SUMS` for
  batch verification with `sha256sum -c SHA256SUMS`
- Cosign keyless signatures (`<artifact>.cosign.bundle`) for every release
  artifact, signed via the GitLab OIDC id token (Sigstore Fulcio + Rekor)
- `make verify-release VERSION=vX.Y.Z` target plus `scripts/verify-release.sh`
  for end-to-end consumer verification (downloads `SHA256SUMS`, checks all
  hashes, runs `cosign verify-blob` against the project's tag identity)
- Unsigned SLSA v0.2 provenance metadata emitted next to build artifacts
  via `RUNNER_GENERATE_ARTIFACTS_METADATA` (free SLSA-L1)

### Changed

- Release builds now use `cargo auditable build --release`, embedding a
  compressed `Cargo.lock`-equivalent in every binary so SBOM tools can
  enumerate Rust dependencies without source access

## [0.1.0] - 2026-04-12

### Added

- Initial release of the Coraza WAF plugin for haproxy-spoa-hub
- HTTP request inspection against OWASP CRS v4 rulesets
- Response-phase inspection with detect-only async mode
- Embedded CRS v4 with filesystem override via mergefs
- Multi-application WAF configuration support
- Lightweight WAF metrics (blocked/allowed counts, rule matches, errors)
- CRS anomaly scoring detection (rules 949110/949111)
- Transaction caching with configurable TTL for request-response correlation
- Go c-archive statically linked into Rust cdylib
- Cross-compilation support for amd64, arm64, armv7
- E2E test suite with docker-compose
- Criterion benchmarks for request evaluation latency
