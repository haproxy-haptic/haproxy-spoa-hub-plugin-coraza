# Changelog

## [Unreleased]

### Added

- `validate()` now compiles directives against the **files the validator was handed**, not just the embedded CRS and the local filesystem. The hub's validator passes the request's data files under the `__staged_files` config key (haproxy-spoa-hub !220), and they are layered between the embedded CRS and the OS filesystem — so an `Include /etc/haproxy/general/crs/*.conf` resolves against the ruleset about to be deployed. The validator runs in the controller pod, where that path does not exist, so before this such a config could only be validated by not checking the ruleset at all.

  Staged files live entirely in memory (`testing/fstest.MapFS` behind a path-normalising wrapper). Nothing is written to disk, which keeps temp-dir cleanup, cross-request collisions and staging-root traversal out of a path that runs on every admission. Absolute paths work because the wrapper normalises to the unrooted form `io/fs` requires, while `Glob` answers in the caller's own spelling so Coraza's diagnostics name the paths the operator wrote.

### Security

- An `Include` that matches no files is now an **error** during `validate()`, where Coraza only warns. A ruleset that never reached the pod otherwise compiles to whatever the other includes contributed and validates clean — indistinguishable from one that arrived, with the WAF running silently short of rules. A rule-count check does not catch this: `@coraza.conf-recommended` contributes rules on its own, so the count stays non-zero with the entire ruleset absent.

  Validate-only, deliberately. Admission refuses a config whose files are not all present; the runtime path keeps Coraza's warning, so a fleet already running is not taken down by an upstream that disappeared after it was admitted.

### Notes

- No plugin-API version change: the files arrive in the existing `PluginContext.config` as a `ConfigValue::Table`. The key is absent at runtime, where the files are genuinely on disk and the OS filesystem layer serves them, so `process()` is untouched.
- `coraza_validate_directives` takes an additional `staged_files_json` parameter (NULL when the request carried no data files). This is the plugin's own Rust↔Go FFI, not the plugin API, so it affects nothing outside this repository.
- The empty-glob promotion is keyed on Coraza's message text, because Coraza attaches no structured field naming the pattern — only a line number. `TestPromoteEmptyGlobs_MatchesCorazaWording` fails if an upgrade changes the wording, since a silent no-op there would return the gate to fail-open.

## [0.8.0] - 2026-07-26

### Added

- New `matched_var` SPOE variable naming the request fields rules matched on, as a comma-separated list of `VARIABLE` or `VARIABLE:KEY` names — for example `REQUEST_FILENAME,ARGS_GET:id,REQUEST_LINE`. It answers "which field tripped this rule", which is what scoping a rule exclusion needs, and it carries **names only**: unlike `data` it never contains the matched value, so it needs no `expose_matched_data` gate and is safe in an access-log field.

  A list rather than a single name because there is no single right answer: a CRS block is usually anomaly-scored, so rules of several severities matched on different variables and the interrupting rule (949110) names none of them. The reported rule's own targets lead, then the rest most-severe-first; entries are deduplicated and capped at 5.

  Rules that declare no severity are ranked LAST, not first: Coraza reports unset severity as `-1`, which is numerically below every real severity including EMERGENCY, so ordering on the raw value would put CRS's administrative and reporting rules ahead of the actual attack rule and let them consume the entry cap.

  Only request-derived variables are reported, via an allowlist (`ARGS*`, `REQUEST_*`, `QUERY_STRING`, `PATH_INFO`, `FILES*`, `MULTIPART*`, `XML`, `JSON`). Without it the field reads `UNKNOWN` or `TX:inbound_anomaly_score_threshold`, because CRS's administrative and scoring rules match before the attack rule does — the allowlist also makes the field meaningful by construction, since everything it can name is a request input.

## [0.7.0] - 2026-07-19

### Added

- Per-matched-rule metrics: `rule_hits_total{phase, rule_id, severity, app}` counts every rule that fired on each evaluation — including rules on traffic that was ultimately allowed, which is the signal detect-mode tuning needs (`denials_total` only ever names the single interrupting rule). Severity is labeled with the standard ModSecurity names; rules that declare no severity (CRS administrative/reporting rules, reported as -1 by Coraza) are labeled `none`. The matched-rule list crosses the FFI as a compact JSON array in the new `coraza_result_t.matched_rules` field (heap-allocated, freed by the plugin alongside `data`). Series cardinality is bounded by (#distinct matched rules) x (#apps) x (2 phases) — severity is a dependent label of rule_id and does not multiply the product. A payload the plugin cannot decode increments `rule_hits_decode_errors_total{app}` so an FFI contract break is visible above debug logs.

## [0.6.0] - 2026-07-18

### Added

- Request messages support explicit `body-mode=none|buffered` and require
  `body-complete=true` for buffered inspection, preventing accidental WAF
  decisions over truncated request bodies.
- Bounded response-correlation storage through `max_cached_transactions`,
  with generation leases, synchronous expired-entry reclamation under
  pressure, and fail-closed admission when the cap is exhausted.
- Payload-safe observability controls: rule-match logging is disabled by
  default, matched data can be omitted, hashed, or sanitized and truncated,
  and HAProxy matched-data exposure is separately opt-in.

### Changed

- WAF generations are plugin-instance-owned, compiled completely before an
  atomic swap, and retired only after cached transactions from that generation
  finish. Failed or repeated reloads no longer leak handles or disturb the
  serving policy.
- Unknown application names now fail closed instead of falling back to the
  default WAF. Named applications inherit effective top-level body limits and
  directive files for fields they do not override.
- Response detect-only evaluation is synchronous inside the hub's bounded
  plugin execution permit; it no longer creates unbounded background
  goroutines.
- Transaction identifiers include a process-wide sequence, avoiding response
  cache collisions across SPOP connections and HAProxy processes.
- The standalone default enables `SecRxPreFilter` through the public runtime
  directive and places `SecRuleEngine On` after the recommended configuration
  so enforcement is not reset to detection-only.
- Development and release workflows are available through Make targets; Go
  tests run with the race detector and stable Coraza build tags.

### Fixed

- Coraza `drop` and unknown disruptive actions now fail closed even when no HTTP status is attached.
- Missing request `body-mode` defaults to header-only inspection, and request-triggerable parse failures stay at debug log level to prevent partial-body bypasses and log amplification.
- Request/response body processing errors and cache exhaustion fail closed with
  explicit engine status codes; detect-only cannot coerce engine failures into
  allows.
- Interior null bytes, oversized FFI lengths, malformed validator output, and
  partial application-generation failures are rejected without memory-unsafe
  fallback behavior.
- Request-derived matched data and panic payloads are no longer logged or
  returned by default.

## [0.5.0] - 2026-05-15

### Added

- **Prometheus metrics** via the `haproxy-spoa-hub` v0.6.0 plugin-API v2 vtable. The plugin emits counters / histograms through the hub's `/metrics` endpoint; all names appear under the `plugin_coraza_` prefix the hub adds. Requires hub v0.6.0+ for the dispatcher to install the recorder; the plugin loads on v0.5.x hubs too but emissions become silent no-ops.
- Metric set:

  | metric                         | kind      | labels                          |
  |--------------------------------|-----------|---------------------------------|
  | `evaluations_total`            | counter   | `phase`, `action`, `app`        |
  | `evaluation_duration_seconds`  | histogram | `phase`, `app`                  |
  | `denials_total`                | counter   | `phase`, `rule_id`, `app`       |

  `phase` ∈ `{request, response}`; `action` is whatever the Coraza WAF returned (`allow` / `deny` / `detect`, etc.); `app` is the per-application name from `app_name` arg (empty string on the response path where the FFI looks up app by tx_id). `denials_total` is emitted only when `action="deny"` — separate counter so "which rules are blocking traffic" is a single PromQL query without a join.

### Changed

- Plugin-API dep bumped `^0.5` → `^0.6` to pick up the `MetricRecorder` helper and `metrics_static` macro arm. Vtable change is append-only, so v0.5.0 .so files still load on v0.5.x hubs (metrics silent there); see hub v0.6.0 CHANGELOG.

## [0.4.2] - 2026-05-05

### Fixed

- `validate()` now uses `PluginConfig::from_context(context)` and
  iterates the typed `config.applications: Vec<AppConfig>` instead of
  walking the raw `PluginContext` with its own assumptions about shape.
  v0.4.1 had two parallel parsers: `init()` went through `from_context`
  (read `applications` as a TOML table keyed by app name), while
  `validate()` had its own helper `validate_applications` that read
  `applications` as a TOML array. This drift caused validator-sidecar
  passes to silently skip per-application directive validation in
  HAPTIC's chart rendering (where `applications` is rendered as a
  table), letting broken Coraza directives slip past admission and only
  fail at HAProxy reload time. Routing both code paths through
  `from_context` collapses the two schemas into one source of truth.

### Changed

- Plugin authors writing `validate()` overrides should no longer do
  structural validation of `PluginContext` fields against the schema
  declared by `config_schema()`. The hub
  (`haproxy-spoa-hub` v0.5.2+) now schema-checks the `PluginContext`
  centrally — at load time AND on every validator-socket dispatch —
  before calling `validate()`. Plugins can rely on `from_context()`
  succeeding and only need to do *semantic* validation (e.g. compiling
  SecLang directives). See the `define_plugin!` docstring in
  haproxy-spoa-hub-plugin-api for the full contract.

### Tests

- Existing `invalid_application_directives_yield_prefixed_error` was
  rewritten against the canonical table-keyed-by-name `applications`
  schema (the one `from_context` and `config_schema` agree on), to
  prevent regressing back to the array shape.
- New `multiple_applications_each_validated_with_own_name_prefix` pins
  per-app prefix isolation: with two apps each carrying broken
  directives, every diagnostic is prefixed with the right app name and
  no diagnostics leak between apps.

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
