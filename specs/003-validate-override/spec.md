# Feature Specification: `validate()` Override for SecLang Directive Compile-Check

**Feature Branch**: `003-validate-override`
**Created**: 2026-05-03
**Status**: Draft
**Input**: User description: "Coraza plugin's `validate()` override for per-Ingress modsecurity-snippet line/col error surfacing through the new validator-sidecar pipeline"

## Background

`haproxy-spoa-hub-plugin-api` v0.3 (specs `004-validate-mode` + `005-plugin-api-validate`) introduced a deep `validate(&PluginContext) -> Vec<Diagnostic>` method on the `SpoePlugin` trait. Plugins that override it produce structured findings that the hub can run in two places:

1. In production, before `init()` — a non-empty error list aborts startup with line/column-precise diagnostics in logs.
2. In validator-sidecar mode (`hub --validate-socket <path>`), where HAPTIC's controller pushes proposed configs over a unix socket and uses the plugin's diagnostics to drive the Kubernetes admission webhook's accept/reject decision.

For the Coraza plugin specifically, the deep validation is a SecLang **compile-check**: feed the operator-supplied directives string to `coraza.NewWAF(WithDirectives(...))`, capture the SecLang parser's structured log events (which carry `line` fields), and translate any captured warnings/errors into `plugin_api::Diagnostic` values.

This closes the per-Ingress modsecurity-snippet gap end-to-end on the plugin side: a HAProxyTemplateConfig CR change that contains broken Coraza directives is rejected by the admission webhook with line numbers pointing at the offending row, rather than silently shipping to the cluster and crashing the plugin's `init()`.

## Clarifications

### Session 2026-05-03

- Q: What range of inputs should `validate()` cover? → A: The top-level `directives` field AND every `applications[].directives` entry. Both are SecLang strings the plugin compiles via `coraza.NewWAF` at `init()` today; both are equally ways an operator can ship broken rules. The other config fields (`directives_file`, body limits, `detect_only`, `transaction_ttl_ms`, `response_check`) are either not directives, or are structural (covered by the existing `config_schema` JSON-Schema check), so they need no `validate()` work here. Per-app diagnostics MUST be tagged with the application name so operators can find which Ingress's snippet is broken when several apps load in the same plugin instance.

- Q: How are line numbers captured? → A: Coraza's SecLang parser logs `Warn()` and `Error()` events through the WAF's debug logger with an `Int("line", N)` field (see `internal/seclang/parser.go:202` for the `logAndReturnErr` path). The plugin's Go side attaches a custom `debuglog.Logger` implementation that records every Warn/Error event into an in-memory slice; on `coraza.NewWAF` failure, the captured slice plus the wrapped error message are JSON-encoded and returned across the FFI boundary. The Rust side deserialises that JSON into `Vec<Diagnostic>`.

- Q: What about errors that don't carry a line number (e.g., the wrapped "failed to compile the directive" path)? → A: Use `0` for `line`/`column` per the plugin-api delta's "unknown / file-level" semantic. The captured diagnostics already cover the more common operator-typo case (unknown directive — `logAndReturnErr` emits a line number); compile-failures from the directive's own implementation propagate the error message but lose precise positioning. Acceptable trade-off: operators see "unknown variable" with the directive name in the message, just without the row pointer.

- Q: How is the `path` field on `Diagnostic` populated? → A: Plugins MUST leave `path` empty (`RString::new()`); the hub overwrites it post-hoc with the file identity it knows about (`files[].path` in validator-sidecar mode, `--config <path>` in production). Plugins don't have access to file identity (their input is the parsed `[plugins.params.coraza]` subtree, decoupled from the file it came from). The 7 unit tests in `src/plugin.rs` enforce this invariant.

- Q: What's the cost of one `validate()` call? → A: Coraza's `NewWAF` allocates rule structures and compiles regexes but doesn't open sockets, spawn goroutines, or touch shared state. Empirically, validating a typical CRS-bundled config (~200 rules) is sub-100ms. Validator-sidecar mode caches results by content-hash on the HAPTIC side, so repeat calls for the same config are O(1) lookups and only changed configs incur the WAF-init cost.

- Q: Does `validate()` need to be reentrant / thread-safe? → A: Yes. The plugin-api delta says `validate()` MUST be pure — no global state mutation, no goroutine fan-out. Each call constructs a fresh WAF instance with its own captured-diagnostic slice and lets the WAF drop at the end. Concurrent calls from a multi-threaded validator orchestrator are independent. The Go runtime is process-global but each `coraza.NewWAF` invocation is independent.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Per-Ingress modsecurity-snippet caught at admission (Priority: P1)

A platform operator has the Coraza WAF deployed via HAPTIC. An application team adds `nginx.ingress.kubernetes.io/modsecurity-snippet: |` with a typo (`SecResquestBodyAccess On` instead of `SecRequestBodyAccess On`) on their Ingress. HAPTIC's controller renders the snippet into the per-app `[[applications]]` block of the hub TOML; before pushing, it calls the validator sidecar with the proposed config; the sidecar invokes the Coraza plugin's `validate()`; Coraza's parser emits `Error(line=3, "unknown directive 'secresquestbodyaccess'")`; HAPTIC translates the diagnostic into a webhook rejection on the Ingress with `line: 3` highlighted.

**Why this priority**: This is the immediate gap blocking HAPTIC from honouring per-Ingress modsecurity-snippets safely. Without it, broken snippets ship to the cluster and surface either as plugin-init failures (entire HAProxy data plane down) or as silent "rule didn't fire" misconfigurations (false sense of security).

**Independent Test**: Build a `[[applications]]` table with `name = "test-ingress"` and `directives = "SecResquestBodyAccess On\n"` in a hub TOML config. Send it over the validate socket. Verify the response is `result: "error"` with at least one `Diagnostic { severity: Error, line: 1, message: "...unknown directive 'secresquestbodyaccess'..." }`. Verify the message is prefixed with `application 'test-ingress':`.

**Acceptance Scenarios**:

1. **Given** the operator's config has a top-level `directives = ""` (empty string), **When** the validator sidecar calls `validate()`, **Then** an empty `Vec<Diagnostic>` is returned (empty input is valid; no plugin-side errors).
2. **Given** the operator's config has a top-level `directives = "SecRuleEngine On\n"` (valid), **When** the validator calls `validate()`, **Then** no `Error`-severity diagnostics are returned (warnings about unused features are ignored).
3. **Given** the operator's config has a top-level `directives = "SecBogusDirective foo\n"` (unknown directive), **When** the validator calls `validate()`, **Then** at least one `Error` diagnostic is returned with `line = 1`.
4. **Given** the operator's config has a top-level `directives` with a typo on line 3 (`SecResquestBodyAccess On`), **When** the validator calls `validate()`, **Then** at least one `Error` diagnostic carries `line = 3`.
5. **Given** the operator's config has `[[applications]]` with `name = "ingress-prod-foo"` and `directives = "SecBogusDirective foo\n"`, **When** the validator calls `validate()`, **Then** at least one `Error` diagnostic is returned with the message prefixed by `application 'ingress-prod-foo': ` so the operator knows which Ingress's snippet is broken.
6. **Given** every diagnostic produced, **When** the hub inspects them before sending the wire response, **Then** every `Diagnostic.path` is empty so the hub can fill it with the file identity it knows about.

---

### Edge Cases

- **`applications` is missing.** Skipped silently; only the top-level `directives` field is checked. Schema validation rejects malformed `applications` entries before `validate()` runs.
- **`applications[i].name` is missing.** Diagnostics are prefixed with `application '<unnamed>':`. The schema check requires `name` so this should be unreachable in practice; the fallback exists so a future schema relaxation doesn't crash the prefix logic.
- **Same line, multiple findings.** Coraza's parser may emit several events on the same line (e.g., a directive that's both unknown AND emits a glob warning). Each event yields its own `Diagnostic`; no de-duplication. The hub passes them through; the admission webhook may format them as multiple cells against the same line.
- **`directives_file` is set.** Out of scope. `validate()` only checks the inline `directives` strings; file-based rule loading is validated at `init()` time (the file path may not exist at admission time anyway since the validator sidecar runs in HAPTIC's namespace, not in HAProxy pods). The schema check ensures `directives_file` and `directives` aren't both set.
- **Concurrent validate calls.** Each call builds an independent `coraza.NewWAF` instance with its own captured-diagnostic slice; no shared mutable state. Safe to call from multiple goroutines.
- **`coraza.NewWAF` panics.** The Go side's `defer recoverPanic("coraza_validate_directives")` catches it; the FFI returns `[]` (empty diagnostics). This is acceptable: a panic during validation indicates a Coraza bug, which is rare; the alternative would be to surface a synthetic "internal: panic during validation" diagnostic, but that's caller-facing noise for a case that should never trigger.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST override the trait method `validate(&self, &PluginContext) -> Vec<Diagnostic>` on `SpoePlugin`. The default empty-vec impl is replaced by per-field SecLang compile-checks.
- **FR-002**: For the top-level `directives` config field (when present), the plugin MUST compile the string via `coraza.NewWAF(WithDirectives(...))`, capturing parser warnings/errors via a custom `debuglog.Logger` implementation that records `line` from `Int("line", N)` fields. Each captured event MUST be returned as a `Diagnostic` with the appropriate severity (`Warning` or `Error`) and the captured line number.
- **FR-003**: For each `applications[].directives` config field (when present), the plugin MUST compile the string the same way and prefix each resulting diagnostic message with `application '<name>': ` so the operator can identify which entry is broken. The `<name>` MUST come from the same `[applications]` table's `name` field (or `<unnamed>` if absent).
- **FR-004**: Every `Diagnostic` produced by `validate()` MUST leave `path` empty (`RString::new()`). The hub overwrites `path` post-hoc with file identity it knows about (per the plugin-api `004-validate-mode` contract).
- **FR-005**: When `coraza.NewWAF` returns an error string that doesn't carry a line number (e.g., `"failed to compile the directive 'secrule': unknown variable"`), the plugin MUST still emit an `Error`-severity diagnostic carrying the wrapped error message with `line = 0` and `column = 0` (the "unknown / file-level" sentinel). Operators see the error message just without the precise row pointer.
- **FR-006**: An empty `directives` string (or absent field) MUST yield zero diagnostics; absence is not an error from the plugin's POV (validation has multiple input sources; `validate()` is not the place to enforce required fields — `config_schema` is).
- **FR-007**: `validate()` MUST be pure: no goroutine fan-out, no network I/O, no file I/O beyond what the `PluginContext` carries. Each call drops its `coraza.NewWAF` instance before returning. Safe for concurrent invocation by a multi-threaded validator orchestrator.

### Non-Functional Requirements

- **NFR-001**: A typical `validate()` call (CRS-bundled config, ~200 rules) MUST complete in under 100ms on a 2026-era developer laptop. The validator sidecar caches results by content-hash on the HAPTIC side, so repeat calls for the same config are O(1) lookups; this budget applies only to changed configs.
- **NFR-002**: Memory cost of one `validate()` call MUST be bounded by Coraza's `NewWAF` allocation (one rule-tree + one transaction template). The captured-diagnostic slice grows with the number of parser events; for malformed configs this is at most a few hundred entries. The slice is dropped at the end of the call.

### Key Entities

- **`capturedDiagnostic`** (Go-side, internal): a `{severity, line, message}` triple that mirrors the Rust `Diagnostic` but with `string` severity (`"warning"` / `"error"`). JSON-marshalled across the FFI.
- **`capturedLogger`** / **`capturedEvent`** (Go-side, internal): implement `coraza/v3/debuglog.Logger` and `debuglog.Event` to record `Int("line", N)` and `Msg(...)` calls into a Go slice.
- **`coraza_validate_directives`** (FFI): one new exported C symbol returning a heap-allocated C string of the JSON-encoded captured slice. Caller MUST free via `coraza_free_string`.

## Success Criteria *(mandatory)*

- **SC-001**: All seven acceptance scenarios in User Story 1 are covered by Rust unit tests in `src/plugin.rs` (`mod validate_tests`), exercising both the top-level `directives` field and per-app `applications[]` entries, both valid and invalid inputs, and the line-number capture path. The user-facing requirement "invalid custom Coraza configs are caught by the validate step" is covered by `unknown_directive_yields_diagnostic_with_line_number`, `invalid_directive_yields_error`, and `invalid_application_directives_yield_prefixed_error`.
- **SC-002**: The Go-side `coraza_validate_directives` exported function passes through the existing `recoverPanic` defer so a Coraza-side panic during validation cannot crash the validator sidecar.
- **SC-003**: The plugin's Cargo.toml bumps `haproxy-spoa-hub-plugin-api` to `"0.3"` and the plugin's own version to `0.3.0`. Dependencies on `serde` and `serde_json` are added at runtime (the JSON-encoded FFI payload is parsed at `validate()` call time).
- **SC-004**: The plugin's CHANGELOG entry under `[Unreleased]` documents the feature in keep-a-changelog format and the next release is a MINOR bump (additive: new method override, no behavioural change to existing methods).
- **SC-005**: Production callers of `init()` continue to fail closed on invalid directives (deny-by-default). `validate()` is additive: existing operators that don't use the validator-sidecar feature see no behaviour change.

## Out of Scope

- HAPTIC chart wiring (validator sidecar container, shared volume, CRD `validators` field, controller LRU cache, /healthz socket-existence check). Tracked in HAPTIC's repository under track #25; depends on this MR landing first so the protocol is stable.
- Otel plugin's `validate()` override (track #24). Same plugin-api pattern, different inputs (OTLP endpoint URL parse, header validity). Tracked separately so the Coraza release isn't blocked by Otel work.
- Validating `directives_file` paths. The validator sidecar runs in HAPTIC's namespace; file paths in the operator's config refer to the HAProxy pod's filesystem, not the validator's. Schema check ensures `directives` and `directives_file` aren't both set.
- Surfacing line numbers for the wrapped "failed to compile the directive" path. Coraza's parser doesn't log a line-numbered event for this case; we'd need to upstream a parser change to capture `currentLine` in the wrapped error. Out of scope here; the message contains the directive name so operators can find the row by `grep`.
- Performance optimisation beyond the 100ms budget. If validate becomes a bottleneck under HAPTIC's CRD reconciliation rate, the right fix is HAPTIC-side content-hash caching, not plugin-side micro-optimisation.
