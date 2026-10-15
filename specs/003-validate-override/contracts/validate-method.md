# `validate()` Method Contract — Coraza Plugin Delta

**Feature**: [../spec.md](../spec.md) | **Plugin-API contract**: [`haproxy-spoa-hub/specs/004-validate-mode/contracts/plugin-api-delta.md`](https://github.com/haproxy-haptic/haproxy-spoa-hub/blob/main/specs/004-validate-mode/contracts/plugin-api-delta.md)

This delta describes the Coraza-plugin-specific behaviour of the `SpoePlugin::validate()` method introduced by `haproxy-spoa-hub-plugin-api` v0.3. It does not redefine the trait (that's the upstream contract above); it only documents what diagnostics this plugin emits and how the per-field check is wired.

## Inputs consumed

`validate()` reads the following keys from the `PluginContext.config` map (the parsed `[plugins.params.coraza]` subtree):

| Key | TOML type | Semantics |
|-----|-----------|-----------|
| `directives` | string | Inline SecLang directives. Compiled via `coraza.NewWAF(WithDirectives(...))`. |
| `applications` | array of tables | Per-app overrides. Each table's `directives` field is compiled the same way; per-app diagnostics are tagged with the table's `name` field. |

All other keys (`directives_file`, body limits, `detect_only`, `transaction_ttl_ms`, `response_check`) are not touched by `validate()` — they are either non-directive structure (covered by `config_schema` JSON-Schema validation) or refer to runtime resources not available at validate time (e.g., file paths in the HAProxy pod's filesystem).

## Diagnostics emitted

For each input field above, the plugin compiles the SecLang string via Coraza's parser. The parser logs structured events through the WAF's debug logger; the plugin captures them via a custom `debuglog.Logger` impl and translates them into `Diagnostic` values:

| Coraza event | Severity | Line | Message |
|-----|-----|-----|-----|
| `Logger.Warn().Int("line", N).Msg(M)` | `Warning` | `N` | `M` |
| `Logger.Error().Int("line", N).Msg(M)` | `Error` | `N` | `M` |
| `coraza.NewWAF` returns wrapped error without a logged event | `Error` | `0` | wrapped error string |

For per-application directives (entries under `applications[]`), each diagnostic's message is prefixed with `application '<name>': ` so operators can identify which entry owns the broken rules. `<name>` is the `name` field of the same `[applications]` table; if absent (schema violation, should be unreachable), the prefix uses `<unnamed>`.

The `column` field is always `0` (Coraza's parser tracks line but not column). The `path` field is always empty (`RString::new()`); the hub overwrites it post-hoc with the file identity it knows about.

## Calling pattern

```text
HAPTIC controller renders new TOML config
  → POSTs ValidateRequest{plugins: [{ name: "coraza", config: <subtree>, files: [...] }]} to validator socket
  → hub orchestrator dispatches to coraza plugin's validate()
  → plugin compiles every `directives` string via coraza.NewWAF, captures parser events
  → plugin returns Vec<Diagnostic> (each with empty `path`)
  → hub fills `path` from files[i].path, marshals as ValidateResponse
  → controller decodes, pushes to admission webhook
  → webhook rejects/accepts the source CR
```

## FFI delta

One new exported C symbol on the Go side. The Rust side declares a matching `extern` and never owns the returned buffer past the synchronous `validate()` call.

```c
char *coraza_validate_directives(const char *directives, int directives_len);
// Returns heap-allocated JSON-encoded `[{"severity","line","message"}, ...]`.
// Caller MUST free via coraza_free_string. Empty array on success.
// On internal errors (Go-side panic recovered, JSON marshal failure)
// returns either "[]" or a single-entry slice with the error message.
```

No changes to existing FFI signatures (`coraza_waf_new`, `coraza_process_request`, etc.). The new symbol is additive; pre-v0.3 plugin builds remain ABI-compatible because the Rust side's only consumer is `validate()`, which is itself an additive trait method.

## Cost model

| Phase | Cost |
|-----|-----|
| `coraza_validate_directives` call | One `coraza.NewWAF` invocation: rule-tree allocation + regex compile. Sub-100ms for ~200 rules. |
| Captured-diagnostic slice | At most a few hundred entries for malformed input; dropped at end of call. |
| Cross-FFI JSON marshal/unmarshal | One JSON encode (Go) + one JSON decode (Rust) per call. Negligible relative to NewWAF. |

The validator sidecar caches results by content-hash on the HAPTIC side, so repeat calls for the same config are O(1) lookups; this budget applies only to changed configs.

## Reentrancy

`validate()` is pure per the plugin-api delta:

- No global state mutation. Each call constructs a fresh `coraza.NewWAF` and drops it before returning.
- No goroutine fan-out. The Go side runs on the calling goroutine.
- No network I/O. No file I/O beyond what `coraza.NewWAF(WithDirectives(...))` does internally (none — the inline string path doesn't touch the filesystem).
- Safe for concurrent invocation by a multi-threaded validator orchestrator.

## Test coverage

| Test | Acceptance Scenario |
|-----|-----|
| `empty_config_yields_no_diagnostics` | AS-1 (empty input is valid) |
| `empty_directives_string_yields_no_diagnostics` | AS-1 (empty string is valid) |
| `valid_directives_yield_no_errors` | AS-2 (valid config: no errors) |
| `invalid_directive_yields_error` | AS-3 (unknown directive: at least one Error) |
| `unknown_directive_yields_diagnostic_with_line_number` | AS-4 (unknown directive on line N: diagnostic carries line N) |
| `invalid_application_directives_yield_prefixed_error` | AS-5 (per-app diagnostic carries app-name prefix) |
| `diagnostics_have_empty_path_for_hub_to_fill` | AS-6 (path is empty so hub can fill) |
