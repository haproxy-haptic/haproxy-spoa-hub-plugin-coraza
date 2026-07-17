# SPOE Variable Contract — `detect-only` on Request-Side Delta

**Feature**: [../spec.md](../spec.md) | **Base contract**: [`/specs/001-coraza-waf-plugin/contracts/spoe-variables.md`](../../001-coraza-waf-plugin/contracts/spoe-variables.md)

This delta extends the `check-request` input argument set with one new optional argument. All other parts of the contract (output variables, response-side message, FFI signature for response, scoping rules) are unchanged.

## `check-request` — added input argument

| Argument | Type | Source (HAProxy fetch) | Description |
|----------|------|------------------------|-------------|
| `detect-only` | bool | Literal or `var(txn.<n>)` from a per-route map | When `true`, the plugin evaluates rules normally but coerces the verdict to `action=allow` even when a rule fires; `rule_id`, `anomaly_score`, and `rules_hit` remain populated. Bounded `data` remains opt-in. When `false` or absent, the verdict is enforced. Falls back to the hub-global `detect_only` config when malformed or wrong-type. |

The argument name `detect-only` is the same name and type used on the existing `check-response` message; operators may symmetrically wire it on both messages without conditional HAProxy config.

## Interaction with existing `check-request` input arguments

When `detect-only` is absent or has the wrong type, the plugin falls back to the hub-global `config.detect_only` setting (current behaviour, unchanged). When `detect-only` is set to `true` or `false`, the per-message value wins regardless of the global default. This means `detect-only=false` is NOT a no-op when the global is `true` — it explicitly overrides the global to enforce the verdict for this transaction.

| `app` | `detect-only` | Effect |
|---|---|---|
| absent | absent | Default WAF instance evaluates; verdict per `config.detect_only`. |
| set | absent | Selected WAF instance evaluates; verdict per `config.detect_only`. |
| absent | `true` | Default WAF instance evaluates; verdict coerced to `allow`. |
| set | `true` | Selected WAF instance evaluates; verdict coerced to `allow`. |
| absent | `false` | Default WAF instance evaluates; verdict enforced (overrides global). |
| set | `false` | Selected WAF instance evaluates; verdict enforced (overrides global). |
| absent | malformed | Same as `detect-only` absent (falls back to global). |
| set | malformed | Same as `detect-only` absent (falls back to global). |

## Metrics behaviour

| Scenario | `metricsAllowed` | `metricsBlocked` | `metricsRulesHit` |
|----------|------------------|------------------|-------------------|
| Benign request, any `detect-only` | +1 | 0 | 0 |
| Malicious request, no `detect-only` | 0 | +1 | +N |
| Malicious request, `detect-only=true` | +1 | 0 | +N |
| Malicious request, `detect-only=false` | 0 | +1 | +N |
| Malicious request, malformed `detect-only` | per `config.detect_only` | per `config.detect_only` | +N |

`metricsRulesHit` MUST increment by the number of matched rules in every case — the rules executed regardless of whether the verdict was enforced.

## FFI signature delta — `coraza_process_request`

The private co-built C ABI carries `detect_only` after the per-request cache
TTL and capacity. Later hardening added matched-data controls after it; the
canonical current signature lives in the base FFI contract.

The Go-side `coraza_process_request` declaration MUST gain the same parameter and honour it after the existing rule evaluation: if `detect_only != 0` and `interrupted == true`, the result's `action` is coerced to `allowAction` and the metric is reclassified from `metricsBlocked` to `metricsAllowed` before returning.

## Backward compatibility

- The Rust-side caller (`src/plugin.rs::process_request`) resolves an absent or malformed argument through the global `config.detect_only` default — preserving current behavior for operators not using the override.
- The Go-side function is decorated with `//export coraza_process_request`; adding a parameter to a Cgo-exported function is a breaking change to the C ABI. Because Rust and Go are built together in the same plugin, the FFI is private to this crate's build — no external consumers — and the parameter addition is fine within a MINOR Cargo version bump for this plugin.
- Existing operator HAProxy configs that don't set `detect-only` on the request side see no behaviour change.
