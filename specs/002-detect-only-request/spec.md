# Feature Specification: Per-Message `detect-only` Override on Request-Side Messages

**Feature Branch**: `002-detect-only-request`
**Created**: 2026-05-03
**Status**: Draft
**Input**: User description: "Per-message detect-only override on request-side messages for waf-mode annotation parity"

## Background

The plugin already accepts a per-message `detect-only` SPOE argument on **response-side** messages (see `src/plugin.rs:208-210`):

```rust
let detect_only = message.get_bool("detect-only").unwrap_or(config.detect_only);
```

When `detect-only=true` on a response, the Go side spawns the WAF evaluation in a background goroutine and returns `allowResult()` immediately — the operator sees rule matches in logs/metrics but the response is never blocked (`go/transaction.go:259-271`).

The **request-side** path has no such override. `process_request` reads `app` (per-message WAF instance routing) but not `detect-only`. The plugin's hub-global `detect_only` config (set in TOML / hub context) applies uniformly to every request, with no way to flip a single Ingress to detect mode without affecting all others. Closing this gap is the only plugin change needed to make HAPTIC's `haproxy-ingress.github.io/waf-mode` annotation per-route.

The hub-global `detect_only` flag *is* already plumbed through the Go side for the request path indirectly: `tx.IsRuleEngineOff()` (`go/transaction.go:143`) honours the WAF instance's own engine setting, but that is a hub-init-time choice, not a per-message one. We need a per-message flag on the request side that tells Go "even if a rule fires, return `allow` and let HAProxy keep the rule_id / anomaly_score for the operator's own decision".

## Clarifications

### Session 2026-05-03

- Q: Does request-side `detect-only` mean "evaluate but don't block" (current response-side meaning) or "log violations but don't even evaluate"? → A: "Evaluate but don't block." Rules MUST still be evaluated so `rule_id`, `anomaly_score`, `rules_hit`, and `data` return variables carry the WAF's findings; the only thing that changes is `action`, which becomes `allow` even when rules would have caused a `deny`. This matches the response-side semantics from the operator's POV ("I see what would have happened, and I still pass the request through") while keeping evaluation cost on the request side. Note: response-side detect-only currently SKIPS synchronous evaluation entirely (background goroutine); request-side detect-only is different because the request hasn't been served yet — we want the rule_id information for HAProxy's logging/decision rules.
- Q: How does the `detect-only` argument interact with `app` (per-message WAF instance routing)? → A: They are orthogonal. `app` selects which WAF instance evaluates the request; `detect-only` decides whether the verdict is enforced. Both can be set, neither set, or just one set — all combinations are valid.
- Q: What happens when `detect-only` is set but the WAF would have allowed the request anyway? → A: No-op. `detect-only=true` only changes `deny` → `allow`; it does not change `allow` to anything.
- Q: Does request-side `detect-only` affect the metrics counters (`coraza_metrics_blocked` / `coraza_metrics_allowed`)? → A: Yes. A request that *would* have been blocked but is allowed by detect-mode counts as `metricsAllowed`, not `metricsBlocked`. The `rules_hit` counter still increments for every matched rule regardless. This matches the response-side path's metric semantics: detect-only requests that were never enforced are reported as allowed.
- Q: How is a malformed `detect-only` value handled (e.g., the SPOE arg is a string `"yes"` instead of a bool)? → A: Ignore the override and fall back to the hub-global `config.detect_only` default. Rationale: `SpoeMessage::get_bool` already returns `None` for malformed/wrong-type values, and the existing response-side code uses `.unwrap_or(config.detect_only)` for exactly this reason. Mirror that behaviour. Unlike the otel plugin's `_root`/`_sample` overrides, we do NOT add a malformed-counter health gauge here because (a) `get_bool` already coerces gracefully and (b) the WAF plugin's existing health surface is intentionally lightweight.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Per-route detect mode for incoming requests (Priority: P1)

A platform operator runs HAPTIC with the Coraza plugin in deny-by-default mode (hub-global `detect_only = false`). One application team wants to dry-run the WAF against their traffic without blocking real requests — they want to see rule matches in HAProxy logs and adjust their app to comply, but they cannot tolerate the WAF returning 403s during the trial period. They put `haproxy-ingress.github.io/waf-mode: detect` on their Ingress. HAPTIC translates this to a per-host+path SPOE argument (`detect-only=true`) on the request-side `check-request` message. The plugin honours the override only for that route; every other Ingress remains in deny mode.

**Why this priority**: This is the immediate gap blocking HAPTIC from closing the `waf-mode` annotation. Without it, operators can't roll out WAF rules safely in stages — their only option is hub-global detect-mode, which loses the security benefit for all routes simultaneously.

**Independent Test**: Configure the plugin with hub-global `detect_only = false` and a request that would normally trigger a CRS rule (e.g., SQL injection in the query). Send two SPOE messages: one with `detect-only=true`, one without. Verify the first returns `action=allow` with non-zero `rule_id`; the second returns `action=deny` with the same `rule_id`. Both should increment the `rules_hit` counter; only the second should increment `metricsBlocked`.

**Acceptance Scenarios**:

1. **Given** the plugin is configured with hub-global `detect_only = false` and a request whose query contains `' OR 1=1 --`, **When** the request-side message arrives without `detect-only`, **Then** the plugin returns `action=deny`, the matched CRS rule ID, and `metricsBlocked` increments.
2. **Given** the same plugin config and the same malicious query, **When** the request-side message arrives with `detect-only=true`, **Then** the plugin returns `action=allow`, the SAME matched rule ID, the SAME anomaly score, and `metricsAllowed` (not `metricsBlocked`) increments. `rules_hit` increments for every rule matched.
3. **Given** the plugin is configured with hub-global `detect_only = true`, **When** a request arrives with `detect-only=false`, **Then** the per-message override wins: a malicious request returns `action=deny` and `metricsBlocked` increments — even though the global default is detect-only.
4. **Given** a benign request that triggers no rules, **When** the request-side message arrives with `detect-only=true`, **Then** the result is identical to a benign request without the override: `action=allow`, `rule_id=0`, `metricsAllowed` increments. Detect mode is a no-op when nothing matches.
5. **Given** a request-side message with `detect-only` set to a malformed value (string `"yes"` rather than bool), **When** the message is dispatched, **Then** the override is ignored and the hub-global `config.detect_only` default applies. No health counter increment specific to malformed values is required (the WAF plugin's existing surface is lightweight).

---

### Edge Cases

- **`detect-only=true` interaction with `app` routing.** Both arguments coexist; `app` selects the WAF instance, `detect-only` overrides the verdict mode for that instance for this message. The hub-global `detect_only` of the *selected* instance is the fallback when `detect-only` is absent (currently the plugin uses `CONFIG.detect_only` regardless of app — that's a separate concern not in scope here).
- **Cross-side asymmetry between `detect-only=true` on request and response.** Request-side detect-mode evaluates synchronously and returns the verdict immediately; response-side detect-mode kicks evaluation to a background goroutine and returns `allow` without waiting. This asymmetry is intentional: the request hasn't been served yet, so the operator needs `rule_id` synchronously to drive logging or shadow-banning rules in HAProxy. The response side has nothing to gate, so backgrounding is purely a latency optimisation.
- **`detect-only=true` on a request that errors during evaluation (FFI panic, recovered).** Coraza errors return `denyResult()` today (FR-008 in the 001 spec, deny-by-default). With `detect-only=true`, this becomes `allowResult()` — failing open in detect mode is consistent with the operator's "don't block, log only" intent. The `metricsErrors` counter still increments. (This combination is not exposed as a separate scenario because it's the natural composition of the existing error path with the new detect-only flag.)
- **Concurrent requests with mixed `detect-only` values.** Each SPOE message is independent; the override is per-message. Two concurrent requests with different `detect-only` values evaluate in different WAF transactions and yield different verdicts. No shared state.
- **Reload during in-flight transactions.** The `detect_only` flag is read from the request-side message at evaluation time; subsequent reloads cannot change the verdict for an already-evaluated transaction.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST accept a request-side SPOE argument named `detect-only` of bool type. When `true` and the WAF would otherwise deny, the plugin MUST return `action=allow` while keeping the matched `rule_id`, `anomaly_score`, `rules_hit`, and `data` return variables populated. When absent or `false`, the verdict is unmodified.
- **FR-002**: When `detect-only=true` is honoured and a rule fires, the plugin MUST increment `coraza_metrics_allowed`, NOT `coraza_metrics_blocked`. The `coraza_metrics_rules_hit` counter MUST increment for every matched rule regardless of the override.
- **FR-003**: A per-message `detect-only` value MUST take precedence over the hub-global `config.detect_only` setting for the duration of one transaction. Mirroring `src/plugin.rs:208-210`, malformed or wrong-type values MUST fall back to `config.detect_only` via `.get_bool().unwrap_or(config.detect_only)`.
- **FR-004**: The plugin's FFI signature `coraza_process_request` MUST gain a `detect_only` C int parameter (0 or 1). The corresponding Go-side `coraza_process_request` MUST honour the flag by coercing the result's `action` to `"allow"` and reclassifying the metric increment from blocked to allowed when the flag is set and the WAF would otherwise have denied.
- **FR-005**: The plugin's documented SPOE variable contract under this feature's `contracts/` and the consolidated reference under `specs/001-coraza-waf-plugin/contracts/spoe-variables.md` MUST list `detect-only` under the `check-request` input arguments table, alongside `app`.
- **FR-006**: Existing operator configurations that do not pass `detect-only` on the request side MUST take the same code path as today; no behaviour change for the absent-arg case.

### Non-Functional Requirements

- **NFR-001**: Per-message `detect-only` evaluation MUST NOT add measurable latency at the plugin's existing performance budget. The argument lookup is a single `get_bool` call already used on the response side; the FFI gains one extra c_int parameter; the Go-side check is one if-branch on the result. None of these change the asymptotic cost of the WAF evaluation itself.

### Key Entities

- The new `detect-only` request-side argument is a stateless per-message override. No new state, no cache, no map.

## Success Criteria *(mandatory)*

- **SC-001**: HAPTIC's `haproxy-ingress.github.io/waf-mode: detect | deny` annotation can be implemented end-to-end (annotation on Ingress → map file → SPOE argument → plugin override → action coerced to allow with rule metadata) using only operator-side templating; no further plugin patch required after this MR lands.
- **SC-002**: A request-side message without `detect-only` takes the same code path as today, with no new allocations, no new branches outside the override block. Verified by the existing test suite (`go/transaction_test.go` and others) continuing to pass without modification.
- **SC-003**: All five acceptance scenarios in User Story 1 are covered by tests: (a) Rust-side unit tests in `src/plugin.rs` covering the SPOE arg parsing, (b) Go-side tests in `go/transaction_test.go` covering the FFI plumbing and metric reclassification, and (c) at least one integration-style test that exercises the full request-side path with a CRS rule and verifies metric counters.
- **SC-004**: The CHANGELOG entry under `[Unreleased]` documents the feature in keep-a-changelog format and the next release is a MINOR bump (additive change to the SPOE input-argument set, no breaking changes to existing inputs or outputs).

## Out of Scope

- Per-route custom rule loading (`nginx.ingress.kubernetes.io/modsecurity-snippet`). Better solved at the chart layer using ConfigMap → pre-baked WAF apps + the existing `app` SPOE argument. No plugin change needed.
- Per-route OWASP CRS toggle. Same approach: pre-bake one WAF instance with CRS enabled, one without, and select via `app`.
- Exposing `tx_id` to HAPTIC's `nginx.ingress.kubernetes.io/modsecurity-transaction-id` annotation. Already implemented: `src/plugin.rs:247` emits `id` as a transaction-scoped return variable. HAPTIC just needs to wire it.
- Changing the response-side `detect-only` semantics. The async/background goroutine handling on the response side is a deliberate latency optimisation and remains unchanged.
- HAPTIC integration. HAPTIC's chart-side annotation library and SPOE-arg wiring is a separate change in `charts/haptic/libraries/spoa-hub.yaml` and `charts/haptic/libraries/haproxy-ingress.yaml` (the prefix-owner library for `haproxy-ingress.github.io/waf-mode`). Tracked in HAPTIC's repository, not here.
