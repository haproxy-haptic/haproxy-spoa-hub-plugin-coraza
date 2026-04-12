# Feature Specification: Coraza WAF Plugin for haproxy-spoa-hub

**Feature Branch**: `001-coraza-waf-plugin`
**Created**: 2026-04-12
**Status**: Draft
**Input**: User description: "Implement a haproxy-spoa-hub plugin for the Coraza WAF"

## Clarifications

### Session 2026-04-12

- Q: Should the plugin use coraza-spoa message names or hub-native names? → A: Hub-native message names (e.g., `check-request`, `check-response`) with a documented variable name mapping for migration from standalone coraza-spoa.
- Q: How should request-response transaction correlation work? → A: Cache transactions by unique ID with configurable TTL (default 10s). Request phase sets the ID; response phase passes it back. Evicted transactions are automatically closed.
- Q: Should OWASP CRS rules be embedded in the plugin binary? → A: Embedded with filesystem override — CRS embedded as default, filesystem rules merged on top (coraza-spoa approach).
- Q: Should the plugin expose WAF-specific Prometheus metrics? → A: Lightweight WAF counters — blocked/allowed request counts, rule match count, evaluation errors.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Inbound Request Inspection (Priority: P1)

An operator configures the Coraza WAF plugin in their haproxy-spoa-hub deployment to inspect incoming HTTP requests against OWASP CRS rulesets. When HAProxy receives an HTTP request, it forwards the request metadata (source IP, method, path, query, headers, body) to the hub via the SPOE protocol. The Coraza plugin evaluates the request against loaded WAF rules and returns a decision (allow or deny) along with metadata (matched rule ID, action, anomaly score) as transaction variables. HAProxy then enforces the decision by either passing the request through or returning an error page.

**Why this priority**: Request inspection is the core WAF function. Without it, the plugin has no value. This eliminates the double-IPC cost for operators who already use haproxy-spoa-hub for other plugins alongside Coraza.

**Independent Test**: Send a known-malicious request (e.g., SQL injection in a query parameter) through HAProxy with the plugin loaded and verify the request is blocked. Send a benign request and verify it passes.

**Acceptance Scenarios**:

1. **Given** a running hub with the Coraza plugin loaded and OWASP CRS rules configured, **When** a request containing `' OR 1=1 --` in a query parameter arrives, **Then** the plugin returns `action=deny` with the matched rule ID and HAProxy rejects the request.
2. **Given** a running hub with the Coraza plugin loaded, **When** a normal GET request for `/index.html` arrives, **Then** the plugin returns `action=allow` and HAProxy forwards the request to the backend.
3. **Given** a running hub with the Coraza plugin loaded, **When** a request with a large body exceeding the configured body limit arrives, **Then** the plugin evaluates only the buffered portion and returns a decision without memory exhaustion.

---

### User Story 2 - Outbound Response Inspection (Priority: P2)

An operator enables response inspection to detect data leakage or other response-phase rule violations. After the backend responds, HAProxy forwards response metadata (status code, headers, body) to the plugin, which evaluates it against response-phase rules. The plugin returns a decision and metadata. Response inspection can optionally run in detect-only mode, where the plugin logs violations but does not block, returning the decision asynchronously to avoid adding latency to the response path.

**Why this priority**: Response inspection completes the WAF evaluation lifecycle (phases 3-4 of ModSecurity/Coraza). Many CRS rules operate on responses (e.g., data leakage detection). However, many deployments can function with request-only inspection.

**Independent Test**: Configure response inspection, send a request that triggers a response containing sensitive data patterns (e.g., credit card numbers in the body), and verify the plugin flags it. Test detect-only mode by verifying the response is delivered immediately while the violation is logged.

**Acceptance Scenarios**:

1. **Given** response inspection is enabled, **When** a backend response contains patterns matching a data leakage rule, **Then** the plugin returns `action=deny` with the matched rule ID.
2. **Given** response inspection is enabled with detect-only mode, **When** a backend response triggers a rule, **Then** the plugin returns immediately (does not block the response) and logs the violation asynchronously.
3. **Given** response inspection is disabled (default), **When** a response arrives, **Then** the plugin does not evaluate it and no response-phase variables are set.

---

### User Story 3 - WAF Configuration and Rule Management (Priority: P3)

An operator configures the Coraza WAF plugin via the hub's TOML configuration, specifying WAF directives (SecLang rules), paranoia level, body processing limits, and which OWASP CRS rules to load. The plugin validates the configuration at startup and reports errors clearly. The operator can also configure per-application rulesets to apply different WAF policies to different HAProxy frontends or backends.

**Why this priority**: Configuration flexibility determines whether the plugin can serve diverse deployment scenarios. However, a working plugin with sensible defaults (P1) is more valuable than configuration flexibility.

**Independent Test**: Start the hub with an intentionally invalid WAF configuration (e.g., a nonexistent rule file path) and verify the plugin reports a clear error at startup. Start with a valid configuration and verify rules are loaded by sending a request that matches a rule.

**Acceptance Scenarios**:

1. **Given** a valid configuration with OWASP CRS rules, **When** the hub starts, **Then** the plugin loads all rules and logs the count of loaded rules.
2. **Given** an invalid rule file path in the configuration, **When** the hub starts, **Then** the plugin reports a clear error message naming the missing file and the hub does not proceed with a broken WAF.
3. **Given** multiple application configurations, **When** requests arrive with different `app` identifiers, **Then** each request is evaluated against the corresponding application's ruleset.

---

### Edge Cases

- What happens when the Coraza WAF engine encounters a malformed request that cannot be parsed (e.g., invalid HTTP version, truncated headers)? The plugin MUST NOT crash; it should return a configurable default action (deny-by-default).
- What happens when the request body exceeds the configured memory limit? The plugin evaluates only the buffered portion without spilling to disk or consuming unbounded memory.
- What happens when the Go runtime experiences a garbage collection pause during request processing? The plugin must still respond within the hub's per-plugin timeout. GC tuning and memory pooling strategies must minimize tail latency.
- What happens when the hub reloads configuration (SIGHUP)? The plugin must reinitialize the WAF engine with the new configuration without leaking resources from the previous instance.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The plugin MUST evaluate HTTP requests against Coraza WAF rules and return a decision (allow/deny) as a transaction variable.
- **FR-002**: The plugin MUST return metadata variables: action type, HTTP status code to return on deny, matched rule ID, anomaly score, and the number of matched rules.
- **FR-003**: The plugin MUST embed OWASP CRS v4 rules as a built-in default and support loading additional rules from the filesystem, merged on top of the embedded baseline.
- **FR-004**: The plugin MUST support configurable request body buffering limits to prevent memory exhaustion.
- **FR-005**: The plugin MUST support optional response-phase inspection with a detect-only async mode. Request-response correlation MUST use a transaction cache keyed by unique ID with a configurable TTL (default 10 seconds). Evicted transactions MUST be automatically closed.
- **FR-006**: The plugin MUST support multiple independent WAF application configurations selectable per request.
- **FR-007**: The plugin MUST expose a JSON schema for its configuration parameters to enable hub-side validation.
- **FR-008**: The plugin MUST default to a deny action when the WAF engine state is uncertain or when rule evaluation fails.
- **FR-009**: The plugin MUST integrate with the hub's logging system using structured log fields (plugin name, rule ID, action, latency).
- **FR-010**: The plugin MUST compile as a Rust cdylib compatible with the haproxy-spoa-hub plugin API, embedding the Go-based Coraza WAF engine via FFI.
- **FR-011**: The plugin MUST track lightweight WAF-specific metrics: blocked/allowed request counts, rule match count, and evaluation error count. These MUST be readable via the FFI interface and logged on shutdown. Note: the hub plugin API does not currently support registering custom Prometheus metrics; integration with the hub's Prometheus endpoint requires a hub API extension.

### Key Entities

- **WAF Instance**: A compiled set of Coraza rules representing a security policy. Created once at startup, shared across all requests. One instance per configured application.
- **Transaction**: A short-lived evaluation context for a single HTTP request (and optionally its response). Created per request, returned to a pool after evaluation.
- **Processing Decision**: The result of WAF evaluation containing allow/deny action, matched rule metadata, anomaly score, and any response variables to set in HAProxy.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Request evaluation latency added by the plugin remains below 1ms at p99 under normal operating conditions (baseline CRS PL1 ruleset, requests under 4KB body).
- **SC-002**: The plugin handles at least 10,000 concurrent requests per second on a single core without request drops or timeouts.
- **SC-003**: Memory usage remains stable (no growth trend) over 1 million processed requests, confirming absence of memory leaks.
- **SC-004**: The plugin detects and blocks at least 99% of OWASP CRS test cases for SQL injection, XSS, and command injection at Paranoia Level 1.
- **SC-005**: Operators migrating from standalone coraza-spoa can adopt the plugin with only configuration changes (hub TOML config, SPOE message names, HAProxy variable references). A migration guide documents the mapping between coraza-spoa variable names and hub-namespaced variable names.
- **SC-006**: Plugin startup time (including WAF rule compilation) completes within 5 seconds for a full OWASP CRS v4 ruleset.

## Assumptions

- The haproxy-spoa-hub plugin API (v0.1, abi_stable 0.11) is stable and will not change during development.
- The Coraza WAF engine (coraza.io/coraza/v3) will be embedded via Go-to-C FFI (`cgo -buildmode=c-shared`), producing a C-compatible shared library that the Rust plugin links against. This is the only practical approach to embed a Go library in a Rust cdylib without introducing additional IPC.
- OWASP CRS v4 rules are the primary ruleset target. Custom SecLang rules are also supported but not the primary test target.
- The Go runtime overhead (goroutine scheduler, garbage collector) is an accepted cost. The optimization strategy focuses on minimizing GC pressure through object pooling, `GOGC` tuning, and bounded memory allocation rather than eliminating the runtime.
- The plugin uses hub-native SPOE message names (`check-request`, `check-response`) rather than the coraza-spoa names (`coraza-req`, `coraza-res`). A migration guide maps coraza-spoa variable names to hub-namespaced equivalents.
- The plugin targets Linux only (same as haproxy-spoa-hub). Cross-compilation for arm64 and armv7 is required.
- The project structure, build configuration, CI/CD pipeline, and release process follow the patterns established by the fingerprinting plugin repo.
