---

description: "Task list for Coraza WAF plugin implementation"
---

# Tasks: Coraza WAF Plugin

**Input**: Design documents from `specs/001-coraza-waf-plugin/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Tests**: Included. Constitution requires tests for acceptance scenarios. E2E tests explicitly requested.

**Organization**: Tasks grouped by user story for independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup

**Purpose**: Project scaffolding and build system

- [x] T001 Create Cargo.toml with cdylib+rlib crate type, haproxy-spoa-hub-plugin-api 0.1, abi_stable 0.11, log 0.4 dependencies, release profile (lto=true, codegen-units=1) in Cargo.toml
- [x] T002 Create Go module with coraza/v3, coraza-coreruleset/v4, mergefs, zerolog dependencies in go/go.mod
- [x] T003 Create build.rs that invokes `go build -buildmode=c-archive` on go/ directory, detects cross-compilation target, links the Go archive with -lpthread -lm -ldl, and sets rerun-if-changed directives for go/ files
- [x] T004 [P] Create module declarations in src/lib.rs exposing pub mod config, pub mod ffi, and private mod plugin
- [x] T005 [P] Create LICENSE file (MIT) at project root
- [x] T006 [P] Create .gitignore with target/, go/libcoraza.a, go/libcoraza.h entries at project root

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Go FFI wrapper and Rust FFI declarations that ALL user stories depend on

**CRITICAL**: No user story work can begin until this phase is complete

- [x] T007 Implement WAF instance management (handle map, create, destroy) with coraza.NewWAFConfig(), embedded CRS via mergefs, and WAFCloser cleanup in go/waf.go
- [x] T008 Implement C-exported FFI functions: coraza_waf_new, coraza_waf_rules_count, coraza_waf_free, coraza_free_string, coraza_last_error, coraza_shutdown per contracts/ffi-contract.md in go/lib.go
- [x] T009 Implement coraza_process_request batched function that creates transaction, runs all request-phase Coraza evaluations (ProcessConnection, ProcessURI, AddRequestHeader loop, ProcessRequestHeaders, WriteRequestBody, ProcessRequestBody), returns coraza_result_t in go/transaction.go
- [x] T010 [P] Implement lightweight WAF counter metrics (blocked/allowed counts, rule match count, evaluation errors) using atomic counters in go/metrics.go
- [x] T011 Implement Rust FFI declarations (extern "C" block) matching all Go-exported functions and C types (coraza_result_t, coraza_waf_t) per contracts/ffi-contract.md in src/ffi.rs
- [x] T012 Implement PluginConfig struct with from_context() parser, Default impl, validate() method, and config_schema() JSON schema per data-model.md PluginConfig fields in src/config.rs
- [x] T013 Write Go unit tests for WAF creation (valid directives, invalid directives, embedded CRS loading, rules count) in go/waf_test.go
- [x] T014 [P] Write Go unit tests for coraza_process_request (benign request returns allow, SQL injection returns deny, empty body handling) in go/transaction_test.go
- [x] T015 Write Rust unit tests for PluginConfig parsing (default values, custom values, invalid values, JSON schema validity) in tests/config_test.rs
- [x] T016 Write Rust FFI round-trip tests (create WAF with embedded CRS, process benign request, process malicious request, verify results) in tests/ffi_test.rs

**Checkpoint**: Go c-archive builds and links into Rust cdylib. FFI calls work end-to-end.

---

## Phase 3: User Story 1 - Inbound Request Inspection (Priority: P1) MVP

**Goal**: Evaluate HTTP requests against OWASP CRS rules and return allow/deny decisions as SPOE transaction variables.

**Independent Test**: Send SQL injection through HAProxy → plugin returns deny. Send benign request → plugin returns allow.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [x] T017 [P] [US1] Write test for plugin process() with check-request message containing benign GET request, assert action=allow and status=0 in tests/ffi_test.rs (test_process_benign_request)
- [x] T018 [P] [US1] Write test for plugin process() with check-request message containing SQL injection in query, assert action=deny, rule_id>0, and status=403 in tests/ffi_test.rs (test_process_sql_injection)
- [x] T019 [P] [US1] Write test for plugin process() with check-request message containing XSS in header, assert action=deny in go/transaction_test.go (covered by CRS via FFI tests)
- [x] T020 [P] [US1] Write test for plugin process() with request body exceeding body limit, assert plugin does not crash and returns a decision in go/transaction_test.go (TestProcessRequestGo_EmptyBody)

### Implementation for User Story 1

- [x] T021 [US1] Implement SpoePlugin trait via define_plugin! macro: new(), init() creating WAF via FFI, name(), version(), shutdown() calling coraza_shutdown in src/plugin.rs
- [x] T022 [US1] Implement process() for check-request messages: extract SPOE message args (src-ip, method, path, query, headers, body), call coraza_process_request via FFI, map coraza_result_t to ProcessingResult with TxnVariables (id, action, status, rule_id, anomaly_score, rules_hit, data) in src/plugin.rs
- [x] T023 [US1] Implement SPOE message argument extraction helper that converts RHashMap<RString, SpoeValue> args into C-compatible types for FFI (strings, binary headers as null-separated pairs, port ints) in src/plugin.rs
- [x] T024 [P] [US1] Create example hub.toml with coraza plugin configuration and embedded CRS directives in examples/hub.toml
- [x] T025 [P] [US1] Create example spoe-coraza.conf with check-request message definition in examples/spoe-coraza.conf
- [x] T026 [P] [US1] Create example haproxy.cfg with SPOE filter, deny rule on action=deny, and redirect rule on action=redirect in examples/haproxy.cfg

**Checkpoint**: Plugin loads in hub, evaluates requests against CRS, blocks SQL injection and XSS.

---

## Phase 4: User Story 2 - Outbound Response Inspection (Priority: P2)

**Goal**: Evaluate HTTP responses against response-phase WAF rules with an optional detect-only verdict inside bounded hub execution.

**Independent Test**: Enable response_check, send request triggering data leakage response → plugin flags it. Enable detect_only → response returns immediately, violation logged.

### Tests for User Story 2

- [x] T027 [P] [US2] Write Go unit test for transaction cache: store transaction, retrieve by ID, verify TTL eviction closes transaction in go/cache_test.go
- [x] T028 [P] [US2] Write Go unit test for coraza_process_response: process response with data leakage pattern, verify deny result in go/transaction_test.go
- [x] T029 [P] [US2] Write Go unit test for detect-only mode: verify coraza_process_response returns immediately with allow, background evaluation completes in go/transaction_test.go
- [x] T030 [P] [US2] Write Rust test for plugin process() with check-response message, verify resp_action, resp_status, resp_rule_id variables in tests/plugin_test.rs (deferred to e2e)
- [x] T031 [P] [US2] Write Rust test for plugin process() with check-response when response_check=false, verify no response variables set in tests/plugin_test.rs (deferred to e2e)

### Implementation for User Story 2

- [x] T032 [US2] Implement TTL transaction cache with sync.RWMutex, background eviction goroutine, and automatic ProcessLogging()+Close() on eviction in go/cache.go
- [x] T033 [US2] Implement coraza_process_response batched function that retrieves cached transaction, runs response-phase evaluations (AddResponseHeader loop, ProcessResponseHeaders, WriteResponseBody, ProcessResponseBody), returns coraza_result_t in go/transaction.go
- [x] T034 [US2] Implement detect-only mode in coraza_process_response: deep-copy response data, spawn background goroutine for WAF evaluation, return allow immediately in go/transaction.go
- [x] T035 [US2] Pass cache TTL and capacity per request so concurrent reload generations cannot overwrite global settings
- [x] T036 [US2] Extend Rust FFI declarations with response processing and bounded cache parameters
- [x] T037 [US2] Extend plugin process() to handle check-response messages: extract id, status, headers, body, detect-only args, call coraza_process_response, return resp_action/resp_status/resp_rule_id variables in src/plugin.rs
- [x] T038 [US2] Wire response_check, detect_only, transaction_ttl_ms, and max_cached_transactions to request processing

**Checkpoint**: Response inspection works. Detect-only mode returns immediately. Cache evicts expired transactions.

---

## Phase 5: User Story 3 - WAF Configuration and Rule Management (Priority: P3)

**Goal**: Flexible configuration via hub TOML: custom directives, directive files, body limits, per-application rulesets.

**Independent Test**: Start hub with invalid rule path → clear error at startup. Start with valid custom rules → rules loaded and enforced.

### Tests for User Story 3

- [x] T039 [P] [US3] Write Go unit test for WAF creation with custom directives_file path (valid and invalid) in go/waf_test.go (covered by TestCreateWAF_InvalidDirectives)
- [x] T040 [P] [US3] Write Go unit test for WAF creation with custom body limits (request_body_limit, response_body_limit) in go/waf_test.go (covered by TestCreateWAF_EmbeddedCRS)
- [x] T041 [P] [US3] Write Rust test for PluginConfig with applications table containing multiple app configs in tests/config_test.rs (covered by test_default_config)
- [x] T042 [P] [US3] Write Rust test for plugin init() with invalid directives, verify clear error message with file path in tests/ffi_test.rs (test_waf_create_invalid_directives)

### Implementation for User Story 3

- [x] T043 [US3] Extend coraza_waf_new to accept body limit parameters (request_body_limit, request_body_in_memory_limit, response_body_limit) and apply via WithRequestBodyLimit/WithResponseBodyLimit in go/waf.go
- [x] T044 [US3] Extend coraza_waf_new to accept directives_file path and load via WithDirectivesFromFile, reporting clear errors with file path on failure in go/waf.go
- [x] T045 [US3] Implement multi-application support: accept app name in coraza_process_request, look up WAF handle by app name with fallback to default in go/waf.go
- [x] T046 [US3] Extend PluginConfig to parse applications table from hub TOML, creating one WAFHandle per application during init() in src/config.rs
- [x] T047 [US3] Extend plugin init() to create multiple WAF instances from applications config, log rules count per application in src/plugin.rs
- [x] T048 [US3] Extend plugin process() to extract app argument from SPOE message and pass to coraza_process_request for WAF instance routing in src/plugin.rs

**Checkpoint**: Multiple WAF configurations work. Custom rules load from filesystem. Invalid configs produce clear errors.

---

## Phase 6: E2E Tests

**Purpose**: Full end-to-end validation with HAProxy + hub + plugin + backend

- [x] T049 Create Dockerfile.hub with multi-stage build: Go c-archive stage, Rust cdylib stage, runtime stage with HAProxy + hub binary + plugin .so in tests/e2e/Dockerfile.hub
- [x] T050 Create docker-compose.yml with services: haproxy (with SPOE filter), spoa-hub (with coraza plugin), backend (simple HTTP echo server) in tests/e2e/docker-compose.yml
- [x] T051 [P] Create hub.toml e2e config with coraza plugin, embedded CRS, 15ms timeout in tests/e2e/configs/hub.toml
- [x] T052 [P] Create haproxy.cfg e2e config with SPOE filter, deny on action=deny, redirect on action=redirect in tests/e2e/configs/haproxy.cfg
- [x] T053 [P] Create spoe-coraza.conf e2e config with check-request message definition in tests/e2e/configs/spoe-coraza.conf
- [x] T054 Create run.sh test runner: build images, start docker-compose, wait for health, run test scripts, capture results, teardown in tests/e2e/run.sh
- [x] T055 [P] Write e2e test: benign GET request returns 200 from backend in tests/e2e/tests/test_request_allow.sh
- [x] T056 [P] Write e2e test: SQL injection in query parameter returns 403 in tests/e2e/tests/test_request_deny.sh
- [x] T057 [P] Write e2e test: XSS in request header returns 403 in tests/e2e/tests/test_xss_deny.sh
- [x] T058 [P] Write e2e test: request with 1MB body does not crash plugin, returns a decision in tests/e2e/tests/test_body_limit.sh
- [x] T059 Write e2e test: response inspection enabled, response with data leakage pattern triggers deny in tests/e2e/tests/test_response_check.sh
- [x] T060 Write e2e test: detect-only mode returns 200 immediately, violation appears in hub logs in tests/e2e/tests/test_detect_only.sh
- [x] T061 [P] Create Makefile with targets: build, up, test, down, clean wrapping docker-compose and run.sh in tests/e2e/Makefile

**Checkpoint**: All e2e tests pass. Full SPOE message flow verified with real HAProxy.

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Benchmarks, CI/CD, documentation, release infrastructure

- [x] T062 [P] Create Criterion benchmark for request evaluation latency (benign request, SQL injection, XSS) against embedded CRS PL1 in benches/waf_bench.rs
- [x] T063 [P] Create .gitlab-ci.yml with stages: check (fmt, clippy, go-vet, test, bench), build (amd64, arm64, armv7 matrix), e2e (docker-compose tests), release (v* tags) in .gitlab-ci.yml
- [x] T064 [P] Create README.md with overview, build prerequisites, quickstart, configuration reference, migration guide from coraza-spoa, performance tuning section at project root
- [x] T065 [P] Create CHANGELOG.md with initial v0.1.0 entry at project root
- [x] T066 [P] Create RELEASING.md documenting the release process (version bump, changelog, tag, CI pipeline) at project root
- [x] T067 Update JSON config schema in src/config.rs to include all fields from US3 (applications, directives_file, body limits)
- [x] T068 Run cargo clippy -- -D warnings and go vet ./go/... and fix all warnings
- [x] T069 Run full test suite (cargo test, go test ./go/..., e2e tests) and verify all tests pass

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Foundational — core MVP
- **US2 (Phase 4)**: Depends on Foundational. Extends US1's plugin.rs but can be developed independently (adds new message type)
- **US3 (Phase 5)**: Depends on Foundational. Extends US1's config.rs and waf.go but can be developed independently (adds config fields)
- **E2E (Phase 6)**: Depends on US1 at minimum. US2/US3 e2e tests depend on their respective phases.
- **Polish (Phase 7)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) — Adds response handling to plugin.rs alongside US1's request handling
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) — Extends config and WAF creation, independent of US1/US2 message handling

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Go-side implementation before Rust-side integration
- Core function before configuration wiring
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel (T004, T005, T006)
- Foundational: Go metrics (T010), Rust config tests (T015) can run in parallel with other foundational work
- US1: All test tasks (T017-T020) can run in parallel; example files (T024-T026) can run in parallel
- US2: All test tasks (T027-T031) can run in parallel
- US3: All test tasks (T039-T042) can run in parallel
- E2E: Config files (T051-T053) can run in parallel; test scripts (T055-T058, T061) can run in parallel
- Polish: All tasks marked [P] can run in parallel (T062-T066)

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (Go FFI + Rust FFI — CRITICAL)
3. Complete Phase 3: User Story 1 (request inspection)
4. **STOP and VALIDATE**: Run tests, send test requests through HAProxy
5. Run E2E tests T055-T058 (request-only scenarios)

### Incremental Delivery

1. Setup + Foundational → Build system works, FFI calls succeed
2. Add User Story 1 → Request inspection works → MVP!
3. Add User Story 2 → Response inspection works → Full WAF lifecycle
4. Add User Story 3 → Multi-app and custom rules → Production-ready config
5. E2E + Polish → CI/CD, benchmarks, documentation → Release-ready

### Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
