# Research: Coraza WAF Plugin

## R1: Go-to-Rust FFI Strategy

**Decision**: Use Go `c-archive` (static linking) to embed the Coraza WAF engine into the Rust cdylib plugin.

**Rationale**: `c-archive` produces a `.a` file that is statically linked into the Rust cdylib. This avoids runtime library path issues and the `dlclose` problem with Go `c-shared` libraries (golang/go#11100 — Go runtime cannot be shut down once started). The hub loads the plugin `.so` via `abi_stable`/`dlopen`; with static linking, the Go runtime is embedded inside and starts automatically.

**Alternatives considered**:
- `c-shared` (.so): Rejected because `dlclose` is unsupported by Go runtime; would cause issues if the hub ever reloads the plugin library. Also requires `LD_LIBRARY_PATH` or rpath management.
- Separate Go process with IPC: Rejected because the entire purpose of this plugin is to eliminate IPC overhead between HAProxy and the WAF.
- WASM compilation of Coraza: Rejected due to WASM runtime overhead and lack of mature WASM-to-native integration for this use case.

**Key constraints**:
- Only one Go `c-archive` library can exist per process (loading multiple causes runtime conflicts: golang/go#65050).
- Go runtime signal handlers will be installed when the plugin loads. The hub must not install conflicting signal handlers for SIGSEGV/SIGBUS/SIGFPE.
- CGo call overhead is ~30 ns/call (Go 1.26), negligible compared to WAF rule evaluation time (~100-500 µs).
- The Rust `build.rs` must invoke `go build -buildmode=c-archive` and link the output with `-lpthread -lm -ldl`.

## R2: Coraza v3 API Surface

**Decision**: Expose a minimal C FFI wrapper (~16 functions) covering WAF creation, transaction lifecycle, and interruption retrieval.

**Rationale**: Coraza v3 uses a clean interface-based Go API. The FFI surface maps 1:1 to the `types.Transaction` pipeline phases. Keeping the FFI surface minimal reduces CGo overhead and simplifies memory management.

**Key API elements**:
- WAF creation: `NewWAFConfig()` + chained `With*()` methods + `NewWAF()`
- Transaction: `NewTransactionWithID(id)` → `ProcessConnection` → `ProcessURI` → `AddRequestHeader` (loop) → `ProcessRequestHeaders` → `WriteRequestBody` → `ProcessRequestBody`
- Response: `AddResponseHeader` (loop) → `ProcessResponseHeaders` → `WriteResponseBody` → `ProcessResponseBody`
- Cleanup: `ProcessLogging()` → `Close()`
- Interruption: `Interruption()` returns `{RuleID, Action, Status, Data}`

**Alternatives considered**:
- Exposing the full Coraza API via FFI: Rejected — too many functions, complex memory management. Better to batch operations in the Go wrapper (e.g., `process_full_request` takes all args at once).
- Using a serialization protocol (protobuf/JSON) across FFI: Rejected — adds serialization overhead. Direct C types are faster.

## R3: CRS Embedding Strategy

**Decision**: Embed OWASP CRS v4 via `coraza-coreruleset/v4` Go package, merged with OS filesystem using `mergefs`.

**Rationale**: The `coreruleset.FS` provides an `fs.FS` implementation with all CRS rules embedded. `mergefs.Merge(coreruleset.FS, io.OSFS)` layers filesystem rules on top, allowing operator customization. This is the exact pattern used by coraza-spoa.

**Alternatives considered**:
- Filesystem-only loading: Rejected — requires operators to ship and manage CRS rule files separately.
- Embed-only without filesystem override: Rejected — prevents operators from customizing rules without rebuilding.

## R4: Performance Optimization Strategy

**Decision**: Apply a multi-layered optimization strategy targeting GC pressure, FFI call count, and Coraza build tags.

**Rationale**: Based on Coraza team's 100x throughput improvement research and ngrok's production deployment experience.

**Optimizations to apply**:

1. **Go runtime tuning**: Keep GC enabled and set `GOMEMLIMIT` below the container memory limit, leaving headroom for Rust, CRS, and native allocations. Disabling GC is unsafe for a request-facing plugin because hostile traffic can force growth until OOM kill.

2. **Coraza build tags**:
   - `SecRxPreFilter On` — public runtime directive for regex pre-filtering; do not depend on Coraza's internal build tag across minor versions
   - `coraza.rule.multiphase_evaluation` — evaluate rules in earlier phases when variables are ready
   - `coraza.rule.no_regex_multiline` — disable multiline regex (aligns with CRS expectations)

3. **Batched FFI calls**: Instead of individual calls per header/phase, expose composite functions (`process_full_request`, `process_full_response`) that accept all data in one CGo crossing, reducing the ~30 ns/call overhead multiplied by header count.

4. **Body buffering**: Default request body limit of 4KB (ngrok's production value). Configurable per-application.

5. **Transaction pooling**: Coraza internally uses `sync.Pool` for transactions. The Go wrapper should also pool FFI-level buffers for result serialization.

6. **Zero-allocation logging**: Use zerolog in the Go wrapper (10-11% performance gain when debug logging disabled).

**Alternatives considered**:
- Using `unsafe` Go pointers across FFI: Rejected — violates cgo pointer-passing rules, would cause runtime panics.
- Custom memory allocator for Go: Rejected — too complex, diminishing returns vs. GOMEMLIMIT approach.

## R5: Transaction Caching for Response Inspection

**Decision**: Use a Go-side TTL cache (`sync.Map` with expiry goroutine or a dedicated cache library) keyed by transaction ID.

**Rationale**: Response messages arrive as separate SPOE messages and need the same Coraza transaction that processed the request phase. A TTL of 10 seconds (configurable) covers the typical request-response window while preventing memory leaks from abandoned transactions.

**Implementation approach**:
- Request phase: create transaction, process request, cache by ID, return decision + ID variable
- Response phase: retrieve transaction by ID from cache, process response, close transaction, remove from cache
- Eviction callback: close transaction on TTL expiry
- Detect-only mode: deep-copy response data, spawn background goroutine for evaluation, return immediately

**Alternatives considered**:
- istio/pkg/cache (used by coraza-spoa): Considered but brings a heavy dependency. A simple `sync.Map` + ticker-based eviction is sufficient.
- Passing transaction handle across FFI to Rust, then back: Rejected — would require maintaining Go pointers in Rust memory, violating cgo rules.

## R6: Cross-Compilation Strategy

**Decision**: Use Docker-based CI with cross-compilation toolchains for arm64 and armv7, matching the fingerprinting plugin's CI approach.

**Rationale**: CGo requires a C cross-compiler for each target. Docker containers with pre-installed toolchains (`gcc-aarch64-linux-gnu`, `gcc-arm-linux-gnueabihf`) are the most reliable approach.

**Build matrix**:
- amd64: native Go + Rust build
- arm64: `GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc` for Go, `--target aarch64-unknown-linux-gnu` for Rust
- armv7: `GOOS=linux GOARCH=arm GOARM=7 CC=arm-linux-gnueabihf-gcc` for Go, `--target armv7-unknown-linux-gnueabihf` for Rust

**Alternatives considered**:
- QEMU emulation: Rejected — much slower than cross-compilation.
- Native builds on target hardware: Rejected — impractical for CI.
