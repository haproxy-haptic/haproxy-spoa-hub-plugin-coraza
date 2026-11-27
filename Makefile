.PHONY: build build-backends build-release test test-go fuzz-go bench-go bench-ffi fmt lint no-replace check test-e2e verify-release

GO_TAGS := coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline

build:
	cargo build

build-release:
	cargo build --release

# Keep the installed Go filename stable so existing hub configs keep working.
CARGO ?= cargo
GO_TARGET_DIR ?= target/go
RUST_TARGET_DIR ?= target/rust
BUNDLE_DIR ?= target/plugin-bundle
TARGET_FLAG = $(if $(RUST_TARGET),--target $(RUST_TARGET))
RELEASE_DIR = $(if $(RUST_TARGET),$(RUST_TARGET)/)release

build-backends:
	$(CARGO) build --locked --release $(TARGET_FLAG) --target-dir "$(GO_TARGET_DIR)" --no-default-features --features go-backend
	$(CARGO) build --locked --release $(TARGET_FLAG) --target-dir "$(RUST_TARGET_DIR)" --no-default-features --features rust-backend
	$(MAKE) stage-backends

# The Go compiler consumes a native CPU profile, including for cross builds.
.PHONY: build-profiled-backends stage-backends
PGO_DRIVER ?= .pgo-tools/scripts/pgo/build.sh
build-profiled-backends:
	test -n "$(RUST_TARGET)"
	mkdir -p "$(GO_TARGET_DIR)"
	cd go && go test -pgo=off -run '^$$' -bench '^BenchmarkEvaluationPlugin$$' -benchtime=5s -tags "$(GO_TAGS)" -cpuprofile "$(abspath $(GO_TARGET_DIR))/evaluation.pprof" -o "$(abspath $(GO_TARGET_DIR))/evaluation.test" .
	GOFLAGS="$(GOFLAGS) -pgo=$(abspath $(GO_TARGET_DIR))/evaluation.pprof" CARGO_TARGET_DIR="$(GO_TARGET_DIR)" $(PGO_DRIVER) "$(RUST_TARGET)" --no-default-features --features go-backend
	CARGO_TARGET_DIR="$(RUST_TARGET_DIR)" $(PGO_DRIVER) "$(RUST_TARGET)" --no-default-features --features rust-backend
	$(MAKE) stage-backends

stage-backends:
	install -D -m 755 "$(GO_TARGET_DIR)/$(RELEASE_DIR)/libcoraza_plugin.so" "$(BUNDLE_DIR)/libcoraza_plugin.so"
	install -D -m 755 "$(RUST_TARGET_DIR)/$(RELEASE_DIR)/libcoraza_plugin.so" "$(BUNDLE_DIR)/libcoraza_rust_plugin.so"

test-go:
	cd go && go test -race -tags "$(GO_TAGS)" ./...

# Fuzz the hand-written matched-rule encoder against encoding/json.
FUZZTIME ?= 30s
fuzz-go:
	cd go && go test -tags "$(GO_TAGS)" -run '^$$' -fuzz '^FuzzAppendMatchedRulesJSON$$' -fuzztime $(FUZZTIME) .

# Evaluation cost against Coraza alone with the chart-default CRS (HAPTIC#697).
# AB_ROUNDS > 0 also runs the interleaved latency comparison.
AB_ROUNDS ?= 0
BENCH ?= ^BenchmarkEvaluation
BENCH_FLAGS ?= -benchtime=3s -count=1
bench-go:
	cd go && CORAZA_AB_ROUNDS=$(AB_ROUNDS) go test -tags "$(GO_TAGS)" -run '^TestEvaluationLatencyAB$$' -bench '$(BENCH)' $(BENCH_FLAGS) .

# The same evaluation called from a Rust thread across cgo, as the hub calls it.
# FFI_PACE_US > 0 sleeps before each call to model low request rates.
FFI_ROUNDS ?= 2000
FFI_PACE_US ?= 0
bench-ffi:
	CORAZA_FFI_ROUNDS=$(FFI_ROUNDS) CORAZA_FFI_PACE=$(FFI_PACE_US) cargo bench --bench evaluation_ffi

test: build test-go
	cargo test

fmt:
	cargo fmt
	cd go && gofmt -w .

lint: no-replace
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings
	@test -z "$$(gofmt -l go)" || { gofmt -l go; exit 1; }
	cd go && go vet -tags "$(GO_TAGS)" ./...

# A replace silently overrides the required version that Renovate bumps and reviewers read.
no-replace:
	@replaced="$$(cd go && go list -m -f '{{with .Replace}}{{$$.Path}} => {{.Path}} {{.Version}}{{end}}' all)"; \
	if [ -n "$$replaced" ]; then \
		printf 'go/go.mod replaces required modules, so the build does not use the versions it requires:\n%s\nRemove the replace directive.\n' "$$replaced" >&2; \
		exit 1; \
	fi

check: lint test

test-e2e:
	$(MAKE) -C tests/e2e

verify-release:
ifndef VERSION
	$(error VERSION not set; usage: make verify-release VERSION=vX.Y.Z)
endif
	@scripts/verify-release.sh "$(VERSION)"
