.PHONY: build build-release test test-go fmt lint no-replace check test-e2e verify-release

GO_TAGS := coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline

build:
	cargo build

build-release:
	cargo build --release

test-go:
	cd go && go test -race -tags "$(GO_TAGS)" ./...

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
