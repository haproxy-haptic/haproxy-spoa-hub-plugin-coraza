.PHONY: build build-release test test-go fmt lint check test-e2e verify-release

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

lint:
	cargo fmt -- --check
	cargo clippy --all-targets -- -D warnings
	@test -z "$$(gofmt -l go)" || { gofmt -l go; exit 1; }
	cd go && go vet -tags "$(GO_TAGS)" ./...

check: lint test

test-e2e:
	$(MAKE) -C tests/e2e

verify-release:
ifndef VERSION
	$(error VERSION not set; usage: make verify-release VERSION=vX.Y.Z)
endif
	@scripts/verify-release.sh "$(VERSION)"
