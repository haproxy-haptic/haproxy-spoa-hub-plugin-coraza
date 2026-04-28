# Changelog

## [Unreleased]

## [0.1.1] - 2026-04-28

### Added

- Release artifacts (plugin `.so` files) published to the GitLab Generic
  Package Registry under `packages/generic/coraza/<tag>/` with stable URLs
- Per-file `<artifact>.sha256` sidecars and a combined `SHA256SUMS` for
  batch verification with `sha256sum -c SHA256SUMS`
- Cosign keyless signatures (`<artifact>.cosign.bundle`) for every release
  artifact, signed via the GitLab OIDC id token (Sigstore Fulcio + Rekor)
- `make verify-release VERSION=vX.Y.Z` target plus `scripts/verify-release.sh`
  for end-to-end consumer verification (downloads `SHA256SUMS`, checks all
  hashes, runs `cosign verify-blob` against the project's tag identity)
- Unsigned SLSA v0.2 provenance metadata emitted next to build artifacts
  via `RUNNER_GENERATE_ARTIFACTS_METADATA` (free SLSA-L1)

### Changed

- Release builds now use `cargo auditable build --release`, embedding a
  compressed `Cargo.lock`-equivalent in every binary so SBOM tools can
  enumerate Rust dependencies without source access

## [0.1.0] - 2026-04-12

### Added

- Initial release of the Coraza WAF plugin for haproxy-spoa-hub
- HTTP request inspection against OWASP CRS v4 rulesets
- Response-phase inspection with detect-only async mode
- Embedded CRS v4 with filesystem override via mergefs
- Multi-application WAF configuration support
- Lightweight WAF metrics (blocked/allowed counts, rule matches, errors)
- CRS anomaly scoring detection (rules 949110/949111)
- Transaction caching with configurable TTL for request-response correlation
- Go c-archive statically linked into Rust cdylib
- Cross-compilation support for amd64, arm64, armv7
- E2E test suite with docker-compose
- Criterion benchmarks for request evaluation latency
