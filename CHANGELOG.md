# Changelog

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
