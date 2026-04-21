# Coraza WAF Plugin for haproxy-spoa-hub

A [haproxy-spoa-hub](https://github.com/haproxy-spoa-hub) plugin that embeds the [Coraza WAF](https://coraza.io/) engine for HTTP request and response inspection against OWASP CRS v4 rulesets.

## Overview

This plugin eliminates the double-IPC cost for operators who run both haproxy-spoa-hub (for plugins like fingerprinting, external auth) and the standalone [coraza-spoa](https://github.com/corazawaf/coraza-spoa). By embedding Coraza directly into a hub plugin via Go-to-Rust FFI, WAF evaluation happens in-process without additional network hops.

## Prerequisites

- Go 1.25+
- Rust 1.86+ (edition 2024)
- GCC (for CGo)
- haproxy-spoa-hub binary

For cross-compilation:
- `gcc-aarch64-linux-gnu` (arm64)
- `gcc-arm-linux-gnueabihf` (armv7)

## Build

```bash
cargo build --release
# Output: target/release/libcoraza_plugin.so
```

The build process compiles the Go Coraza wrapper as a `c-archive` and statically links it into the Rust cdylib plugin.

## Configuration

### Hub Configuration (`hub.toml`)

```toml
[[plugins]]
name = "coraza"
library = "libcoraza_plugin.so"
messages = ["check-request"]
timeout_ms = 15

[plugins.params]
directives = """
SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
"""
request_body_limit = 131072
request_body_in_memory_limit = 131072
```

### Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `directives` | string | Embedded CRS | SecLang WAF directives |
| `directives_file` | string | - | Path to additional directives file |
| `request_body_limit` | int | 4096 | Max request body bytes to buffer |
| `request_body_in_memory_limit` | int | 4096 | Max body bytes in memory |
| `response_body_limit` | int | 4096 | Max response body bytes to buffer |
| `response_check` | bool | false | Enable response-phase inspection |
| `detect_only` | bool | false | Log-only mode (non-blocking) |
| `transaction_ttl_ms` | int | 10000 | TTL for cached transactions |

### HAProxy SPOE Configuration

See `examples/spoe-coraza.conf` for the SPOE message definitions and `examples/haproxy.cfg` for the HAProxy frontend rules.

### Transaction Variables

The plugin sets these variables in HAProxy (prefixed with `hub.<plugin_name>.`):

| Variable | Type | Description |
|----------|------|-------------|
| `id` | string | Transaction ID |
| `action` | string | "allow" or "deny" |
| `status` | int | HTTP status code (0=allow, 403=deny) |
| `rule_id` | int | Matched rule ID |
| `anomaly_score` | int | CRS anomaly score |
| `rules_hit` | int | Number of matched rules |
| `data` | string | Redirect URL (when action=redirect) |

## Migration from coraza-spoa

| coraza-spoa variable | Hub equivalent |
|---------------------|----------------|
| `txn.coraza.action` | `var(txn.hub.coraza.action)` |
| `txn.coraza.status` | `var(txn.hub.coraza.status)` |
| `txn.coraza.ruleid` | `var(txn.hub.coraza.rule_id)` |
| `txn.coraza.id` | `var(txn.hub.coraza.id)` |
| `txn.coraza.data` | `var(txn.hub.coraza.data)` |
| `txn.coraza.anomaly_score` | `var(txn.hub.coraza.anomaly_score)` |
| `txn.coraza.rules_hit` | `var(txn.hub.coraza.rules_hit)` |

## Performance Tuning

For production deployments:

```bash
# Reduce Go GC pressure
export GOGC=off
export GOMEMLIMIT=<85% of available memory>
```

The plugin uses Coraza build tags for optimized rule evaluation:
- `coraza.rule.rx_prefilter` - skip regex when pre-filter determines no match
- `coraza.rule.multiphase_evaluation` - evaluate rules in earlier phases
- `coraza.rule.no_regex_multiline` - disable multiline regex

## Testing

```bash
# Go unit tests
cd go && go test -v -tags "coraza.rule.rx_prefilter,coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline" ./...

# Rust tests
cargo test

# E2E tests (requires Docker)
cd tests/e2e && make test
```

## License

Licensed under the [Apache License 2.0](LICENSE).
