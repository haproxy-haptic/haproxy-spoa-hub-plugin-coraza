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
make build-release
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
max_concurrency = 2
max_queue = 0

[plugins.params]
directives = """
Include @coraza.conf-recommended
SecRxPreFilter On
SecRequestBodyAccess On
SecRequestBodyLimitAction Reject
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
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
| `detect_only` | bool | false | Default log-only verdict for request and response inspection |
| `transaction_ttl_ms` | int | 10000 | TTL for cached transactions |
| `max_cached_transactions` | int | 1024 | Hard cap on response-correlation transactions; requests fail closed when full |
| `rule_match_log` | bool | false | Emit a warning per matched rule; disabled by default to avoid log amplification |
| `matched_data_log` | string | `none` | Matched-data logging mode: `none`, `hash`, or bounded `truncate` |
| `matched_data_max_bytes` | int | 128 | Bound for truncated logs and exposed matched data |
| `expose_matched_data` | bool | false | Expose bounded interruption data as a transaction variable |
| `applications` | table | empty | Named WAF policies; omitted fields inherit the effective top-level policy |

Request-body access is controlled by SecLang, not by the numeric limit alone.
Use `SecRequestBodyAccess Off` for header/URI-only policies and
`SecRequestBodyAccess On` only when the integration guarantees that the complete,
bounded body is passed with `body-mode=buffered` and `body-complete=true`.
`SecRequestBodyLimitAction Reject` avoids partial-inspection bypasses.
Missing `body-mode` is treated as `none`; body inspection is never inferred
from whatever bytes happen to be present in HAProxy's request buffer.

`applications` are compiled as an atomic generation. A reload becomes visible
only after the default policy and every named policy compile successfully; a
failed candidate leaves the serving generation untouched. Unknown application
names are errors rather than silently falling back to the default policy.

### HAProxy SPOE Configuration

See `examples/spoe-coraza.conf` for the SPOE message definitions and `examples/haproxy.cfg` for the HAProxy frontend rules.

### Transaction Variables

The plugin sets these variables in HAProxy (prefixed with `hub.<plugin_name>.`):

| Variable | Type | Description |
|----------|------|-------------|
| `id` | string | Transaction ID |
| `action` | string | `allow`, `deny`, `drop`, or `redirect` |
| `status` | int | HTTP status code; `drop` is disruptive even though its status is 0 |
| `rule_id` | int | Matched rule ID |
| `anomaly_score` | int | CRS anomaly score |
| `rules_hit` | int | Number of matched rules |
| `data` | string | Bounded interruption data; absent unless `expose_matched_data=true` |

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

Keep the Go runtime under the container limit, but leave garbage collection
enabled. Disabling GC allows hostile request traffic to grow the process until
the kernel kills it.

```bash
# Example for a 256 MiB container limit; leave headroom for Rust, CRS, and libc.
export GOMEMLIMIT=192MiB
```

The build uses the stable `coraza.rule.multiphase_evaluation` and
`coraza.rule.no_regex_multiline` tags. Regex pre-filtering is enabled through the
public runtime directive `SecRxPreFilter On`; Coraza does not guarantee internal
build-tag compatibility across minor releases.

Set hub-side `max_concurrency` explicitly and keep `max_queue=0` on public
edges unless a short, measured queue is preferable to immediate overload. A
timed-out native evaluation keeps its concurrency permit until it really exits,
so repeated slow calls cannot create an unbounded blocking backlog.

## Testing

```bash
# Formatting, lint, Go race tests, and Rust tests
make check

# Full Docker E2E suite
make test-e2e
```

## License

Licensed under the [Apache License 2.0](LICENSE).
