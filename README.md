# Coraza WAF Plugin for haproxy-spoa-hub

This [haproxy-spoa-hub](https://github.com/haproxy-haptic/haproxy-spoa-hub) plugin inspects HTTP requests and responses in the hub process. Choose the WAF engine when building the plugin. Both builds expose the same plugin name, hub configuration and SPOE messages.

## Build

The default build uses Go Coraza and links it into the plugin as a C archive. It requires Rust, Go 1.26 or newer, and a C compiler.

```sh
cargo build --locked --release --target-dir target/go
```

For the Rust engine, use Rust 1.94.1 or newer. This build uses the pinned [zentinel-modsec fork](https://github.com/phihos/zentinel-modsec) and its Rust libinjection detector. It builds without a Go toolchain.

```sh
cargo build --locked --release --no-default-features --features rust-backend --target-dir target/rust
```

To prepare both libraries for a HAPTIC hub image, run `make build-backends` and copy the contents of `target/plugin-bundle/` to the hub plugin directory. Select the engine with the existing `library` setting in the `coraza` plugin entry. All other message routing and configuration keys stay the same.

| Hub library setting | Engine |
|---|---|
| `library = "libcoraza_plugin.so"` | Go Coraza |
| `library = "libcoraza_rust_plugin.so"` | Rust zentinel-modsec |

The release workflow builds and signs both libraries for each supported architecture. For cross-compilation, install the target's system linker. The Go build also uses a target C compiler for cgo.

### Choosing an engine for a policy

Both plugins load OWASP CRS 4.25.0 and use Coraza's multiphase evaluation order. A phase-2 rule that inspects only the request method can block during phase 1. A rule that counts `&ARGS` counts query arguments during request-header inspection and form arguments during body inspection. The hub reports up to five distinct matched input fields, including their query or body origin. The [policy comparison](benches/backend/README.md) runs the same requests through each plugin and compares the hub's returned variables.

The Rust build compiles embedded and staged rule files in a private temporary directory. Give the hub a writable `TMPDIR`. For admission of a staged JSON Schema, include its referenced JSON files in the same staged tree. The Rust backend reports unsupported rule features during policy loading. Connector match logging is available on both builds. Both builds also support serial JSON transaction auditing. To log the request and response headers and rules that matched, configure the trusted policy:

```apache
SecAuditEngine RelevantOnly
SecAuditLogParts ABFHKZ
SecAuditLog /dev/stdout
SecAuditLogFormat JSON
```

With `RelevantOnly`, a configured `SecAuditLogRelevantStatus` selects by response or interruption status, including a detection-only interruption. Without a status expression, a matching rule must enable audit logging. The recommended Coraza configuration supplies a status expression. `SecAuditEngine On` records every transaction.

The Rust writer supports parts `ABFHKZ` and subsets. These exclude HTTP bodies. Header values, query strings, expanded rule messages and `logdata` may still contain secrets. Audit output is independent of connector match logging and its redaction settings. Use a mounted file path to keep records out of container stdout. Rust creates new files with mode `0600` by default and accepts `SecAuditLogFileMode` in octal. Admission validates the directives without creating the destination. Each Rust audit record identifies the physical source line of the rule, including rules from included files.

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
| `rule_watch_interval_ms` | int | 15000 | How often to re-check the rule files named by `Include` directives, recompiling in place when they change; `0` disables |
| `default_waf` | bool | true | Compile the default policy for requests without an `app`; when `false`, such requests get `action=deny`, `status=503` |
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
Applications with equal effective configuration share one compiled WAF:
comments, blank lines and surrounding whitespace don't count.

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
| `rule_ids` | string | Comma-separated IDs of the matched rules that carry a severity (the anomaly score's rules), most severe first, at most 10; absent when none matched |
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

With one request in flight through hub v0.13.0 and OWASP CRS 4.25.0, median GET latency was 1,382 µs with Go and 324 µs with Rust. A request and its correlated response took 1,474 µs and 384 µs respectively. These figures come from interleaved runs on a shared Linux host. [Benchmark, policy comparison and replay instructions](benches/backend/results/993a588.md)

For the Go build, keep the Go runtime under the container limit, but leave garbage collection
enabled. Disabling GC allows hostile request traffic to grow the process until
the kernel kills it.

```bash
# Example for a 256 MiB container limit; leave headroom for Rust, CRS, and libc.
export GOMEMLIMIT=192MiB
```

The Go build uses the stable `coraza.rule.multiphase_evaluation` and
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
