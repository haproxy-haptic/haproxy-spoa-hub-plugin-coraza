# Quickstart: Coraza WAF Plugin

## Prerequisites

- Go 1.25+ (for Coraza v3 and c-archive build)
- Rust 1.86+ (for haproxy-spoa-hub plugin API)
- C compiler (gcc) for CGo
- For cross-compilation: `gcc-aarch64-linux-gnu` (arm64), `gcc-arm-linux-gnueabihf` (armv7)
- HAProxy 2.6+ with SPOE support
- haproxy-spoa-hub binary

## Build

```bash
# Build the plugin (Go c-archive + Rust cdylib)
cargo build --release

# Output: target/release/libcoraza_plugin.so
```

The build process:
1. `build.rs` invokes `go build -buildmode=c-archive` on the Go wrapper in `go/`
2. Generates C bindings via the Go-produced header file
3. Statically links the Go archive into the Rust cdylib
4. Produces `libcoraza_plugin.so` loadable by haproxy-spoa-hub

## Configuration

### Hub Configuration (`hub.toml`)

```toml
plugin_dir = "/opt/spoa-plugins"

[[plugins]]
name = "coraza"
library = "libcoraza_plugin.so"
messages = ["check-request", "check-response"]
timeout_ms = 15

[plugins.params]
# SecLang directives (embedded CRS loaded by default)
directives = """
SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
"""

# Optional: additional rules from filesystem
# directives_file = "/etc/coraza/custom-rules.conf"

# Body processing limits (bytes)
request_body_limit = 4096
response_body_limit = 4096

# Response inspection (disabled by default)
response_check = false
detect_only = false
transaction_ttl_ms = 10000
```

### HAProxy SPOE Configuration (`spoe-coraza.conf`)

```
[coraza-waf]
spoe-agent coraza-agent
    messages check-request
    use-backend spoa-hub
    timeout hello      100ms
    timeout idle       30s
    timeout processing 15ms

spoe-message check-request
    args src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs_bin body=req.body
    event on-frontend-http-request
```

### HAProxy Frontend Configuration

```
frontend web
    bind :80
    filter spoe engine coraza-waf config /etc/haproxy/spoe-coraza.conf

    # Block requests denied by WAF
    http-request deny deny_status 403 if { var(txn.hub.coraza.action) -m str deny }

    # Optional: redirect if WAF says redirect
    http-request redirect location %[var(txn.hub.coraza.data)] if { var(txn.hub.coraza.action) -m str redirect }

    default_backend app
```

## Verify

1. Start the hub: `haproxy-spoa-hub --config hub.toml`
2. Start HAProxy with the SPOE configuration
3. Send a benign request: `curl http://localhost/` → should pass
4. Send a malicious request: `curl "http://localhost/?id=1' OR 1=1 --"` → should return 403

## Performance Tuning

For production deployments, set these environment variables before starting the hub:

```bash
# Keep GC enabled and leave headroom for Rust, CRS, and native allocations.
export GOMEMLIMIT=900MiB

# Or for containerized deployments
export GOMEMLIMIT=<container_memory * 0.85>
```

## Cross-Compilation

```bash
# arm64
cargo build --release --target aarch64-unknown-linux-gnu

# armv7
cargo build --release --target armv7-unknown-linux-gnueabihf
```

The `build.rs` automatically detects the target and configures the Go cross-compiler.
