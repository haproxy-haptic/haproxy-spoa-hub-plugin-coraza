# Go and Rust backend benchmark

This harness loads each release library into its own process running the same SPOA hub. A Python client sends SPOP 2.0 NOTIFY frames over a persistent Unix socket and checks every ACK. Both plugins load the embedded recommended configuration, setup file and complete OWASP CRS 4.25.0. Two small extra rules check that the request and response phases actually inspect bodies.

Build the libraries from the same plugin revision. Separate target directories preserve both artifacts.

```sh
CARGO_TARGET_DIR=target/bench-go cargo build --locked --release --lib
CARGO_TARGET_DIR=target/bench-rust cargo build --locked --release --lib \
    --no-default-features --features rust-backend
```

Supply a release build of haproxy-spoa-hub. The recorded Linux run used the amd64 glibc binary from the [hub v0.13.0 release](https://github.com/haproxy-haptic/haproxy-spoa-hub/releases/tag/v0.13.0). Choose two server CPUs and a separate client CPU on different physical cores, as reported by `lscpu -e`. Run this command from the project root, substituting the hub path and CPU numbers for the host.

```sh
python3 benches/backend/compare.py \
    --hub /path/to/haproxy-spoa-hub \
    --go target/bench-go/release/libcoraza_plugin.so \
    --rust target/bench-rust/release/libcoraza_plugin.so \
    --server-cpus 5,6 --client-cpu 2 --output comparison.json
```

Each backend receives 100 warmup requests per workload. The client measures 12 alternating Go/Rust pairs of 300 requests. GET has a query string. Form and JSON POST use complete buffered bodies. The response profile uses fresh hub processes, enables transaction retention, and sends a request followed by the correlated response. Its latency is the sum of the two socket exchanges. The timer starts before sending a prepared frame and stops when the full ACK has arrived.

The report includes median batch p50, p95 and p99 latency, and process CPU per completed workload across all hub and plugin threads. The paired percentage compares adjacent batches. It includes the hashes of the hub and both libraries, the policy hash, each batch and the correctness probes. Startup, rule loading and client-side ACK decoding are outside the latency interval. This measures single-in-flight local SPOA traffic. Saturation throughput and HAProxy HTTP processing require different workloads.
