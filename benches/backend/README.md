# Go and Rust backend benchmark

[Recorded full CRS comparison](results/786d014.md)

This harness loads each release library into its own process running the same SPOA hub. A Python client sends SPOP 2.0 NOTIFY frames over a persistent Unix socket and checks every ACK. Both plugins load the embedded recommended configuration, setup file and complete OWASP CRS 4.25.0. Two small extra rules check that the request and response phases actually inspect bodies.

Build the libraries from the same plugin revision. Separate target directories preserve both artifacts.

```sh
CARGO_TARGET_DIR=target/bench-go cargo build --locked --release --lib
CARGO_TARGET_DIR=target/bench-rust cargo build --locked --release --lib \
    --no-default-features --features rust-backend
mkdir -p target/bench-plugins
cp target/bench-go/release/libcoraza_plugin.so target/bench-plugins/
cp target/bench-rust/release/libcoraza_plugin.so target/bench-plugins/libcoraza_rust_plugin.so
```

The harness checks each unstripped library with `go version -m` and `nm`. Supply a release build of haproxy-spoa-hub. The recorded Linux run used the amd64 glibc binary from the [hub v0.13.0 release](https://github.com/haproxy-haptic/haproxy-spoa-hub/releases/tag/v0.13.0). Choose two server CPUs and a separate client CPU on different physical cores, as reported by `lscpu -e`. Run this command from the project root, substituting the hub path and CPU numbers for the host.

```sh
python3 benches/backend/compare.py \
    --hub /path/to/haproxy-spoa-hub \
    --go target/bench-plugins/libcoraza_plugin.so \
    --rust target/bench-plugins/libcoraza_rust_plugin.so \
    --server-cpus 5,6 --client-cpu 2 --output comparison.json
```

Each backend receives 100 warmup requests per workload. The client measures 12 alternating Go/Rust pairs of 300 requests. GET has a query string. Form and JSON POST use complete buffered bodies. The response profile uses fresh hub processes, enables transaction retention, and sends a request followed by the correlated response. Its latency is the sum of the two socket exchanges. The timer starts before sending a prepared frame and stops when the full ACK has arrived.

The report includes median batch p50, p95 and p99 latency, and process CPU per completed workload across all hub and plugin threads. The paired percentage compares adjacent batches. It includes the hashes of the hub and both libraries, the policy hash, each batch and the correctness probes. Startup, rule loading and client-side ACK decoding are outside the latency interval. This measures single-in-flight local SPOA traffic. Saturation throughput and HAProxy HTTP processing require different workloads.

On Linux the harness also samples each hub process after the workload, including plugin state and runtime. PSS apportions shared pages. VmHWM is peak RSS since that process started. These point-in-time figures depend on allocator and GC behavior.

## Compare policy decisions

Run the policy comparison against the same release libraries and hub. It sends benign requests through isolated policies for phase order, counts and exclusions, argument names, multiple matches, chained actions and response processing. It also exercises the full CRS and a representative HAPTIC configuration with method, score-threshold and target overrides.

```sh
python3 benches/backend/policy_parity.py \
    --hub /path/to/haproxy-spoa-hub \
    --go target/bench-plugins/libcoraza_plugin.so \
    --rust target/bench-plugins/libcoraza_rust_plugin.so --output policy-parity.json
```

A policy that fails to start the hub or a difference in any returned SPOA field fails the comparison. Each response uses the transaction ID returned by its own backend. IDs are generated independently and are excluded from the field comparison. The JSON records binary and policy hashes, both sets of returned fields, and any differences.
