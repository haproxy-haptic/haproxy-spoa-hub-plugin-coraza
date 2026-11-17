//! Per-request cost of the FFI entry point as the hub calls it: from a
//! non-Go thread, across the cgo boundary, with the chart-default CRS
//! (HAPTIC#697). Compare with `make bench-go AB_ROUNDS=...`, which measures
//! the same call from Go next to Coraza alone.
//!
//! Wall minus CPU minus run-queue wait, with voluntary context switches, is
//! time the calling thread spent parked inside the Go runtime.

use std::ffi::{c_int, c_long};
use std::time::{Duration, Instant};

use coraza_plugin::ffi::{self, to_cstring};

const CHART_DEFAULT_DIRECTIVES: &str = "Include @coraza.conf-recommended
SecRxPreFilter On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess Off
";

#[repr(C)]
struct Timespec {
    sec: c_long,
    nsec: c_long,
}

unsafe extern "C" {
    fn clock_gettime(clock: c_int, ts: *mut Timespec) -> c_int;
}

fn cpu_clock(clock: c_int) -> Duration {
    let mut ts = Timespec { sec: 0, nsec: 0 };
    unsafe { clock_gettime(clock, &mut ts) };
    Duration::new(ts.sec as u64, ts.nsec as u32)
}

fn thread_cpu() -> Duration {
    cpu_clock(3)
}

/// All threads, including the Go runtime's GC workers and scheduler hand-offs.
fn process_cpu() -> Duration {
    cpu_clock(2)
}

/// (run-queue wait, voluntary switches, involuntary switches) of this thread:
/// separates waiting for a CPU from blocking inside the call.
fn sched() -> (Duration, u64, u64) {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
    let wait = stat
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    };
    (
        Duration::from_nanos(wait),
        field("voluntary_ctxt_switches:"),
        field("nonvoluntary_ctxt_switches:"),
    )
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentiles(name: &str, mut d: Vec<Duration>) {
    d.sort();
    let at = |q: f64| d[(q * (d.len() - 1) as f64) as usize];
    let mean = d.iter().sum::<Duration>() / d.len() as u32;
    println!(
        "{name} n={} mean={mean:?} p50={:?} p90={:?} p99={:?}",
        d.len(),
        at(0.5),
        at(0.9),
        at(0.99)
    );
}

fn main() {
    let rounds = env_u64("CORAZA_FFI_ROUNDS", 2000);
    let pace = Duration::from_micros(env_u64("CORAZA_FFI_PACE", 0));

    let dir_c = to_cstring(CHART_DEFAULT_DIRECTIVES);
    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            CHART_DEFAULT_DIRECTIVES.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            128,
        )
    };
    assert!(handle > 0, "WAF setup failed");

    let src_ip = to_cstring("127.0.0.1");
    let dst_ip = to_cstring("127.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/");
    let query = to_cstring("");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example\0User-Agent\0oha/1.4.5\0";

    let evaluate = |i: u64| {
        let tx_id = to_cstring(&i.to_string());
        let result = unsafe {
            ffi::coraza_process_request(
                handle,
                tx_id.as_ptr(),
                src_ip.as_ptr(),
                40000,
                dst_ip.as_ptr(),
                8080,
                method.as_ptr(),
                path.as_ptr(),
                query.as_ptr(),
                version.as_ptr(),
                headers.as_ptr() as *const _,
                headers.len() as c_int,
                std::ptr::null(),
                0,
                0,
                1024,
                0,
                0,
                128,
            )
        };
        assert_eq!(result.action_str(), "allow");
        result.free_data();
        result.free_matched_rules();
        result.free_matched_var();
    };

    for i in 0..200 {
        evaluate(i);
    }
    let (mut wall, mut cpu, mut runq) = (Vec::new(), Vec::new(), Vec::new());
    let (mut voluntary, mut involuntary) = (0, 0);
    let process_start = process_cpu();
    for i in 0..rounds {
        std::thread::sleep(pace);
        let s = sched();
        let (w, c) = (Instant::now(), thread_cpu());
        evaluate(i);
        cpu.push(thread_cpu() - c);
        wall.push(w.elapsed());
        let e = sched();
        runq.push(e.0 - s.0);
        voluntary += e.1 - s.1;
        involuntary += e.2 - s.2;
    }
    println!(
        "process CPU per call, all threads: {:?}",
        (process_cpu() - process_start) / rounds as u32
    );
    percentiles("ffi wall", wall);
    percentiles("ffi cpu ", cpu);
    percentiles("ffi runq", runq);
    println!(
        "context switches per call: voluntary={:.2} involuntary={:.2}",
        voluntary as f64 / rounds as f64,
        involuntary as f64 / rounds as f64
    );
    unsafe { ffi::coraza_waf_free(handle) };
}
