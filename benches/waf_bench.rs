use std::ffi::c_int;

use coraza_plugin::ffi::{self, to_cstring};
use criterion::{Criterion, criterion_group, criterion_main};

fn setup_waf() -> u64 {
    let directives = concat!(
        "SecRuleEngine On\n",
        "Include @coraza.conf-recommended\n",
        "Include @crs-setup.conf.example\n",
        "Include @owasp_crs/*.conf\n",
    );
    let dir_c = to_cstring(directives);
    unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072,
            131072,
            131072,
        )
    }
}

fn bench_benign_request(c: &mut Criterion) {
    let handle = setup_waf();
    assert!(handle > 0, "WAF setup failed");

    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/index.html");
    let query = to_cstring("");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0User-Agent\0Mozilla/5.0\0";

    let mut counter: u64 = 0;
    c.bench_function("benign_request", |b| {
        b.iter(|| {
            counter += 1;
            let tx_id = to_cstring(&format!("bench-{counter}"));
            let result = unsafe {
                ffi::coraza_process_request(
                    handle,
                    tx_id.as_ptr(),
                    src_ip.as_ptr(),
                    12345,
                    dst_ip.as_ptr(),
                    80,
                    method.as_ptr(),
                    path.as_ptr(),
                    query.as_ptr(),
                    version.as_ptr(),
                    headers.as_ptr() as *const _,
                    headers.len() as c_int,
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null(),
                    0, // detect_only
                )
            };
            assert_eq!(result.action_str(), "allow");
        });
    });

    unsafe { ffi::coraza_waf_free(handle) };
}

fn bench_sql_injection(c: &mut Criterion) {
    let handle = setup_waf();
    assert!(handle > 0, "WAF setup failed");

    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/search");
    let query = to_cstring("id=1' OR 1=1 --");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0";

    let mut counter: u64 = 0;
    c.bench_function("sql_injection", |b| {
        b.iter(|| {
            counter += 1;
            let tx_id = to_cstring(&format!("bench-sqli-{counter}"));
            let result = unsafe {
                ffi::coraza_process_request(
                    handle,
                    tx_id.as_ptr(),
                    src_ip.as_ptr(),
                    12345,
                    dst_ip.as_ptr(),
                    80,
                    method.as_ptr(),
                    path.as_ptr(),
                    query.as_ptr(),
                    version.as_ptr(),
                    headers.as_ptr() as *const _,
                    headers.len() as c_int,
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null(),
                    0, // detect_only
                )
            };
            assert_eq!(result.action_str(), "deny");
        });
    });

    unsafe { ffi::coraza_waf_free(handle) };
}

criterion_group!(benches, bench_benign_request, bench_sql_injection);
criterion_main!(benches);
