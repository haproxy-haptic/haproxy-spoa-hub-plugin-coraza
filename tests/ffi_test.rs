use std::ffi::c_int;

use coraza_plugin::ffi::{self, to_cstring};

#[test]
fn test_waf_create_with_embedded_crs() {
    let directives = concat!(
        "SecRuleEngine On\n",
        "Include @coraza.conf-recommended\n",
        "Include @crs-setup.conf.example\n",
        "Include @owasp_crs/*.conf\n",
    );
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072, // request body limit
            131072, // request body mem limit
            131072, // response body limit
            0,      // rule_match_log
            0,      // matched_data_log_mode
            128,    // matched_data_max_bytes
        )
    };
    assert!(handle > 0, "WAF handle should be non-zero");

    let rules = unsafe { ffi::coraza_waf_rules_count(handle) };
    assert!(rules > 0, "should have loaded CRS rules, got {rules}");

    unsafe { ffi::coraza_waf_free(handle) };
}

#[test]
fn test_waf_create_invalid_directives() {
    let directives = "Include /nonexistent/rules.conf";
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            4096,
            4096,
            4096,
            0,
            0,
            128,
        )
    };
    assert_eq!(handle, 0, "should return 0 for invalid directives");
}

#[test]
fn test_process_benign_request() {
    let directives = concat!(
        "SecRuleEngine On\n",
        "Include @coraza.conf-recommended\n",
        "Include @crs-setup.conf.example\n",
        "Include @owasp_crs/*.conf\n",
    );
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072,
            131072,
            131072,
            0,
            0,
            128,
        )
    };
    assert!(handle > 0);

    let tx_id = to_cstring("test-benign");
    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/index.html");
    let query = to_cstring("");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0";

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
            0,    // cache_ttl_ms
            1024, // max_cached_transactions
            0,    // detect_only
            0,    // expose_matched_data
            128,
        )
    };

    assert_eq!(result.action_str(), "allow");
    assert_eq!(result.status, 0);

    unsafe { ffi::coraza_waf_free(handle) };
}

#[test]
fn test_process_sql_injection() {
    let directives = concat!(
        "SecRuleEngine On\n",
        "Include @coraza.conf-recommended\n",
        "Include @crs-setup.conf.example\n",
        "Include @owasp_crs/*.conf\n",
    );
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072,
            131072,
            131072,
            0,
            0,
            128,
        )
    };
    assert!(handle > 0);

    let tx_id = to_cstring("test-sqli");
    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/search");
    let query = to_cstring("id=1' OR 1=1 --");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0";

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
            1024,
            0, // detect_only
            0,
            128,
        )
    };

    assert_eq!(
        result.action_str(),
        "deny",
        "SQL injection should be denied"
    );
    assert!(
        result.rule_id > 0,
        "should have a rule_id for SQL injection"
    );
    assert_eq!(result.status, 403);

    unsafe { ffi::coraza_waf_free(handle) };
}

/// US1 acceptance — detect-only flag coerces a would-be deny verdict to
/// allow while keeping rule_id, anomaly_score, rules_hit, and data
/// populated. See specs/002-detect-only-request/spec.md.
#[test]
fn test_process_sql_injection_detect_only() {
    let directives = concat!(
        "SecRuleEngine On\n",
        "Include @coraza.conf-recommended\n",
        "Include @crs-setup.conf.example\n",
        "Include @owasp_crs/*.conf\n",
    );
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072,
            131072,
            131072,
            0,
            0,
            128,
        )
    };
    assert!(handle > 0);

    let tx_id = to_cstring("test-sqli-detect");
    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/search");
    let query = to_cstring("id=1' OR 1=1 --");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0";

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
            1024,
            1, // detect_only=true: rules evaluate but verdict coerced to allow
            0,
            128,
        )
    };

    assert_eq!(
        result.action_str(),
        "allow",
        "detect-only must coerce deny -> allow"
    );
    assert_eq!(
        result.status, 0,
        "detect-only must reset status to 0 (allow)"
    );
    assert!(
        result.rule_id > 0,
        "rule_id MUST still be populated so HAProxy can act on it"
    );
    assert!(
        result.rules_hit > 0,
        "rules_hit MUST reflect the rules that fired"
    );
    assert!(
        result.anomaly_score > 0,
        "anomaly_score MUST reflect the WAF's findings"
    );

    unsafe { ffi::coraza_waf_free(handle) };
}

/// Negative complement: detect-only=true on a benign request is a no-op
/// — same outcome as detect-only absent.
#[test]
fn test_process_benign_request_detect_only_is_noop() {
    let directives = concat!("SecRuleEngine On\n", "Include @coraza.conf-recommended\n",);
    let dir_c = to_cstring(directives);

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            std::ptr::null(),
            std::ptr::null(),
            131072,
            131072,
            131072,
            0,
            0,
            128,
        )
    };
    assert!(handle > 0);

    let tx_id = to_cstring("test-benign-detect");
    let src_ip = to_cstring("192.168.1.1");
    let dst_ip = to_cstring("10.0.0.1");
    let method = to_cstring("GET");
    let path = to_cstring("/index.html");
    let query = to_cstring("");
    let version = to_cstring("HTTP/1.1");
    let headers = b"Host\0example.com\0";

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
            1024,
            1, // detect_only=true on a benign request
            0,
            128,
        )
    };

    assert_eq!(result.action_str(), "allow");
    assert_eq!(result.status, 0);
    assert_eq!(result.rule_id, 0, "no rule fired on benign request");

    unsafe { ffi::coraza_waf_free(handle) };
}
