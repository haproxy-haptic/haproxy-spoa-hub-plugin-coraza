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
            0,
            std::ptr::null(),
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
            std::ptr::null(),
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
