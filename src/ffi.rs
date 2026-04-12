use std::ffi::{CStr, CString, c_char, c_int, c_longlong};

/// Result of WAF evaluation returned by the Go c-archive.
#[repr(C)]
pub struct CorazaResult {
    pub rule_id: c_int,
    pub action: *const c_char,
    pub status: c_int,
    pub data: *const c_char,
    pub anomaly_score: c_int,
    pub rules_hit: c_int,
}

unsafe extern "C" {
    // WAF lifecycle
    pub fn coraza_waf_new(
        directives: *const c_char,
        directives_len: c_int,
        directives_file: *const c_char,
        root_fs_path: *const c_char,
        req_body_limit: c_int,
        req_body_mem_limit: c_int,
        resp_body_limit: c_int,
    ) -> u64;

    pub fn coraza_waf_rules_count(waf: u64) -> c_int;
    pub fn coraza_waf_free(waf: u64);

    // Request processing
    pub fn coraza_process_request(
        waf_handle: u64,
        tx_id: *const c_char,
        src_ip: *const c_char,
        src_port: c_int,
        dst_ip: *const c_char,
        dst_port: c_int,
        method: *const c_char,
        path: *const c_char,
        query: *const c_char,
        http_version: *const c_char,
        headers: *const c_char,
        headers_len: c_int,
        body: *const c_char,
        body_len: c_int,
        cache_tx: c_int,
        app_name: *const c_char,
    ) -> CorazaResult;

    // Response processing
    pub fn coraza_process_response(
        tx_id: *const c_char,
        status_code: c_int,
        http_version: *const c_char,
        headers: *const c_char,
        headers_len: c_int,
        body: *const c_char,
        body_len: c_int,
        detect_only: c_int,
    ) -> CorazaResult;

    // Cache configuration
    pub fn coraza_set_cache_ttl(ttl_ms: c_int);

    // WAF app routing
    pub fn coraza_set_default_waf(waf: u64);
    pub fn coraza_set_app_waf(app_name: *const c_char, waf: u64);

    // Utilities
    pub fn coraza_free_string(s: *mut c_char);
    pub fn coraza_last_error() -> *mut c_char;
    // Metrics
    pub fn coraza_metrics_allowed() -> c_longlong;
    pub fn coraza_metrics_blocked() -> c_longlong;
    pub fn coraza_metrics_rules_hit() -> c_longlong;
    pub fn coraza_metrics_errors() -> c_longlong;
}

impl CorazaResult {
    /// Extract the action string from the C pointer.
    /// Defaults to "deny" if null (FR-008: deny-by-default on errors).
    pub fn action_str(&self) -> &str {
        if self.action.is_null() {
            return "deny";
        }
        unsafe { CStr::from_ptr(self.action) }
            .to_str()
            .unwrap_or("deny")
    }

    /// Extract the data string from the C pointer.
    pub fn data_str(&self) -> &str {
        if self.data.is_null() {
            return "";
        }
        unsafe { CStr::from_ptr(self.data) }.to_str().unwrap_or("")
    }

    /// Free the data string if it was dynamically allocated.
    /// Safe to call unconditionally — `coraza_free_string` guards against
    /// freeing null and pre-allocated constants.
    pub fn free_data(&self) {
        unsafe { coraza_free_string(self.data as *mut c_char) };
    }
}

/// Helper to create a C string, returning a CString that must be kept alive.
pub fn to_cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap())
}
