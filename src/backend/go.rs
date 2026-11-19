//! Own the Go archive's handles and result buffers on the Rust side.
use super::{Request, Response};
use crate::{
    config::PluginConfig,
    ffi::{self, CorazaResult, to_cstring},
};
use haproxy_spoa_hub_plugin_api::Diagnostic;
use std::ffi::{CStr, CString, c_char, c_int};

#[derive(Debug)]
pub(crate) struct Waf(u64);

impl Waf {
    pub(crate) fn rule_count(&self) -> i32 {
        unsafe { ffi::coraza_waf_rules_count(self.0) }
    }
}
impl Drop for Waf {
    fn drop(&mut self) {
        unsafe { ffi::coraza_waf_free(self.0) };
    }
}
#[cfg(test)]
pub(crate) fn active_count() -> i32 {
    unsafe { ffi::coraza_waf_active_count() }
}

// The archive owns the process-wide response cache.
#[derive(Default, Debug)]
pub(crate) struct TransactionCache {}
impl TransactionCache {
    pub(crate) fn summary(&self) -> (i64, i64, i64, i64) {
        unsafe {
            (
                ffi::coraza_metrics_allowed(),
                ffi::coraza_metrics_blocked(),
                ffi::coraza_metrics_rules_hit(),
                ffi::coraza_metrics_errors(),
            )
        }
    }
}
pub(crate) struct Evaluation(CorazaResult);
impl std::ops::Deref for Evaluation {
    type Target = CorazaResult;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Evaluation {
    fn drop(&mut self) {
        self.free_data();
        self.free_matched_rules();
        self.free_matched_var();
    }
}
impl Evaluation {
    fn checked(raw: CorazaResult, phase: &str) -> Result<Self, String> {
        let value = Self(raw);
        if value.action.is_null() {
            return Err(format!(
                "Coraza {phase} evaluation failed: {}",
                last_ffi_error()
            ));
        }
        Ok(value)
    }
}
pub(crate) fn configure_validation_memory() {
    unsafe { ffi::coraza_configure_validation_memory() };
}
pub(crate) fn validate_directives(directives: &str, staged_files: &str) -> Vec<Diagnostic> {
    if directives.is_empty() {
        return Vec::new();
    }
    if directives.as_bytes().contains(&0) {
        return vec![Diagnostic::error(
            0,
            0,
            "directives contain an interior null byte; refusing an ambiguous FFI string",
        )];
    }
    let staged_files_json = CString::new(staged_files).expect("JSON escapes null bytes");
    let dir_c = to_cstring(directives);
    let dir_len = match c_int::try_from(dir_c.as_bytes().len()) {
        Ok(n) => n,
        // SecLang directive strings exceeding i32::MAX are not
        // realistic; surface a synthetic error rather than silently
        // truncating the length on the FFI boundary.
        Err(_) => {
            return vec![Diagnostic::error(
                0,
                0,
                "directives string exceeds i32::MAX bytes; refusing to validate",
            )];
        }
    };

    let json_ptr = unsafe {
        ffi::coraza_validate_directives(dir_c.as_ptr(), dir_len, staged_files_json.as_ptr())
    };
    if json_ptr.is_null() {
        return Vec::new();
    }
    let json_str = unsafe { CStr::from_ptr(json_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::coraza_free_string(json_ptr as *mut c_char) };

    parse_validation_json(&json_str)
}

/// Deserialise the JSON returned by `coraza_validate_directives` into
/// `Vec<Diagnostic>`. The wire form is `[{"severity","line","message"},...]`.
pub(crate) fn parse_validation_json(json: &str) -> Vec<Diagnostic> {
    #[derive(serde::Deserialize)]
    struct CapturedDiagnostic {
        severity: String,
        line: u32,
        message: String,
    }
    let captured: Vec<CapturedDiagnostic> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(error) => {
            return vec![Diagnostic::error(
                0,
                0,
                format!("Coraza validator returned malformed diagnostics: {error}"),
            )];
        }
    };
    captured
        .into_iter()
        .map(|c| match c.severity.as_str() {
            "error" => Diagnostic::error(c.line, 0, c.message),
            _ => Diagnostic::warning(c.line, 0, c.message),
        })
        .collect()
}

pub(crate) fn create_waf(
    directives: &str,
    directives_file: Option<&str>,
    req_body_limit: i32,
    req_body_mem_limit: i32,
    resp_body_limit: i32,
    config: &PluginConfig,
) -> Result<Waf, String> {
    let dir_c = std::ffi::CString::new(directives)
        .map_err(|_| "directives contain an interior NUL byte".to_string())?;
    let file_c = directives_file
        .map(std::ffi::CString::new)
        .transpose()
        .map_err(|_| "directives_file contains an interior NUL byte".to_string())?;
    let file_ptr = file_c
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null());

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            checked_ffi_len("directives", dir_c.as_bytes().len())
                .map_err(|error| error.to_string())?,
            file_ptr,
            std::ptr::null(),
            req_body_limit as c_int,
            req_body_mem_limit as c_int,
            resp_body_limit as c_int,
            i32::from(config.rule_match_log),
            config.matched_data_log.ffi_value(),
            config.matched_data_max_bytes,
            i32::from(config.include_crs_control_rule_hits),
        )
    };

    if handle == 0 {
        Err(last_ffi_error())
    } else {
        Ok(Waf(handle))
    }
}

fn checked_cstring(field: &str, value: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(value).map_err(|_| format!("{field} contains an interior NUL byte"))
}

fn checked_ffi_len(field: &str, value: usize) -> Result<c_int, String> {
    c_int::try_from(value).map_err(|_| format!("{field} exceeds i32::MAX bytes"))
}

/// Fetch and clear the last Go-side error message.
fn last_ffi_error() -> String {
    let err_ptr = unsafe { ffi::coraza_last_error() };
    if err_ptr.is_null() {
        return "unknown error".to_string();
    }
    let msg = unsafe { CStr::from_ptr(err_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { ffi::coraza_free_string(err_ptr) };
    msg
}

pub(crate) fn evaluate_request(
    waf: &Waf,
    _cache: &TransactionCache,
    request: Request<'_>,
    config: &PluginConfig,
    detect_only: bool,
) -> Result<Evaluation, String> {
    let Request {
        tx_id,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        method,
        path,
        query,
        version,
        headers: headers_buf,
        body: body_buf,
    } = request;
    // Convert to C strings
    let tx_id_c = checked_cstring("transaction ID", tx_id)?;
    let src_ip_c = checked_cstring("source IP", src_ip)?;
    let dst_ip_c = checked_cstring("destination IP", dst_ip)?;
    let method_c = checked_cstring("method", method)?;
    let path_c = checked_cstring("path", path)?;
    let query_c = checked_cstring("query", query)?;
    let version_c = checked_cstring("HTTP version", version)?;
    let headers_len = checked_ffi_len("headers", headers_buf.len())?;
    let body_len = checked_ffi_len("body", body_buf.len())?;

    let cache_ttl_ms = if config.response_check {
        config.transaction_ttl_ms
    } else {
        0
    };

    let detect_only_flag = if detect_only { 1 } else { 0 };

    let result = unsafe {
        ffi::coraza_process_request(
            waf.0,
            tx_id_c.as_ptr(),
            src_ip_c.as_ptr(),
            src_port as c_int,
            dst_ip_c.as_ptr(),
            dst_port as c_int,
            method_c.as_ptr(),
            path_c.as_ptr(),
            query_c.as_ptr(),
            version_c.as_ptr(),
            headers_buf.as_ptr() as *const _,
            headers_len,
            body_buf.as_ptr() as *const _,
            body_len,
            cache_ttl_ms,
            config.max_cached_transactions,
            detect_only_flag,
            i32::from(config.expose_matched_data),
            config.matched_data_max_bytes,
        )
    };
    Evaluation::checked(result, "request")
}
pub(crate) fn evaluate_response(
    _cache: &TransactionCache,
    response: Response<'_>,
    detect_only: bool,
) -> Result<Evaluation, String> {
    let Response {
        tx_id,
        status: status_code,
        version,
        headers: headers_buf,
        body: body_buf,
    } = response;
    let tx_id_c = checked_cstring("transaction ID", tx_id)?;
    let version_c = checked_cstring("HTTP version", version)?;
    let headers_len = checked_ffi_len("headers", headers_buf.len())?;
    let body_len = checked_ffi_len("body", body_buf.len())?;
    let detect_only_flag = if detect_only { 1 } else { 0 };

    let result = unsafe {
        ffi::coraza_process_response(
            tx_id_c.as_ptr(),
            status_code as c_int,
            version_c.as_ptr(),
            headers_buf.as_ptr() as *const _,
            headers_len,
            body_buf.as_ptr() as *const _,
            body_len,
            detect_only_flag,
        )
    };
    Evaluation::checked(result, "response")
}
