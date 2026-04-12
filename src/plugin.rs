use std::ffi::{CStr, c_int};
use std::sync::OnceLock;

use abi_stable::std_types::{RString, RVec, Tuple2};
use haproxy_spoa_hub_plugin_api::{
    ProcessingResult, SpoeMessage, SpoeValue, TxnVariable, VarScope, define_plugin,
};

use crate::config::PluginConfig;
use crate::ffi::{self, CorazaResult, to_cstring};

static CONFIG: OnceLock<PluginConfig> = OnceLock::new();
static WAF_HANDLE: OnceLock<u64> = OnceLock::new();

#[derive(Debug)]
struct CorazaPlugin;

define_plugin!(CorazaPlugin, {
    fn new() -> Self {
        CorazaPlugin
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context);

        // Create default WAF instance
        let handle = create_waf(
            &config.directives,
            config.directives_file.as_deref(),
            config.request_body_limit,
            config.request_body_in_memory_limit,
            config.response_body_limit,
        )
        .map_err(|e| format!("Failed to create WAF: {e}"))?;

        let rules_count = unsafe { ffi::coraza_waf_rules_count(handle) };
        log::info!("Coraza WAF initialized with {rules_count} rules");

        unsafe { ffi::coraza_set_default_waf(handle) };

        // Create per-application WAF instances
        for app in &config.applications {
            let app_handle = create_waf(
                &app.directives,
                app.directives_file.as_deref(),
                app.request_body_limit,
                app.request_body_in_memory_limit,
                app.response_body_limit,
            )
            .map_err(|e| format!("Failed to create WAF for app '{}': {e}", app.name))?;

            let app_rules = unsafe { ffi::coraza_waf_rules_count(app_handle) };
            log::info!(
                "Coraza WAF app '{}' initialized with {app_rules} rules",
                app.name
            );

            let app_name_c = to_cstring(&app.name);
            unsafe { ffi::coraza_set_app_waf(app_name_c.as_ptr(), app_handle) };
        }

        // Configure cache TTL
        if config.response_check {
            unsafe { ffi::coraza_set_cache_ttl(config.transaction_ttl_ms as c_int) };
        }

        WAF_HANDLE.set(handle).ok();
        CONFIG.set(config).ok();
        Ok(())
    }

    fn name(&self) -> &str {
        "coraza"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn process(
        &self,
        message: &SpoeMessage,
    ) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let default_config = PluginConfig::default();
        let config = CONFIG.get().unwrap_or(&default_config);
        let waf_handle = WAF_HANDLE.get().copied().unwrap_or(0);

        match message.name.as_str() {
            "check-request" => process_request(message, config, waf_handle),
            "check-response" => process_response(message, config),
            _ => Ok(ProcessingResult {
                variables: RVec::new(),
            }),
        }
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }
});

impl Drop for CorazaPlugin {
    fn drop(&mut self) {
        // Log final metrics before cleanup
        let allowed = unsafe { ffi::coraza_metrics_allowed() };
        let blocked = unsafe { ffi::coraza_metrics_blocked() };
        let rules_hit = unsafe { ffi::coraza_metrics_rules_hit() };
        let errors = unsafe { ffi::coraza_metrics_errors() };
        log::info!(
            "Coraza WAF shutting down: allowed={allowed}, blocked={blocked}, \
             rules_hit={rules_hit}, errors={errors}"
        );

        // Free only this instance's WAF handle. Don't call coraza_shutdown()
        // here because the Go runtime is process-global — other plugin
        // instances (e.g., after SIGHUP reload) may still be active.
        if let Some(&handle) = WAF_HANDLE.get() {
            unsafe { ffi::coraza_waf_free(handle) };
        }
    }
}

fn process_request(
    message: &SpoeMessage,
    config: &PluginConfig,
    waf_handle: u64,
) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut src_ip = String::new();
    let mut src_port: i32 = 0;
    let mut dst_ip = String::new();
    let mut dst_port: i32 = 0;
    let mut method = String::new();
    let mut path = String::new();
    let mut query = String::new();
    let mut version = String::new();
    let mut headers_buf: Vec<u8> = Vec::new();
    let mut body_buf: Vec<u8> = Vec::new();
    let mut app_name: Option<String> = None;

    // Extract SPOE message arguments
    for Tuple2(k, v) in message.args.iter() {
        match k.as_str() {
            "src-ip" => {
                if let SpoeValue::String(s) = v {
                    src_ip = s.to_string();
                }
            }
            "src-port" => {
                src_port = extract_int(v);
            }
            "dst-ip" => {
                if let SpoeValue::String(s) = v {
                    dst_ip = s.to_string();
                }
            }
            "dst-port" => {
                dst_port = extract_int(v);
            }
            "method" => {
                if let SpoeValue::String(s) = v {
                    method = s.to_string();
                }
            }
            "path" => {
                if let SpoeValue::String(s) = v {
                    path = s.to_string();
                }
            }
            "query" => {
                if let SpoeValue::String(s) = v {
                    query = s.to_string();
                }
            }
            "version" => {
                if let SpoeValue::String(s) = v {
                    version = s.to_string();
                }
            }
            "headers" => match v {
                SpoeValue::Binary(b) => {
                    headers_buf = parse_haproxy_headers(b.as_slice());
                }
                SpoeValue::String(s) => {
                    headers_buf = parse_haproxy_headers(s.as_bytes());
                }
                _ => {}
            },
            "body" => match v {
                SpoeValue::Binary(b) => {
                    body_buf = b.to_vec();
                }
                SpoeValue::String(s) => {
                    body_buf = s.as_bytes().to_vec();
                }
                _ => {}
            },
            "app" => {
                if let SpoeValue::String(s) = v {
                    app_name = Some(s.to_string());
                }
            }
            _ => {}
        }
    }

    // Generate transaction ID
    let tx_id = format!("{}-{}", message.stream_id, message.frame_id);

    // Convert to C strings
    let tx_id_c = to_cstring(&tx_id);
    let src_ip_c = to_cstring(&src_ip);
    let dst_ip_c = to_cstring(&dst_ip);
    let method_c = to_cstring(&method);
    let path_c = to_cstring(&path);
    let query_c = to_cstring(&query);
    let version_c = to_cstring(&version);

    let app_name_c = app_name.as_ref().map(|s| to_cstring(s));
    let app_name_ptr = app_name_c
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null());

    let cache_tx = if config.response_check { 1 } else { 0 };

    let start = std::time::Instant::now();
    let result = unsafe {
        ffi::coraza_process_request(
            waf_handle,
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
            headers_buf.len() as c_int,
            body_buf.as_ptr() as *const _,
            body_buf.len() as c_int,
            cache_tx,
            app_name_ptr,
        )
    };
    let latency_us = start.elapsed().as_micros();

    log::debug!(
        "coraza request: action={} rule_id={} latency_us={latency_us}",
        result.action_str(),
        result.rule_id,
    );

    let variables = result_to_variables(&result, &tx_id, false);
    result.free_data();

    Ok(ProcessingResult { variables })
}

fn process_response(
    message: &SpoeMessage,
    config: &PluginConfig,
) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
    if !config.response_check {
        return Ok(ProcessingResult {
            variables: RVec::new(),
        });
    }

    let mut tx_id = String::new();
    let mut status_code: i32 = 0;
    let mut version = String::new();
    let mut headers_buf: Vec<u8> = Vec::new();
    let mut body_buf: Vec<u8> = Vec::new();
    let mut detect_only = config.detect_only;

    for Tuple2(k, v) in message.args.iter() {
        match k.as_str() {
            "id" => {
                if let SpoeValue::String(s) = v {
                    tx_id = s.to_string();
                }
            }
            "status" => {
                status_code = extract_int(v);
            }
            "version" => {
                if let SpoeValue::String(s) = v {
                    version = s.to_string();
                }
            }
            "headers" => match v {
                SpoeValue::Binary(b) => {
                    headers_buf = parse_haproxy_headers(b.as_slice());
                }
                SpoeValue::String(s) => {
                    headers_buf = parse_haproxy_headers(s.as_bytes());
                }
                _ => {}
            },
            "body" => match v {
                SpoeValue::Binary(b) => {
                    body_buf = b.to_vec();
                }
                SpoeValue::String(s) => {
                    body_buf = s.as_bytes().to_vec();
                }
                _ => {}
            },
            "detect-only" => {
                if let SpoeValue::Bool(b) = v {
                    detect_only = *b;
                }
            }
            _ => {}
        }
    }

    let tx_id_c = to_cstring(&tx_id);
    let version_c = to_cstring(&version);
    let detect_only_flag = if detect_only { 1 } else { 0 };

    let result = unsafe {
        ffi::coraza_process_response(
            tx_id_c.as_ptr(),
            status_code as c_int,
            version_c.as_ptr(),
            headers_buf.as_ptr() as *const _,
            headers_buf.len() as c_int,
            body_buf.as_ptr() as *const _,
            body_buf.len() as c_int,
            detect_only_flag,
        )
    };

    let variables = result_to_variables(&result, &tx_id, true);
    result.free_data();

    Ok(ProcessingResult { variables })
}

/// Convert a CorazaResult into SPOE transaction variables.
fn result_to_variables(result: &CorazaResult, tx_id: &str, is_response: bool) -> RVec<TxnVariable> {
    let prefix = if is_response { "resp_" } else { "" };
    let mut vars = RVec::with_capacity(if is_response { 3 } else { 7 });

    if !is_response {
        vars.push(TxnVariable {
            scope: VarScope::Transaction,
            name: RString::from("id"),
            value: SpoeValue::String(RString::from(tx_id)),
        });
    }

    vars.push(TxnVariable {
        scope: VarScope::Transaction,
        name: RString::from(format!("{prefix}action")),
        value: SpoeValue::String(RString::from(result.action_str())),
    });

    vars.push(TxnVariable {
        scope: VarScope::Transaction,
        name: RString::from(format!("{prefix}status")),
        value: SpoeValue::Int32(result.status),
    });

    vars.push(TxnVariable {
        scope: VarScope::Transaction,
        name: RString::from(format!("{prefix}rule_id")),
        value: SpoeValue::Int32(result.rule_id),
    });

    if !is_response {
        vars.push(TxnVariable {
            scope: VarScope::Transaction,
            name: RString::from("anomaly_score"),
            value: SpoeValue::Int32(result.anomaly_score),
        });

        vars.push(TxnVariable {
            scope: VarScope::Transaction,
            name: RString::from("rules_hit"),
            value: SpoeValue::Int32(result.rules_hit),
        });

        let data = result.data_str();
        if !data.is_empty() {
            vars.push(TxnVariable {
                scope: VarScope::Transaction,
                name: RString::from("data"),
                value: SpoeValue::String(RString::from(data)),
            });
        }
    }

    vars
}

/// Parse HAProxy raw headers (hdrs_bin format) into null-separated key-value pairs
/// for the Go FFI. HAProxy hdrs_bin format: each header is "Name: Value\r\n".
fn parse_haproxy_headers(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut result = Vec::new();

    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            result.extend_from_slice(name.as_bytes());
            result.push(0); // null separator
            result.extend_from_slice(value.as_bytes());
            result.push(0); // null separator
        }
    }

    result
}

/// Create a WAF instance via FFI. Returns the handle or an error message.
fn create_waf(
    directives: &str,
    directives_file: Option<&str>,
    req_body_limit: i32,
    req_body_mem_limit: i32,
    resp_body_limit: i32,
) -> Result<u64, String> {
    let dir_c = to_cstring(directives);
    let file_c = directives_file.map(to_cstring);
    let file_ptr = file_c
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null());

    let handle = unsafe {
        ffi::coraza_waf_new(
            dir_c.as_ptr(),
            directives.len() as c_int,
            file_ptr,
            std::ptr::null(),
            req_body_limit as c_int,
            req_body_mem_limit as c_int,
            resp_body_limit as c_int,
        )
    };

    if handle == 0 {
        Err(last_ffi_error())
    } else {
        Ok(handle)
    }
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

/// Extract an integer from a SpoeValue.
fn extract_int(v: &SpoeValue) -> i32 {
    match v {
        SpoeValue::Int32(n) => *n,
        SpoeValue::Uint32(n) => *n as i32,
        SpoeValue::Int64(n) => *n as i32,
        SpoeValue::Uint64(n) => *n as i32,
        _ => 0,
    }
}
