use std::ffi::{CStr, c_char, c_int};
use std::sync::{OnceLock, RwLock};

use haproxy_spoa_hub_plugin_api::{
    Diagnostic, ProcessingResult, RString, RVec, SpoeMessage, SpoeValue, TxnVariable, define_plugin,
};

use crate::config::PluginConfig;
use crate::ffi::{self, CorazaResult, to_cstring};

// Plugin state lives in a process-global `RwLock<State>` rather than
// on the `CorazaPlugin` struct because the upstream `define_plugin!`
// macro (macro_rules! in `haproxy-spoa-hub-plugin-api`) does not
// expose the `&self` / `&mut self` receiver inside the user-supplied
// init/process bodies — `self.field` in those bodies fails to bind to
// the generated method's receiver under Rust 2024 macro hygiene
// rules. Storing the WAF handle and config in a `static` and gating
// access with `RwLock` keeps the bodies free of `self.field`.
//
// The previous design used `OnceLock<u64>` for the WAF handle, which
// silently dropped the second init's handle on hub reload. Linux's
// dlopen returns the same process-shared `.so` data segment, so the
// static persists across hub-level "loads", and `OnceLock::set`
// returns Err on every init except the first. `process()` kept using
// the first init's handle, which the *first* Drop had already freed,
// so every request post-reload landed on the WAF-engine-error path
// (`action="deny", rule_id=0`) — defeating ADR-0007's hot-reload
// guarantee for HAPTIC. See `reload_tests::process_after_reload_uses_new_init_waf`.
//
// The new design swaps both fields under one write lock per `init()`
// and frees the previous handle in the same critical section. Reads
// in `process()` take the read lock for the duration of the
// `coraza_process_request` FFI call, so a reload that runs in
// parallel waits for in-flight requests to finish before swapping —
// no use-after-free on the Go side, no need for per-instance Drop
// tracking, no `OnceLock` on the hot path.

/// Combined latest-config + latest-WAF-handle. Wrapped in a single
/// `RwLock` so init swaps both atomically and `process()` reads both
/// against the same generation.
#[derive(Default)]
struct State {
    /// WAF handle returned by the Go FFI for the latest `init()`
    /// call. `0` before the first init runs.
    waf_handle: u64,
    /// Plugin config from the latest `init()` call. `Default` until
    /// the first init runs.
    config: PluginConfig,
}

static STATE: OnceLock<RwLock<State>> = OnceLock::new();

fn state() -> &'static RwLock<State> {
    STATE.get_or_init(|| RwLock::new(State::default()))
}

/// Acquire the state for reading, recovering through poisoned locks.
///
/// Lock poisoning happens when a writer panics mid-update. In our
/// case the only writer is `init()`, and the data invariants it
/// maintains are simple — both fields are plain values (`u64` and a
/// `PluginConfig` clone) that are written together but never observed
/// in a "half-applied" form, since the swap is `previous = mem::replace`-
/// style. So a poisoned lock is safe to read through with
/// `into_inner()`: callers see either the previous coherent state
/// (init panicked before the assignments) or the new coherent state
/// (init panicked after). The alternative — propagating the
/// `PoisonError` as a panic on every subsequent `process()` call —
/// would mean a single rare init panic permanently jams the SPOE
/// worker pool, exactly the cascading failure mode we exist to
/// prevent.
fn state_read() -> std::sync::RwLockReadGuard<'static, State> {
    state().read().unwrap_or_else(|e| e.into_inner())
}

/// Acquire the state for writing, recovering through poisoned locks.
/// Same rationale as `state_read` — every `init()` overwrites the
/// state in full, so a partial/inconsistent prior state is also safe
/// to overwrite.
fn state_write() -> std::sync::RwLockWriteGuard<'static, State> {
    state().write().unwrap_or_else(|e| e.into_inner())
}

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

        // Atomic swap-and-replace: take the previous handle out,
        // install the new one + config in the same critical section.
        // The write lock blocks until in-flight `process()` calls
        // (which hold the read lock) finish, so no SPOE worker is
        // mid-FFI on the previous handle when we free it below.
        let previous_handle = {
            let mut s = state_write();
            let previous = s.waf_handle;
            s.waf_handle = handle;
            s.config = config;
            previous
        };

        if previous_handle != 0 {
            // Free the prior WAF instance — there are no live readers
            // of it after the swap above, so the Go-side WAFs map
            // can drop it safely. Don't call `coraza_shutdown()`: the
            // Go runtime is process-global and shared with the rest
            // of the spoa-hub binary.
            unsafe { ffi::coraza_waf_free(previous_handle) };
        }

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
        // Hold the read lock across the FFI call so a parallel
        // `init()` waits for us to finish before swapping the handle.
        // Without that, a freed-handle race surfaces as spurious
        // `action="deny", rule_id=0` errors during reload.
        let s = state_read();
        match message.name.as_str() {
            "check-request" => process_request(message, &s.config, s.waf_handle),
            "check-response" => process_response(message, &s.config),
            _ => Ok(ProcessingResult::empty()),
        }
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    fn validate(&self, context: &PluginContext) -> Vec<Diagnostic> {
        // Pure SecLang compile-check via coraza.NewWAF, capturing
        // parser line numbers from the WAF's debug logger. No side
        // effects: NewWAF allocates rule structures + compiles
        // regexes but doesn't open sockets, spawn goroutines, or
        // touch shared state. The WAF instance is dropped at the end
        // of this call.
        //
        // Validates BOTH the top-level `directives` field and each
        // per-application `applications.<name>.directives` field. Per-
        // app directives are HAPTIC's primary path for per-Ingress
        // modsecurity-snippet wiring.
        //
        // Routes through `PluginConfig::from_context` rather than
        // walking the raw `PluginContext` so the schema understood
        // here exactly matches what `init()` consumes — single source
        // of truth, no parallel parser, no drift. The hub guarantees
        // the context already satisfies `config_schema()` before
        // calling `validate()` (haproxy-spoa-hub v0.5.2+
        // `plugin_loader::collect_schema_errors`), so we only do
        // semantic (Coraza-parser) checks here.
        let config = PluginConfig::from_context(context);
        let mut diagnostics = validate_directives_string(&config.directives);
        for app in &config.applications {
            for mut d in validate_directives_string(&app.directives) {
                let mut prefixed = String::with_capacity(d.message.len() + app.name.len() + 16);
                prefixed.push_str("application '");
                prefixed.push_str(&app.name);
                prefixed.push_str("': ");
                prefixed.push_str(d.message.as_str());
                d.message = prefixed.into();
                diagnostics.push(d);
            }
        }
        diagnostics
    }
});

/// Compile a SecLang directives string via Coraza, return any
/// captured warnings/errors as `plugin_api::Diagnostic` values.
fn validate_directives_string(directives: &str) -> Vec<Diagnostic> {
    if directives.is_empty() {
        return Vec::new();
    }
    // Use the length of the *converted* CString, not `directives.len()`.
    // `to_cstring` falls back to an empty string when the input
    // contains an interior null byte, so passing the original length
    // would have the Go side read past the end of the empty buffer
    // (out-of-bounds read). After conversion, `dir_c.as_bytes().len()`
    // is the actual byte count of the string Go will see.
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
    let json_ptr = unsafe { ffi::coraza_validate_directives(dir_c.as_ptr(), dir_len) };
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
fn parse_validation_json(json: &str) -> Vec<Diagnostic> {
    #[derive(serde::Deserialize)]
    struct CapturedDiagnostic {
        severity: String,
        line: u32,
        message: String,
    }
    let captured: Vec<CapturedDiagnostic> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    captured
        .into_iter()
        .map(|c| match c.severity.as_str() {
            "error" => Diagnostic::error(c.line, 0, c.message),
            _ => Diagnostic::warning(c.line, 0, c.message),
        })
        .collect()
}

impl Drop for CorazaPlugin {
    fn drop(&mut self) {
        // Log final metrics before the plugin instance goes away.
        // Counters are process-global on the Go side, so the values
        // include traffic from any concurrently-live instances during
        // a hub reload window — fine for an operator-facing summary.
        //
        // We don't free the WAF handle here. `init()` already frees
        // the previous handle when it swaps in a new one (see the
        // swap-and-replace block there), so the only handle still
        // alive at Drop time is the one currently serving traffic.
        // Freeing it here would race with the hub's atomic registry
        // swap and cut traffic out from under the new plugin
        // instance. The last handle is reaped by the Go runtime at
        // process exit.
        let allowed = unsafe { ffi::coraza_metrics_allowed() };
        let blocked = unsafe { ffi::coraza_metrics_blocked() };
        let rules_hit = unsafe { ffi::coraza_metrics_rules_hit() };
        let errors = unsafe { ffi::coraza_metrics_errors() };
        log::info!(
            "Coraza plugin shutting down: allowed={allowed}, blocked={blocked}, \
             rules_hit={rules_hit}, errors={errors}"
        );
    }
}

fn process_request(
    message: &SpoeMessage,
    config: &PluginConfig,
    waf_handle: u64,
) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
    let src_ip = message.get_string("src-ip").unwrap_or("");
    let src_port = message.get_int("src-port").unwrap_or(0) as i32;
    let dst_ip = message.get_string("dst-ip").unwrap_or("");
    let dst_port = message.get_int("dst-port").unwrap_or(0) as i32;
    let method = message.get_string("method").unwrap_or("");
    let path = message.get_string("path").unwrap_or("");
    let query = message.get_string("query").unwrap_or("");
    let version = message.get_string("version").unwrap_or("");
    let app_name = message.get_string("app");

    // headers and body can arrive as either Binary or String
    let headers_buf = extract_bytes_as_headers(message.get("headers"));
    let body_buf = extract_bytes(message.get("body"));

    // Generate transaction ID
    let tx_id = format!("{}-{}", message.stream_id, message.frame_id);

    // Convert to C strings
    let tx_id_c = to_cstring(&tx_id);
    let src_ip_c = to_cstring(src_ip);
    let dst_ip_c = to_cstring(dst_ip);
    let method_c = to_cstring(method);
    let path_c = to_cstring(path);
    let query_c = to_cstring(query);
    let version_c = to_cstring(version);

    let app_name_c = app_name.map(to_cstring);
    let app_name_ptr = app_name_c
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null());

    let cache_tx = if config.response_check { 1 } else { 0 };

    // Per-message detect-only override. When set on a request-side message,
    // the WAF still evaluates rules normally but coerces the verdict to
    // `action=allow` while keeping `rule_id`, `anomaly_score`, etc.
    // populated. Mirrors the response-side override and falls back to the
    // hub-global `config.detect_only` for absent or malformed values.
    // See specs/002-detect-only-request/.
    let detect_only = message
        .get_bool("detect-only")
        .unwrap_or(config.detect_only);
    let detect_only_flag = if detect_only { 1 } else { 0 };

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
            detect_only_flag,
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
        return Ok(ProcessingResult::empty());
    }

    let tx_id = message.get_string("id").unwrap_or("");
    let status_code = message.get_int("status").unwrap_or(0) as i32;
    let version = message.get_string("version").unwrap_or("");
    let detect_only = message
        .get_bool("detect-only")
        .unwrap_or(config.detect_only);

    // headers and body can arrive as either Binary or String
    let headers_buf = extract_bytes_as_headers(message.get("headers"));
    let body_buf = extract_bytes(message.get("body"));

    let tx_id_c = to_cstring(tx_id);
    let version_c = to_cstring(version);
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

    let variables = result_to_variables(&result, tx_id, true);
    result.free_data();

    Ok(ProcessingResult { variables })
}

/// Convert a CorazaResult into SPOE transaction variables.
fn result_to_variables(result: &CorazaResult, tx_id: &str, is_response: bool) -> RVec<TxnVariable> {
    let prefix = if is_response { "resp_" } else { "" };
    let mut vars = RVec::with_capacity(if is_response { 3 } else { 7 });

    if !is_response {
        vars.push(TxnVariable::transaction(
            "id",
            SpoeValue::String(RString::from(tx_id)),
        ));
    }

    vars.push(TxnVariable::transaction(
        format!("{prefix}action"),
        SpoeValue::String(RString::from(result.action_str())),
    ));

    vars.push(TxnVariable::transaction(
        format!("{prefix}status"),
        SpoeValue::Int32(result.status),
    ));

    vars.push(TxnVariable::transaction(
        format!("{prefix}rule_id"),
        SpoeValue::Int32(result.rule_id),
    ));

    if !is_response {
        vars.push(TxnVariable::transaction(
            "anomaly_score",
            SpoeValue::Int32(result.anomaly_score),
        ));

        vars.push(TxnVariable::transaction(
            "rules_hit",
            SpoeValue::Int32(result.rules_hit),
        ));

        let data = result.data_str();
        if !data.is_empty() {
            vars.push(TxnVariable::transaction(
                "data",
                SpoeValue::String(RString::from(data)),
            ));
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

/// Extract raw bytes from a `SpoeValue` that may be `Binary` or `String`.
fn extract_bytes(value: Option<&SpoeValue>) -> Vec<u8> {
    match value {
        Some(SpoeValue::Binary(b)) => b.to_vec(),
        Some(SpoeValue::String(s)) => s.as_bytes().to_vec(),
        _ => Vec::new(),
    }
}

/// Extract raw bytes from a `SpoeValue` that may be `Binary` or `String`,
/// then parse as HAProxy header format.
fn extract_bytes_as_headers(value: Option<&SpoeValue>) -> Vec<u8> {
    match value {
        Some(SpoeValue::Binary(b)) => parse_haproxy_headers(b.as_slice()),
        Some(SpoeValue::String(s)) => parse_haproxy_headers(s.as_bytes()),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod validate_tests {
    //! Unit tests for the `validate()` plugin-API method (spec
    //! `003-validate-override`). These cover both the per-field call
    //! into Coraza's parser via FFI and the per-application prefixing.

    use super::*;
    use haproxy_spoa_hub_plugin_api::{ConfigValue, DiagnosticSeverity, PluginContext, RHashMap};

    fn ctx_with(entries: Vec<(&str, ConfigValue)>) -> PluginContext {
        let mut config = RHashMap::new();
        for (k, v) in entries {
            config.insert(RString::from(k), v);
        }
        PluginContext {
            name: RString::from("coraza"),
            config,
        }
    }

    #[test]
    fn empty_config_yields_no_diagnostics() {
        let plugin = CorazaPlugin::__new();
        let diags = plugin.__validate(&ctx_with(vec![]));
        assert!(
            diags.is_empty(),
            "expected no diagnostics for empty config, got {diags:?}"
        );
    }

    #[test]
    fn empty_directives_string_yields_no_diagnostics() {
        let plugin = CorazaPlugin::__new();
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String("".into()),
        )]));
        assert!(
            diags.is_empty(),
            "expected no diagnostics for empty directives string, got {diags:?}"
        );
    }

    #[test]
    fn valid_directives_yield_no_errors() {
        let plugin = CorazaPlugin::__new();
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String("SecRuleEngine On\n".into()),
        )]));
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "expected no errors for valid directives, got {errors:?}"
        );
    }

    /// Regression: a plain SecLang typo (unknown directive) MUST surface
    /// as at least one Error diagnostic. This is the central property of
    /// validate() — invalid custom Coraza configs (e.g., from a HAPTIC
    /// per-Ingress modsecurity-snippet annotation) get caught at admission
    /// time rather than crashing the plugin's `init()` later.
    #[test]
    fn invalid_directive_yields_error() {
        let plugin = CorazaPlugin::__new();
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String("SecBogusDirective totally-invalid\n".into()),
        )]));
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(
            !errors.is_empty(),
            "expected at least one Error diagnostic for unknown directive, got {diags:?}"
        );
    }

    /// Regression: an unknown directive on a specific line MUST emit a
    /// diagnostic carrying a non-zero `line` field so the upstream
    /// admission webhook can highlight the offending row in the user's
    /// snippet. Coraza's parser uses the `logAndReturnErr` path for the
    /// "unknown directive" case which logs `Error().Int("line", N)`
    /// before returning the wrapped error — this is the most common
    /// operator typo case (a misspelled directive name).
    #[test]
    fn unknown_directive_yields_diagnostic_with_line_number() {
        let plugin = CorazaPlugin::__new();
        // Line 1: SecRuleEngine On (valid)
        // Line 2: blank
        // Line 3: typo of `SecRequestBodyAccess` — unknown directive
        let directives = "SecRuleEngine On\n\nSecResquestBodyAccess On\n";
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String(directives.into()),
        )]));
        assert!(
            !diags.is_empty(),
            "expected diagnostics for unknown directive, got none"
        );
        assert!(
            diags.iter().any(|d| d.line == 3),
            "expected diagnostic on line 3 (the typo line), got {diags:?}"
        );
    }

    /// Regression for the user-requested behaviour: invalid custom
    /// Coraza configs supplied through `applications.<name>.directives`
    /// MUST be caught by validate() and tagged with the application
    /// name so operators can find which Ingress is broken.
    ///
    /// Schema is `applications` as a TOML *table* keyed by app name —
    /// matching what `config_schema()` declares and what
    /// `PluginConfig::from_context` parses at runtime. Pre-v0.4.2 this
    /// test was written against an array-of-tables schema (each entry
    /// embedding `name` + `directives`); that was a parallel-parser
    /// bug in the validator path that silently no-op'd in production
    /// because the runtime parser used the table-keyed-by-name form.
    /// Routing both paths through `from_context` collapsed the two
    /// schemas into one source of truth.
    #[test]
    fn invalid_application_directives_yield_prefixed_error() {
        let plugin = CorazaPlugin::__new();
        let mut app_table = RHashMap::new();
        app_table.insert(
            RString::from("directives"),
            ConfigValue::String("SecBogusDirective foo\n".into()),
        );
        let mut applications = RHashMap::new();
        applications.insert(
            RString::from("ingress-prod-foo"),
            ConfigValue::Table(app_table),
        );
        let ctx = ctx_with(vec![("applications", ConfigValue::Table(applications))]);

        let diags = plugin.__validate(&ctx);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(
            !errors.is_empty(),
            "expected error for bad application directives, got {diags:?}"
        );
        assert!(
            errors.iter().any(|d| d
                .message
                .as_str()
                .contains("application 'ingress-prod-foo':")),
            "expected app-name prefix in messages, got {:?}",
            errors
                .iter()
                .map(|d| d.message.as_str().to_string())
                .collect::<Vec<_>>()
        );
    }

    /// Multiple applications under the same `applications` table each
    /// get their diagnostics independently and tagged with their own
    /// app name. Pins the per-app isolation contract: a bad rule in
    /// one app doesn't suppress validation of another.
    #[test]
    fn multiple_applications_each_validated_with_own_name_prefix() {
        let plugin = CorazaPlugin::__new();
        let mut applications = RHashMap::new();
        let mut alpha = RHashMap::new();
        alpha.insert(
            RString::from("directives"),
            ConfigValue::String("SecBogusAlpha foo\n".into()),
        );
        applications.insert(RString::from("alpha"), ConfigValue::Table(alpha));
        let mut bravo = RHashMap::new();
        bravo.insert(
            RString::from("directives"),
            ConfigValue::String("SecBogusBravo bar\n".into()),
        );
        applications.insert(RString::from("bravo"), ConfigValue::Table(bravo));

        let ctx = ctx_with(vec![("applications", ConfigValue::Table(applications))]);

        let diags = plugin.__validate(&ctx);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(
            errors
                .iter()
                .any(|d| d.message.as_str().contains("application 'alpha':")),
            "expected alpha-prefix in messages, got {:?}",
            errors
                .iter()
                .map(|d| d.message.as_str().to_string())
                .collect::<Vec<_>>()
        );
        assert!(
            errors
                .iter()
                .any(|d| d.message.as_str().contains("application 'bravo':")),
            "expected bravo-prefix in messages, got {:?}",
            errors
                .iter()
                .map(|d| d.message.as_str().to_string())
                .collect::<Vec<_>>()
        );
    }

    /// Regression for the null-byte FFI length mismatch. `to_cstring`
    /// falls back to an empty CString on interior null bytes; if we
    /// passed the original `&str` length to the Go side it would read
    /// `len` bytes from a 1-byte buffer and corrupt memory. Using
    /// `dir_c.as_bytes().len()` after conversion keeps lengths and
    /// pointers coherent. The plugin must NOT crash for this input.
    #[test]
    fn directives_with_interior_null_byte_does_not_corrupt_memory() {
        let plugin = CorazaPlugin::__new();
        let directives = "SecRuleEngine On\n\0SecBogus On\n";
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String(directives.into()),
        )]));
        // We don't assert a specific shape — Coraza sees an empty
        // directives string after the conversion and returns no
        // diagnostics. The point of the test is that we don't read
        // past the end of the converted buffer, which would manifest
        // as a crash or sanitiser error under MIRI / asan.
        let _ = diags;
    }

    /// Coraza-bundled directives like `@coraza.conf-recommended` and
    /// `@owasp_crs/*.conf` reference the embedded CRS filesystem. The
    /// production WAF wires this via `WithRootFS(mergefs.Merge(coreruleset.FS, ...))`;
    /// `validate()` must mirror that setup or it would synthesise
    /// false-positive errors for configs that production accepts.
    #[test]
    fn validates_embedded_coreruleset_includes() {
        let plugin = CorazaPlugin::__new();
        let directives = concat!(
            "SecRuleEngine On\n",
            "Include @coraza.conf-recommended\n",
            "Include @crs-setup.conf.example\n",
            "Include @owasp_crs/*.conf\n",
        );
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String(directives.into()),
        )]));
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "embedded CRS includes must resolve via mergefs(coreruleset.FS, ...), got {errors:?}"
        );
    }

    /// Plugins MUST leave `path` empty so the hub can overwrite it
    /// with the file identity it knows about. See plugin-api delta in
    /// `specs/004-validate-mode/contracts/plugin-api-delta.md`.
    #[test]
    fn diagnostics_have_empty_path_for_hub_to_fill() {
        let plugin = CorazaPlugin::__new();
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String("SecBogusDirective foo\n".into()),
        )]));
        for d in &diags {
            assert!(
                d.path.is_empty(),
                "plugin diagnostic carried non-empty path; hub-owned invariant violated: {:?}",
                d.path.as_str()
            );
        }
    }
}

#[cfg(test)]
mod reload_tests {
    //! Regression tests for the plugin's reload semantics. The hub
    //! reloads by creating a NEW plugin instance, calling `init()` on
    //! it, atomic-swapping the registry, then dropping the old
    //! instance (see haproxy-spoa-hub `crates/hub/src/main.rs::reload_plugins`).
    //! Linux's dlopen returns the same process-shared handle for the
    //! same `.so` path, so the plugin's `static` data segment persists
    //! across hub-level "loads" — i.e. across multiple `init()` calls
    //! the plugin sees in one process. Any state that holds the live
    //! WAF handle MUST therefore be replaceable on every init, not
    //! one-shot.
    //!
    //! The bug this module exists to prevent: a `OnceLock<u64>` for
    //! the WAF handle silently drops the second init's handle and
    //! keeps serving requests with the first init's handle, which the
    //! old plugin's Drop has already freed. Symptoms in production:
    //! after HAPTIC pushes a hub config update with new SecRules,
    //! coraza ignores the new rules — every request lands on the
    //! WAF-engine-error path (action="deny", rule_id=0) instead of
    //! either the new rules' decision or a fresh allow.
    //!
    //! Note on test isolation: this module's tests touch `WAF_HANDLE`
    //! / `CONFIG`, which are crate-level statics. Running these tests
    //! concurrently with anything else that calls `__init` would
    //! corrupt that shared state. Today no other test does — keep it
    //! that way, or wire up `serial_test` if a second `__init` caller
    //! ever lands.

    use super::*;
    use haproxy_spoa_hub_plugin_api::{
        ConfigValue, PluginContext, RHashMap, RString, SpoeMessage, SpoeValue,
    };

    fn make_context(directives: &str) -> PluginContext {
        let mut config = RHashMap::new();
        config.insert(
            RString::from("directives"),
            ConfigValue::String(directives.into()),
        );
        PluginContext {
            name: RString::from("coraza"),
            config,
        }
    }

    fn make_check_request(path: &str) -> SpoeMessage {
        let mut args = RHashMap::new();
        args.insert(
            RString::from("src-ip"),
            SpoeValue::String("127.0.0.1".into()),
        );
        args.insert(RString::from("src-port"), SpoeValue::Int32(12345));
        args.insert(
            RString::from("dst-ip"),
            SpoeValue::String("10.0.0.1".into()),
        );
        args.insert(RString::from("dst-port"), SpoeValue::Int32(80));
        args.insert(RString::from("method"), SpoeValue::String("GET".into()));
        args.insert(RString::from("path"), SpoeValue::String(path.into()));
        args.insert(RString::from("query"), SpoeValue::String("".into()));
        args.insert(
            RString::from("version"),
            SpoeValue::String("HTTP/1.1".into()),
        );
        args.insert(
            RString::from("headers"),
            SpoeValue::Binary(b"Host\0example.com\0".to_vec().into()),
        );
        SpoeMessage {
            name: RString::from("check-request"),
            args,
            stream_id: 1,
            frame_id: 1,
        }
    }

    fn find_var<'a>(result: &'a ProcessingResult, name: &str) -> &'a SpoeValue {
        &result
            .variables
            .iter()
            .find(|v| v.name.as_str() == name)
            .unwrap_or_else(|| {
                panic!(
                    "plugin must emit `{name}` variable; got {:?}",
                    result.variables
                )
            })
            .value
    }

    /// After a reload, the new init's directives MUST be the ones
    /// `process()` evaluates against. Mirrors the hub's reload
    /// pipeline: build the new plugin first, init it, then drop the
    /// old plugin last.
    ///
    /// With a `OnceLock<u64>` for the WAF handle this fails because
    /// the second init's `WAF_HANDLE.set(h2)` returns `Err(_)`
    /// silently and `process()` keeps reading the freed first handle.
    /// The Go side's `getWAF(stale_handle)` errors out and returns
    /// the deny-by-default WAF-engine-error result with `rule_id = 0`,
    /// so we assert on `rule_id` matching the new init's SecRule id —
    /// that's the only signal that distinguishes "the new WAF
    /// processed this request" from "we hit the error path."
    #[test]
    fn process_after_reload_uses_new_init_waf() {
        // Init #1 — first plugin instance with rule 9001 blocking /v1.
        let mut plugin1 = CorazaPlugin::__new();
        plugin1
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecRule REQUEST_URI \"@beginsWith /v1\" \"id:9001,phase:1,deny,status:403\"\n",
            ))
            .expect("first init should succeed");

        // Init #2 — new plugin instance with DIFFERENT rule 9002
        // blocking /v2. Must run BEFORE plugin1 is dropped to mirror
        // the hub's reload pipeline (build-new → init-new →
        // atomic-swap → drop-old).
        let mut plugin2 = CorazaPlugin::__new();
        plugin2
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecRule REQUEST_URI \"@beginsWith /v2\" \"id:9002,phase:1,deny,status:403\"\n",
            ))
            .expect("second init should succeed");

        // Drop the old instance. With OnceLock-backed WAF_HANDLE this
        // is what makes the bug observable: the freed handle is the
        // only one `process()` knows about.
        drop(plugin1);

        // /v2 must match rule 9002 (in plugin2's directives) AND must
        // NOT match rule 9001 (in plugin1's directives, which were
        // supposed to be replaced).
        let result = plugin2
            .__process(&make_check_request("/v2"))
            .expect("process should succeed");

        let action = find_var(&result, "action");
        let rule_id = find_var(&result, "rule_id");

        match action {
            SpoeValue::String(s) => assert_eq!(
                s.as_str(),
                "deny",
                "second init's rule must enforce on /v2 after reload",
            ),
            other => panic!("action variable should be String, got {other:?}"),
        }
        match rule_id {
            SpoeValue::Int32(id) => assert_eq!(
                *id, 9002,
                "rule_id must be the second init's rule (9002). \
                 rule_id=0 means the WAF-engine-error path fired \
                 (stale freed handle); rule_id=9001 means the first \
                 init's WAF was used (also wrong — its directives are \
                 supposed to have been replaced)",
            ),
            other => panic!("rule_id variable should be Int32, got {other:?}"),
        }
    }
}
