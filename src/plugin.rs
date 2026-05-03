use std::ffi::{CStr, c_char, c_int};
use std::sync::OnceLock;

use haproxy_spoa_hub_plugin_api::{
    ConfigValue, Diagnostic, PluginContext, ProcessingResult, RString, RVec, SpoeMessage,
    SpoeValue, TxnVariable, define_plugin,
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
        // entry in `applications[].directives`. Per-app directives
        // are HAPTIC's primary path for per-Ingress modsecurity-
        // snippet wiring (see docs/agents/coraza-pluggable.md after
        // chart-side wiring lands).
        let mut diagnostics = Vec::new();
        validate_directives_field(context, "directives", &mut diagnostics);
        validate_applications(context, &mut diagnostics);
        diagnostics
    }
});

/// Validate the directives string at `key` (top-level `directives` or
/// `applications[].directives`) by compiling it via Coraza and
/// capturing line-numbered parser diagnostics.
fn validate_directives_field(
    context: &PluginContext,
    key: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(value) = context.get_config(key) else {
        return;
    };
    let Some(directives) = value.as_str() else {
        return;
    };
    diagnostics.extend(validate_directives_string(directives));
}

/// Validate each `[plugins.params.coraza.applications]` entry's
/// `directives` field. Skipped silently when applications is missing
/// or has the wrong shape — the schema check handles structural
/// errors.
fn validate_applications(context: &PluginContext, diagnostics: &mut Vec<Diagnostic>) {
    let Some(apps) = context
        .get_config("applications")
        .and_then(ConfigValue::as_array)
    else {
        return;
    };
    for app in apps {
        let Some(table) = app.as_table() else {
            continue;
        };
        let Some(directives) = table
            .get(&RString::from("directives"))
            .and_then(ConfigValue::as_str)
        else {
            continue;
        };
        // Tag each diagnostic with the app name when available so
        // the operator can find which application's directives are
        // bad. Coraza's parser doesn't know about app names so we
        // prefix the message ourselves.
        let app_name = table
            .get(&RString::from("name"))
            .and_then(ConfigValue::as_str)
            .unwrap_or("<unnamed>");
        for mut d in validate_directives_string(directives) {
            let mut prefixed = String::with_capacity(d.message.len() + app_name.len() + 16);
            prefixed.push_str("application '");
            prefixed.push_str(app_name);
            prefixed.push_str("': ");
            prefixed.push_str(d.message.as_str());
            d.message = prefixed.into();
            diagnostics.push(d);
        }
    }
}

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
    use haproxy_spoa_hub_plugin_api::{
        ConfigValue, DiagnosticSeverity, PluginContext, RHashMap, RVec,
    };

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
    /// Coraza configs supplied through `applications[].directives` MUST
    /// be caught by validate() and tagged with the application name so
    /// operators can find which Ingress is broken.
    #[test]
    fn invalid_application_directives_yield_prefixed_error() {
        let plugin = CorazaPlugin::__new();
        let mut app = RHashMap::new();
        app.insert(
            RString::from("name"),
            ConfigValue::String("ingress-prod-foo".into()),
        );
        app.insert(
            RString::from("directives"),
            ConfigValue::String("SecBogusDirective foo\n".into()),
        );
        let apps: RVec<ConfigValue> = vec![ConfigValue::Table(app)].into();
        let ctx = ctx_with(vec![("applications", ConfigValue::Array(apps))]);

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
