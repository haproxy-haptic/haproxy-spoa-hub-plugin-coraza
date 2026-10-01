use std::ffi::{CStr, CString, c_char, c_int};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use haproxy_spoa_hub_plugin_api::{
    ConfigValue, Diagnostic, MetricRecorder, PluginContext, ProcessingResult, RString, RVec,
    SpoeMessage, SpoeValue, TxnVariable, define_plugin,
};

use crate::config::PluginConfig;
use crate::ffi::{self, CorazaResult, to_cstring};
use crate::watcher::{self, Fingerprint, RuleWatcher};

static TX_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct WafHandle(u64);

impl Drop for WafHandle {
    fn drop(&mut self) {
        unsafe { ffi::coraza_waf_free(self.0) };
    }
}

/// One completely compiled, immutable plugin generation. It is built off to
/// the side and installed only after every application WAF succeeds, so failed
/// hub reloads cannot mutate the generation still serving traffic.
#[derive(Debug)]
struct WafGeneration {
    default: WafHandle,
    applications: HashMap<String, WafHandle>,
}

impl WafGeneration {
    fn build(config: &PluginConfig) -> Result<Self, String> {
        let default = WafHandle(create_waf(
            &config.directives,
            config.directives_file.as_deref(),
            config.request_body_limit,
            config.request_body_in_memory_limit,
            config.response_body_limit,
            config,
        )?);
        let rules_count = unsafe { ffi::coraza_waf_rules_count(default.0) };
        log::info!("Coraza default WAF initialized with {rules_count} rules");

        let mut applications = HashMap::with_capacity(config.applications.len());
        for app in &config.applications {
            let handle = WafHandle(
                create_waf(
                    &app.directives,
                    app.directives_file.as_deref(),
                    app.request_body_limit,
                    app.request_body_in_memory_limit,
                    app.response_body_limit,
                    config,
                )
                .map_err(|error| format!("application '{}': {error}", app.name))?,
            );
            let app_rules = unsafe { ffi::coraza_waf_rules_count(handle.0) };
            log::info!(
                "Coraza WAF app '{}' initialized with {app_rules} rules",
                app.name
            );
            applications.insert(app.name.clone(), handle);
        }

        Ok(Self {
            default,
            applications,
        })
    }

    fn select<'a>(&self, application: Option<&'a str>) -> Result<(u64, &'a str), String> {
        match application.filter(|name| !name.is_empty()) {
            None => Ok((self.default.0, "")),
            Some(name) => self
                .applications
                .get(name)
                .map(|handle| (handle.0, name))
                .ok_or_else(|| format!("unknown Coraza application policy '{name}'")),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    generation: Option<WafGeneration>,
    config: PluginConfig,
}

/// Plugin-scoped metric recorder. The `define_plugin!` `metrics_static`
/// arm binds the hub's v2 recorder here once between `create` and
/// `init`. With a v0.5.x hub (pre-vtable-v2) the install never fires
/// and emissions are silent no-ops — plugin is forward-compatible
/// with older hubs.
static METRICS: MetricRecorder = MetricRecorder::new();

#[derive(Debug)]
struct CorazaPlugin {
    // Shared with the rule-file watcher thread, which rebuilds the generation
    // against this same state. An Arc rather than a borrow so the state cannot
    // be freed while that thread is between its stop check and its next use.
    state: Arc<RwLock<State>>,
    // Replaced on every init; dropping the previous handle stops and joins its
    // thread, so a reconfigure never leaves two watchers rebuilding one plugin.
    watcher: Mutex<Option<RuleWatcher>>,
}

impl CorazaPlugin {
    /// Replace the rule-file watcher for a new configuration.
    ///
    /// Dropping the previous handle stops and joins its thread first, so a
    /// reconfigure can never leave two watchers rebuilding one plugin.
    fn restart_rule_watcher(&self, globs: Vec<String>, interval: Duration, baseline: Fingerprint) {
        let mut slot = self
            .watcher
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *slot = None;

        // A zero interval means watching is off, as documented. Passing it on
        // would not sleep at all: the poll loop would spin a core stat-ing the
        // rule files, which is the opposite of disabling it.
        if globs.is_empty() || interval.is_zero() {
            return;
        }

        log::info!(
            "Coraza watching {} rule glob(s) for changes every {:?}",
            globs.len(),
            interval
        );
        let state = Arc::clone(&self.state);
        *slot = Some(RuleWatcher::spawn(globs, interval, baseline, move || {
            rebuild_generation(&state);
        }));
    }
}

/// Recompile the WAF from the current config and swap it in.
///
/// The build happens outside the write lock: compiling a full rule set takes
/// long enough that holding the lock would stall every request for its
/// duration, and the point of a local reload is that traffic does not notice.
///
/// A failed build keeps the running generation. The rule files are written by
/// something else and can be observed mid-batch, so "does not compile right
/// now" is an expected transient — retrying on the next poll is correct, and
/// serving the previous rules meanwhile is strictly better than serving none.
fn rebuild_generation(state: &Arc<RwLock<State>>) {
    let config = {
        let guard = state.read().unwrap_or_else(|error| error.into_inner());
        guard.config.clone()
    };

    match WafGeneration::build(&config) {
        Ok(generation) => {
            let mut guard = state.write().unwrap_or_else(|error| error.into_inner());
            guard.generation = Some(generation);
            drop(guard);
            log::info!("Coraza reloaded its rule set after an on-disk change");
            METRICS.counter("plugin_coraza_rule_reloads_total", &[("result", "ok")], 1);
        }
        Err(error) => {
            // Loud: a WAF quietly serving rules older than the ones on disk is
            // the failure this whole path exists to avoid.
            log::warn!("Coraza rule reload failed, keeping the running rule set: {error}");
            METRICS.counter(
                "plugin_coraza_rule_reloads_total",
                &[("result", "failed")],
                1,
            );
        }
    }
}

define_plugin!(CorazaPlugin, {
    fn new() -> Self {
        CorazaPlugin {
            state: Arc::new(RwLock::new(State::default())),
            watcher: Mutex::new(None),
        }
    }

    fn init(
        &mut self,
        context: &PluginContext,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = PluginConfig::from_context(context);
        let watch_globs = config.rule_watch_globs();
        let watch_interval = config.rule_watch_interval();
        // Before the build, never after: a rule file written between the two is
        // then a change the watcher still sees.
        let baseline = watcher::fingerprint(&watch_globs);

        let generation = WafGeneration::build(&config)
            .map_err(|error| format!("failed to build Coraza generation: {error}"))?;

        let mut state = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        *state = State {
            generation: Some(generation),
            config,
        };
        drop(state);

        self.restart_rule_watcher(watch_globs, watch_interval, baseline);

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
        let state = self.state.read().unwrap_or_else(|error| error.into_inner());
        match message.name.as_str() {
            "check-request" => {
                let generation = state
                    .generation
                    .as_ref()
                    .ok_or("Coraza plugin has not been initialized")?;
                let (handle, selected_app) = generation.select(message.get_string("app"))?;
                process_request(message, &state.config, handle, selected_app)
            }
            "check-response" => process_response(message, &state.config),
            _ => Ok(ProcessingResult::empty()),
        }
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    fn validate(&self, context: &PluginContext) -> Vec<Diagnostic> {
        let config = PluginConfig::from_context(context);
        let staged = CString::new(staged_files_json(context)).expect("JSON escapes null bytes");
        let mut diagnostics = validate_directives_string(&config.directives, &staged);
        for app in &config.applications {
            for mut d in validate_directives_string(&app.directives, &staged) {
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

    metrics_static = METRICS;
});

/// Config key under which the hub's validator hands over the request's data
/// files, as a table of path -> content. Contract owned by the hub
/// (`crates/hub/src/validate/orchestrator.rs`); absent at runtime, where the
/// files are really on disk and the OS filesystem layer serves them.
const STAGED_FILES_KEY: &str = "__staged_files";

/// Extract the staged files as a JSON object for the FFI hop.
///
/// Returns an empty string when the key is absent — the ordinary case for a
/// config whose directives include nothing off disk, and for every runtime
/// call. Non-string entries are skipped rather than failing the whole
/// validation: the hub only ever sends strings, so a stray value means a
/// future protocol addition this build predates.
fn staged_files_json(context: &PluginContext) -> String {
    let Some(ConfigValue::Table(files)) = context.config.get(&RString::from(STAGED_FILES_KEY))
    else {
        return String::new();
    };
    let map: std::collections::BTreeMap<&str, &str> = files
        .iter()
        .filter_map(|entry| entry.1.as_str().map(|content| (entry.0.as_str(), content)))
        .collect();
    if map.is_empty() {
        return String::new();
    }
    serde_json::to_string(&map).expect("string map serializes as JSON")
}

/// Compile a SecLang directives string via Coraza, return any
/// captured warnings/errors as `plugin_api::Diagnostic` values.
fn validate_directives_string(directives: &str, staged_files_json: &CStr) -> Vec<Diagnostic> {
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
fn parse_validation_json(json: &str) -> Vec<Diagnostic> {
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

impl Drop for CorazaPlugin {
    fn drop(&mut self) {
        // Log final metrics before the plugin instance goes away.
        // Counters are process-global on the Go side, so the values
        // include traffic from any concurrently-live instances during
        // a hub reload window — fine for an operator-facing summary.
        //
        // Instance fields are dropped immediately after this method. Each WAF
        // handle is then retired on the Go side; handles with cached response
        // transactions remain leased until those transactions finish or
        // expire.
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
    selected_app: &str,
) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
    let src_ip = message.get_string("src-ip").unwrap_or("");
    let src_port = message.get_int("src-port").unwrap_or(0) as i32;
    let dst_ip = message.get_string("dst-ip").unwrap_or("");
    let dst_port = message.get_int("dst-port").unwrap_or(0) as i32;
    let method = message.get_string("method").unwrap_or("");
    let path = message.get_string("path").unwrap_or("");
    let query = message.get_string("query").unwrap_or("");
    let version = message.get_string("version").unwrap_or("");
    let body_mode = message.get_string("body-mode");
    let inspect_body = match body_mode {
        // A missing completeness assertion can never make a potentially
        // partial HAProxy buffer safe to inspect. Default to the header-only
        // path; integrations that need phase-2 body variables must opt in to
        // the explicit buffered contract below.
        None => false,
        Some("none") => false,
        Some("buffered") => {
            if !message.get_bool("body-complete").unwrap_or(false) {
                return Err(
                    "buffered request body is incomplete; refusing partial WAF inspection".into(),
                );
            }
            true
        }
        Some(other) => return Err(format!("unsupported body-mode '{other}'").into()),
    };

    // headers and body can arrive as either Binary or String
    let headers_buf = extract_bytes_as_headers(message.get("headers"));
    let body_buf = if inspect_body {
        extract_bytes(message.get("body"))
    } else {
        Vec::new()
    };

    // Stream/frame IDs are scoped to one SPOP connection and collide across
    // HAProxy processes. A process-wide sequence makes response correlation
    // unique without putting request data into the identifier.
    let sequence = TX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let tx_id = format!("{sequence}-{}-{}", message.stream_id, message.frame_id);

    // Convert to C strings
    let tx_id_c = checked_cstring("transaction ID", &tx_id)?;
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
    let elapsed = start.elapsed();
    let latency_us = elapsed.as_micros();

    if result.action.is_null() {
        return Err(format!("Coraza request evaluation failed: {}", last_ffi_error()).into());
    }

    log::debug!(
        "coraza request: action={} rule_id={} latency_us={latency_us}",
        result.action_str(),
        result.rule_id,
    );

    emit_eval_metrics("request", &result, selected_app, elapsed);

    let variables = result_to_variables(&result, &tx_id, false, config.expose_matched_data);
    result.free_data();
    result.free_matched_rules();
    result.free_matched_var();

    Ok(ProcessingResult { variables })
}

/// Emit Prometheus metrics for one WAF evaluation. Called from both
/// `process_request` and `process_response`; centralises the label
/// shape so the two paths can't drift. Hub prefixes everything with
/// `plugin_coraza_`.
fn emit_eval_metrics(
    phase: &str,
    result: &ffi::CorazaResult,
    app: &str,
    elapsed: std::time::Duration,
) {
    let action = result.action_str();
    METRICS.counter(
        "evaluations_total",
        &[("phase", phase), ("action", action), ("app", app)],
        1,
    );
    METRICS.histogram(
        "evaluation_duration_seconds",
        &[("phase", phase), ("app", app)],
        elapsed.as_secs_f64(),
    );
    // Denies are the operationally-critical signal: separate counter
    // with the rule_id surfaces "which rules are blocking traffic"
    // without joining counters.
    if action == "deny" {
        let rule_id_label = result.rule_id.to_string();
        METRICS.counter(
            "denials_total",
            &[("phase", phase), ("rule_id", &rule_id_label), ("app", app)],
            1,
        );
    }
    emit_rule_hit_metrics(phase, result, app);
}

/// Per-matched-rule hit counters — the detect-mode tuning signal.
/// `denials_total` only names the single interrupting rule; tuning a
/// policy toward `deny` needs every rule that fired on traffic that was
/// ultimately ALLOWED (in detect mode nothing interrupts at all). Rules
/// arrive as compact JSON from the Go bridge; only rules that actually
/// matched emit.
///
/// Cardinality ceiling: series count is bounded by
/// (#distinct rules that have ever matched) x (#apps) x (2 phases).
/// Severity does NOT multiply the product — each rule ID carries one
/// fixed severity, so it's a dependent label kept for query ergonomics.
/// CRS ships ~800 rule IDs but only a small fraction ever match real
/// traffic; a deployment where every rule matched for every app would
/// still sit well under typical per-target series budgets. A decode
/// failure of the FFI payload increments `rule_hits_decode_errors_total`
/// so a contract break between the Go bridge and this parser is
/// operator-visible rather than a silent metric flatline.
fn emit_rule_hit_metrics(phase: &str, result: &ffi::CorazaResult, app: &str) {
    #[derive(serde::Deserialize)]
    struct RuleHit {
        i: i64,
        s: i64,
    }
    let raw = result.matched_rules_str();
    if raw.is_empty() {
        return;
    }
    let hits: Vec<RuleHit> = match serde_json::from_str(raw) {
        Ok(hits) => hits,
        Err(err) => {
            log::debug!("unparseable matched_rules payload ({err}): {raw}");
            METRICS.counter("rule_hits_decode_errors_total", &[("app", app)], 1);
            return;
        }
    };
    for hit in hits {
        let rule_id = hit.i.to_string();
        METRICS.counter(
            "rule_hits_total",
            &[
                ("phase", phase),
                ("rule_id", &rule_id),
                ("severity", severity_label(hit.s)),
                ("app", app),
            ],
            1,
        );
    }
}

/// ModSecurity/Coraza severity numbers to their standard names. Coraza
/// reports -1 for rules that declare no severity (CRS administrative /
/// reporting rules) — those map to "none", as does anything out of range.
fn severity_label(severity: i64) -> &'static str {
    match severity {
        0 => "emergency",
        1 => "alert",
        2 => "critical",
        3 => "error",
        4 => "warning",
        5 => "notice",
        6 => "info",
        7 => "debug",
        _ => "none",
    }
}

fn process_response(
    message: &SpoeMessage,
    config: &PluginConfig,
) -> Result<ProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
    let tx_id = message.get_string("id").unwrap_or("");
    let status_code = message.get_int("status").unwrap_or(0) as i32;
    let version = message.get_string("version").unwrap_or("");
    let detect_only = message
        .get_bool("detect-only")
        .unwrap_or(config.detect_only);

    // headers and body can arrive as either Binary or String
    let headers_buf = extract_bytes_as_headers(message.get("headers"));
    let body_buf = extract_bytes(message.get("body"));

    let tx_id_c = checked_cstring("transaction ID", tx_id)?;
    let version_c = checked_cstring("HTTP version", version)?;
    let headers_len = checked_ffi_len("headers", headers_buf.len())?;
    let body_len = checked_ffi_len("body", body_buf.len())?;
    let detect_only_flag = if detect_only { 1 } else { 0 };

    let start = std::time::Instant::now();
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
    let elapsed = start.elapsed();

    if result.action.is_null() {
        return Err(format!("Coraza response evaluation failed: {}", last_ffi_error()).into());
    }

    // No `app` label on the response path — the upstream coraza FFI
    // looks up the app context by tx_id, not by an arg. Pass empty
    // string for consistent labelset shape across phase=request and
    // phase=response.
    emit_eval_metrics("response", &result, "", elapsed);

    let variables = result_to_variables(&result, tx_id, true, false);
    result.free_data();
    result.free_matched_rules();
    result.free_matched_var();

    Ok(ProcessingResult { variables })
}

/// Convert a CorazaResult into SPOE transaction variables.
fn result_to_variables(
    result: &CorazaResult,
    tx_id: &str,
    is_response: bool,
    expose_matched_data: bool,
) -> RVec<TxnVariable> {
    let prefix = if is_response { "resp_" } else { "" };
    let mut vars = RVec::with_capacity(if is_response { 3 } else { 8 });

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

        // The NAME of the field a rule matched on (e.g. ARGS:q), never its
        // value — so unlike `data` below this needs no expose_matched_data gate.
        // It carries no request content, which is what makes it loggable.
        let matched_var = result.matched_var_str();
        if !matched_var.is_empty() {
            vars.push(TxnVariable::transaction(
                "matched_var",
                SpoeValue::String(RString::from(matched_var)),
            ));
        }

        let data = result.data_str();
        if expose_matched_data && !data.is_empty() {
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
    config: &PluginConfig,
) -> Result<u64, String> {
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
        )
    };

    if handle == 0 {
        Err(last_ffi_error())
    } else {
        Ok(handle)
    }
}

fn checked_cstring(
    field: &str,
    value: &str,
) -> Result<std::ffi::CString, Box<dyn std::error::Error + Send + Sync>> {
    std::ffi::CString::new(value)
        .map_err(|_| format!("{field} contains an interior NUL byte").into())
}

fn checked_ffi_len(
    field: &str,
    value: usize,
) -> Result<c_int, Box<dyn std::error::Error + Send + Sync>> {
    c_int::try_from(value).map_err(|_| format!("{field} exceeds i32::MAX bytes").into())
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
mod staged_files_tests {
    //! The hub's validator hands over the request's data files under
    //! `__staged_files` so directives that Include a path off the HAProxy
    //! pod's disk can be compiled by a validator that has no such disk.

    use super::*;
    use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext, RHashMap};

    fn ctx_with_staged(entries: Vec<(&str, ConfigValue)>) -> PluginContext {
        let mut files = RHashMap::new();
        for (k, v) in entries {
            files.insert(RString::from(k), v);
        }
        let mut config = RHashMap::new();
        config.insert(RString::from(STAGED_FILES_KEY), ConfigValue::Table(files));
        PluginContext {
            name: RString::from("coraza"),
            config,
        }
    }

    // Absent is the ordinary case: every runtime call, and any config whose
    // directives include nothing off disk.

    #[test]
    fn absent_key_yields_empty_payload() {
        let ctx = PluginContext {
            name: RString::from("coraza"),
            config: RHashMap::new(),
        };
        assert_eq!(staged_files_json(&ctx), "");
    }

    #[test]
    fn staged_files_become_a_json_object() {
        let ctx = ctx_with_staged(vec![(
            "/etc/haproxy/general/crs/a.conf",
            ConfigValue::String(RString::from("SecAction id:1")),
        )]);

        let payload = staged_files_json(&ctx);

        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            parsed["/etc/haproxy/general/crs/a.conf"],
            serde_json::Value::String("SecAction id:1".into())
        );
    }

    // An empty table must read as "nothing staged", not as an empty JSON
    // object: the Go side would build a staged filesystem with no entries,
    // which shadows nothing but costs a merge layer on every validation.
    #[test]
    fn empty_table_yields_empty_payload() {
        let ctx = ctx_with_staged(vec![]);
        assert_eq!(staged_files_json(&ctx), "");
    }

    // A non-string entry means a protocol addition this build predates.
    // Skipping it keeps the files this build does understand usable, rather
    // than failing validation over a value it was never going to read.
    #[test]
    fn non_string_entries_are_skipped() {
        let ctx = ctx_with_staged(vec![
            ("/a.conf", ConfigValue::String(RString::from("keep"))),
            ("/b.conf", ConfigValue::Integer(42)),
        ]);

        let parsed: serde_json::Value = serde_json::from_str(&staged_files_json(&ctx)).unwrap();

        assert_eq!(parsed.as_object().unwrap().len(), 1);
        assert!(parsed.get("/a.conf").is_some());
        assert!(parsed.get("/b.conf").is_none());
    }

    // The wrong ConfigValue shape entirely — not a table — must not panic.
    #[test]
    fn non_table_value_yields_empty_payload() {
        let mut config = RHashMap::new();
        config.insert(
            RString::from(STAGED_FILES_KEY),
            ConfigValue::String(RString::from("not a table")),
        );
        let ctx = PluginContext {
            name: RString::from("coraza"),
            config,
        };
        assert_eq!(staged_files_json(&ctx), "");
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

    /// Null bytes cannot be represented on the C string boundary. Reject them
    /// explicitly instead of validating an empty substitute and then failing
    /// later during plugin initialization.
    #[test]
    fn directives_with_interior_null_byte_does_not_corrupt_memory() {
        let plugin = CorazaPlugin::__new();
        let directives = "SecRuleEngine On\n\0SecBogus On\n";
        let diags = plugin.__validate(&ctx_with(vec![(
            "directives",
            ConfigValue::String(directives.into()),
        )]));
        assert!(
            diags
                .iter()
                .any(|d| d.message.as_str().contains("interior null byte")),
            "null bytes must fail validation explicitly, got {diags:?}"
        );
    }

    #[test]
    fn malformed_validator_json_fails_closed() {
        let diags = parse_validation_json("not-json");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].severity, DiagnosticSeverity::Error);
        assert!(diags[0].message.as_str().contains("malformed diagnostics"));
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
    //! Regression tests for atomic, instance-owned reload generations. The hub
    //! constructs and initializes a new instance before swapping registries;
    //! the old instance must remain fully usable if that build fails, and old
    //! application names must not leak into the next instance through shared
    //! Go or Rust maps.

    use super::*;
    use haproxy_spoa_hub_plugin_api::{
        ConfigValue, PluginContext, RHashMap, RString, SpoeMessage, SpoeValue,
    };
    use std::thread;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // The whole point of the feature: a rule file changing on disk must change
    // the WAF that serves traffic, with no reload of the hub. Exercises the
    // real chain — Include-derived globs, the poll, the rebuild, the swap.
    #[test]
    fn recompiles_the_waf_when_a_rule_file_changes_on_disk() {
        // Serialises against the WAF-count leak assertions: the handle count
        // is process-global, and this test keeps a live WAF across its sleeps.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = rule_dir("reload");
        std::fs::write(
            dir.join("crs-rules.conf"),
            "SecRule REQUEST_HEADERS:User-Agent \"@streq bad\" \"id:1,phase:1,deny\"\n",
        )
        .expect("seed rule file");

        let directives = format!(
            "SecRuleEngine On\nInclude {}/crs-*.conf\n",
            dir.to_string_lossy()
        );
        let mut context = make_context(&directives);
        context.config.insert(
            RString::from("rule_watch_interval_ms"),
            ConfigValue::Integer(50),
        );

        assert_eq!(
            PluginConfig::from_context(&context).rule_watch_interval(),
            Duration::from_millis(50),
            "the test's poll interval must reach the watcher"
        );
        assert_eq!(
            PluginConfig::from_context(&context).rule_watch_globs(),
            vec![format!("{}/crs-*.conf", dir.to_string_lossy())],
            "the Include must be derived into a watch glob"
        );

        let mut plugin = CorazaPlugin::__new();
        plugin.__init(&context).expect("init");
        assert_eq!(rules_now(&plugin), 1, "seeded rule set must compile");

        std::fs::write(
            dir.join("crs-rules.conf"),
            "SecRule REQUEST_HEADERS:User-Agent \"@streq bad\" \"id:1,phase:1,deny\"\n\
             SecRule REQUEST_HEADERS:User-Agent \"@streq worse\" \"id:2,phase:1,deny\"\n",
        )
        .expect("update rule file");

        assert!(
            wait_for_rules(&plugin, 2),
            "an updated rule file must be recompiled without a hub reload; \
             rule count stayed at {}",
            rules_now(&plugin)
        );
    }

    // A rule set that stops compiling must not disarm the WAF: the previous
    // generation keeps serving until a good one replaces it.
    #[test]
    fn keeps_the_running_rule_set_when_a_reload_fails_to_compile() {
        // Serialises against the WAF-count leak assertions: the handle count
        // is process-global, and this test keeps a live WAF across its sleeps.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = rule_dir("badreload");
        std::fs::write(dir.join("crs-rules.conf"), "SecRuleEngine On\n").expect("seed");

        let directives = format!(
            "SecRuleEngine On\nInclude {}/crs-*.conf\n",
            dir.to_string_lossy()
        );
        let mut context = make_context(&directives);
        context.config.insert(
            RString::from("rule_watch_interval_ms"),
            ConfigValue::Integer(50),
        );

        let mut plugin = CorazaPlugin::__new();
        plugin.__init(&context).expect("init");
        let before = rules_now(&plugin);

        std::fs::write(dir.join("crs-rules.conf"), "This Is Not SecLang At All\n")
            .expect("break the rule file");
        thread::sleep(Duration::from_millis(400));

        assert_eq!(
            rules_now(&plugin),
            before,
            "a rule set that fails to compile must leave the running one in place"
        );
    }

    #[test]
    fn watch_globs_cover_every_application_and_skip_embedded_includes() {
        let dir = "/etc/haproxy/general";
        let context = make_context_with_app(
            &format!("Include @coraza.conf-recommended\nInclude {dir}/crs-*.conf\n"),
            "shop",
            &format!("Include {dir}/shop-*.conf\n"),
        );
        let config = PluginConfig::from_context(&context);

        assert_eq!(
            config.rule_watch_globs(),
            vec![format!("{dir}/crs-*.conf"), format!("{dir}/shop-*.conf"),],
            "every application's on-disk includes must be watched, and only those"
        );
    }

    #[test]
    fn watching_is_off_when_no_include_names_a_file_on_disk() {
        let context = make_context("Include @coraza.conf-recommended\nSecRuleEngine On\n");
        assert!(
            PluginConfig::from_context(&context)
                .rule_watch_globs()
                .is_empty(),
            "an embedded-only rule set has nothing on disk to watch"
        );
    }

    // Documented as the off switch. It must not reach the poll loop, which does
    // not sleep on a zero interval and would spin a core instead.
    #[test]
    fn a_zero_interval_disables_watching() {
        // Serialises against the WAF-count leak assertions: the handle count
        // is process-global, and this test keeps a live WAF across its sleeps.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let dir = rule_dir("disabled");
        std::fs::write(dir.join("crs-rules.conf"), "SecRuleEngine On\n").expect("seed");

        let directives = format!(
            "SecRuleEngine On\nInclude {}/crs-*.conf\n",
            dir.to_string_lossy()
        );
        let mut context = make_context(&directives);
        context.config.insert(
            RString::from("rule_watch_interval_ms"),
            ConfigValue::Integer(0),
        );

        let mut plugin = CorazaPlugin::__new();
        plugin.__init(&context).expect("init");
        let before = rules_now(&plugin);

        std::fs::write(
            dir.join("crs-rules.conf"),
            "SecRule REQUEST_HEADERS:User-Agent \"@streq bad\" \"id:1,phase:1,deny\"\n",
        )
        .expect("update rule file");
        thread::sleep(Duration::from_millis(400));

        assert_eq!(
            rules_now(&plugin),
            before,
            "rule_watch_interval_ms=0 must leave the rule set alone"
        );
    }

    fn rules_now(plugin: &CorazaPlugin) -> i32 {
        let state = plugin
            .state
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let generation = state.generation.as_ref().expect("generation");
        unsafe { ffi::coraza_waf_rules_count(generation.default.0) }
    }

    fn wait_for_rules(plugin: &CorazaPlugin, want: i32) -> bool {
        for _ in 0..40 {
            if rules_now(plugin) == want {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn rule_dir(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("coraza-rule-reload-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir");
        path
    }

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

    fn make_context_with_app(
        default_directives: &str,
        app_name: &str,
        app_directives: &str,
    ) -> PluginContext {
        let mut app = RHashMap::new();
        app.insert(
            RString::from("directives"),
            ConfigValue::String(app_directives.into()),
        );
        let mut applications = RHashMap::new();
        applications.insert(RString::from(app_name), ConfigValue::Table(app));
        let mut config = RHashMap::new();
        config.insert(
            RString::from("directives"),
            ConfigValue::String(default_directives.into()),
        );
        config.insert(
            RString::from("applications"),
            ConfigValue::Table(applications),
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
            SpoeValue::Binary(
                b"Host: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                    .to_vec()
                    .into(),
            ),
        );
        SpoeMessage {
            name: RString::from("check-request"),
            args,
            stream_id: 1,
            frame_id: 1,
        }
    }

    fn make_app_request(path: &str, app: &str) -> SpoeMessage {
        let mut message = make_check_request(path);
        message
            .args
            .insert(RString::from("app"), SpoeValue::String(app.into()));
        message
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
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
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

    #[test]
    fn failed_generation_build_leaves_serving_instance_unchanged_and_leak_free() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let baseline = unsafe { ffi::coraza_waf_active_count() };
        let mut serving = CorazaPlugin::__new();
        serving
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecRule REQUEST_URI \"@streq /live\" \"id:9101,phase:1,deny,status:403\"\n",
            ))
            .expect("serving generation should initialize");

        let mut candidate = CorazaPlugin::__new();
        let failed = candidate.__init(&make_context_with_app(
            "SecRuleEngine On\n",
            "broken",
            "SecBogusDirective invalid\n",
        ));
        assert!(failed.is_err(), "candidate generation must fail atomically");
        assert_eq!(
            unsafe { ffi::coraza_waf_active_count() },
            baseline + 1,
            "the candidate's already-built default WAF must be reclaimed"
        );

        let result = serving
            .__process(&make_check_request("/live"))
            .expect("old instance must keep serving after candidate failure");
        assert!(matches!(
            find_var(&result, "rule_id"),
            SpoeValue::Int32(9101)
        ));

        drop(candidate);
        drop(serving);
        assert_eq!(unsafe { ffi::coraza_waf_active_count() }, baseline);
    }

    #[test]
    fn removed_application_name_is_not_visible_in_new_generation() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut old = CorazaPlugin::__new();
        old.__init(&make_context_with_app(
            "SecRuleEngine On\n",
            "legacy",
            "SecRuleEngine On\n\
             SecRule REQUEST_URI \"@streq /legacy\" \"id:9201,phase:1,deny,status:403\"\n",
        ))
        .expect("old generation should initialize");

        let mut new = CorazaPlugin::__new();
        new.__init(&make_context("SecRuleEngine On\n"))
            .expect("new generation should initialize");

        let old_result = old
            .__process(&make_app_request("/legacy", "legacy"))
            .expect("old generation should retain its own app");
        assert!(matches!(
            find_var(&old_result, "rule_id"),
            SpoeValue::Int32(9201)
        ));

        let error = new
            .__process(&make_app_request("/legacy", "legacy"))
            .expect_err("removed app must fail closed instead of using stale/global state");
        assert!(
            error
                .to_string()
                .contains("unknown Coraza application policy")
        );
    }

    #[test]
    fn repeated_instance_drop_reclaims_every_waf_handle() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let baseline = unsafe { ffi::coraza_waf_active_count() };
        for generation in 0..3 {
            let mut plugin = CorazaPlugin::__new();
            plugin
                .__init(&make_context_with_app(
                    "SecRuleEngine On\n",
                    "app",
                    "SecRuleEngine On\n",
                ))
                .unwrap_or_else(|error| panic!("generation {generation} failed: {error}"));
            assert_eq!(unsafe { ffi::coraza_waf_active_count() }, baseline + 2);
            drop(plugin);
            assert_eq!(
                unsafe { ffi::coraza_waf_active_count() },
                baseline,
                "generation {generation} leaked WAF handles"
            );
        }
    }

    #[test]
    fn buffered_body_requires_explicit_completeness() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut plugin = CorazaPlugin::__new();
        plugin
            .__init(&make_context("SecRuleEngine On\nSecRequestBodyAccess On\n"))
            .expect("plugin should initialize");
        let mut request = make_check_request("/body");
        request.args.insert(
            RString::from("body-mode"),
            SpoeValue::String("buffered".into()),
        );
        request.args.insert(
            RString::from("body"),
            SpoeValue::Binary(b"partial".to_vec().into()),
        );

        let error = plugin
            .__process(&request)
            .expect_err("partial body must fail closed");
        assert!(error.to_string().contains("body is incomplete"));
    }

    #[test]
    fn missing_body_mode_defaults_to_header_only() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut plugin = CorazaPlugin::__new();
        plugin
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecRequestBodyAccess On\n\
                 SecRule ARGS:payload \"@streq malicious\" \"id:9300,phase:2,deny,status:403\"\n",
            ))
            .expect("plugin should initialize");
        let mut request = make_check_request("/opaque");
        request.args.insert(
            RString::from("body"),
            SpoeValue::Binary(b"payload=malicious".to_vec().into()),
        );

        let result = plugin
            .__process(&request)
            .expect("missing body mode should take the safe header-only path");
        assert!(
            matches!(find_var(&result, "action"), SpoeValue::String(action) if action.as_str() == "allow")
        );
    }

    #[test]
    fn detect_only_coerces_statusless_drop_to_allow() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut plugin = CorazaPlugin::__new();
        plugin
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecAction \"id:9302,phase:1,drop\"\n",
            ))
            .expect("plugin should initialize");
        let mut request = make_check_request("/drop");
        request
            .args
            .insert(RString::from("detect-only"), SpoeValue::Bool(true));

        let result = plugin
            .__process(&request)
            .expect("detect-only request should evaluate");
        assert!(
            matches!(find_var(&result, "action"), SpoeValue::String(action) if action.as_str() == "allow")
        );
        assert!(matches!(find_var(&result, "status"), SpoeValue::Int32(0)));
        assert!(matches!(
            find_var(&result, "rule_id"),
            SpoeValue::Int32(9302)
        ));
    }

    #[test]
    fn header_only_mode_never_inspects_supplied_opaque_body() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut plugin = CorazaPlugin::__new();
        plugin
            .__init(&make_context(
                "SecRuleEngine On\n\
                 SecRequestBodyAccess On\n\
                 SecRule ARGS:payload \"@streq malicious\" \"id:9301,phase:2,deny,status:403\"\n",
            ))
            .expect("plugin should initialize");
        let mut request = make_check_request("/opaque");
        request
            .args
            .insert(RString::from("body-mode"), SpoeValue::String("none".into()));
        request.args.insert(
            RString::from("body"),
            SpoeValue::Binary(b"payload=malicious".to_vec().into()),
        );

        let result = plugin
            .__process(&request)
            .expect("header-only request should evaluate");
        assert!(
            matches!(find_var(&result, "action"), SpoeValue::String(action) if action.as_str() == "allow")
        );

        request.args.insert(
            RString::from("body-mode"),
            SpoeValue::String("buffered".into()),
        );
        request
            .args
            .insert(RString::from("body-complete"), SpoeValue::Bool(true));
        let inspected = plugin
            .__process(&request)
            .expect("complete buffered request should evaluate");
        assert!(matches!(find_var(&inspected, "rule_id"), SpoeValue::Int32(id) if *id == 9301));
    }
}
