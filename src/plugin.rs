use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use haproxy_spoa_hub_plugin_api::{
    ConfigValue, MetricRecorder, PluginContext, ProcessingResult, RString, RVec, SpoeMessage,
    SpoeValue, TxnVariable, define_plugin,
};

use crate::backend::{self, Evaluation, Request, Response, TransactionCache, Waf, create_waf};
use crate::config::{PluginConfig, WafKey, effective_directives};
use crate::watcher::{self, Fingerprint, RuleWatcher};

static TX_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// One completely compiled, immutable plugin generation. It is built off to
/// the side and installed only after every application WAF succeeds, so failed
/// hub reloads cannot mutate the generation still serving traffic.
///
/// Applications whose effective configuration is equal share one compiled WAF;
/// each keeps its own name for selection, logs and metrics.
#[derive(Debug)]
struct WafGeneration {
    /// None when `default_waf = false`: requests without an application are
    /// denied rather than inspected by rules nobody configured for them.
    default: Option<Arc<Waf>>,
    applications: HashMap<String, Arc<Waf>>,
}

impl WafGeneration {
    fn build(config: &PluginConfig) -> Result<Self, String> {
        let mut compiled: HashMap<WafKey, (Arc<Waf>, String)> = HashMap::new();
        let mut compile_once = |label: String,
                                key: WafKey,
                                build: &dyn Fn() -> Result<Waf, String>|
         -> Result<Arc<Waf>, String> {
            if let Some((handle, owner)) = compiled.get(&key) {
                log::info!("Coraza {label} shares the compiled rule set of {owner}");
                return Ok(Arc::clone(handle));
            }
            let handle = Arc::new(build()?);
            let rules_count = handle.rule_count();
            log::info!("Coraza {label} initialized with {rules_count} rules");
            compiled.insert(key, (Arc::clone(&handle), label));
            Ok(handle)
        };

        let default = if config.default_waf {
            Some(compile_once(
                "default WAF".into(),
                config.default_waf_key(),
                &|| {
                    create_waf(
                        &config.directives,
                        config.directives_file.as_deref(),
                        config.request_body_limit,
                        config.request_body_in_memory_limit,
                        config.response_body_limit,
                        config,
                    )
                },
            )?)
        } else {
            log::info!("Coraza default WAF disabled; requests without an application are denied");
            None
        };

        let mut applications = HashMap::with_capacity(config.applications.len());
        for app in &config.applications {
            let handle = compile_once(format!("WAF app '{}'", app.name), app.waf_key(), &|| {
                create_waf(
                    &app.directives,
                    app.directives_file.as_deref(),
                    app.request_body_limit,
                    app.request_body_in_memory_limit,
                    app.response_body_limit,
                    config,
                )
                .map_err(|error| format!("application '{}': {error}", app.name))
            })?;
            applications.insert(app.name.clone(), handle);
        }
        log::info!(
            "Coraza compiled {} distinct rule set(s) for {} application(s)",
            compiled.len(),
            config.applications.len()
        );

        Ok(Self {
            default,
            applications,
        })
    }

    /// `Ok(None)` is a request without an application while the default WAF
    /// is disabled.
    fn select<'a>(&self, application: Option<&'a str>) -> Result<Option<(&Waf, &'a str)>, String> {
        match application.filter(|name| !name.is_empty()) {
            None => Ok(self.default.as_ref().map(|handle| (handle.as_ref(), ""))),
            Some(name) => self
                .applications
                .get(name)
                .map(|handle| Some((handle.as_ref(), name)))
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
    cache: TransactionCache,
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
            cache: TransactionCache::default(),
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
                match generation.select(message.get_string("app"))? {
                    Some((handle, selected_app)) => {
                        process_request(message, &state.config, handle, selected_app, &self.cache)
                    }
                    None => Ok(deny_without_application()),
                }
            }
            "check-response" => process_response(message, &state.config, &self.cache),
            _ => Ok(ProcessingResult::empty()),
        }
    }

    fn config_schema(&self) -> Option<&str> {
        Some(PluginConfig::config_schema())
    }

    fn validate(&self, context: &PluginContext) -> Vec<Diagnostic> {
        #[cfg(feature = "go-backend")]
        if is_validation_only(context) {
            backend::configure_validation_memory();
        }
        let config = PluginConfig::from_context(context);
        let staged = staged_files_json(context);
        // Only a clean result is reused: diagnostics carry line numbers, which
        // differ between blocks with equal effective directives.
        let mut clean = std::collections::HashSet::new();
        let mut validate_once = |directives: &str| {
            let effective = effective_directives(directives);
            if clean.contains(&effective) {
                return Vec::new();
            }
            let diagnostics = backend::validate_directives(directives, &staged);
            if diagnostics.is_empty() {
                clean.insert(effective);
            }
            diagnostics
        };
        // Validates exactly the rule sets init compiles.
        let mut diagnostics = if config.default_waf {
            validate_once(&config.directives)
        } else {
            Vec::new()
        };
        for app in &config.applications {
            for mut d in validate_once(&app.directives) {
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

// Set only by the dedicated validator; runtime load/reload validation must not retune Go.
#[cfg(any(test, feature = "go-backend"))]
fn is_validation_only(context: &PluginContext) -> bool {
    matches!(
        context.config.get(&RString::from("__validation_only")),
        Some(ConfigValue::Bool(true))
    )
}

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

impl Drop for CorazaPlugin {
    fn drop(&mut self) {
        let (allowed, blocked, rules_hit, errors) = self.cache.summary();
        log::info!(
            "Coraza plugin shutting down: allowed={allowed}, blocked={blocked}, \
             rules_hit={rules_hit}, errors={errors}"
        );
    }
}

fn process_request(
    message: &SpoeMessage,
    config: &PluginConfig,
    waf: &Waf,
    selected_app: &str,
    cache: &TransactionCache,
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

    // Per-message detect-only override. When set on a request-side message,
    // the WAF still evaluates rules normally but coerces the verdict to
    // `action=allow` while keeping `rule_id`, `anomaly_score`, etc.
    // populated. Mirrors the response-side override and falls back to the
    // hub-global `config.detect_only` for absent or malformed values.
    // See specs/002-detect-only-request/.
    let detect_only = message
        .get_bool("detect-only")
        .unwrap_or(config.detect_only);
    let start = std::time::Instant::now();
    let result = backend::evaluate_request(
        waf,
        cache,
        Request {
            tx_id: &tx_id,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            method,
            path,
            query,
            version,
            headers: &headers_buf,
            body: &body_buf,
        },
        config,
        detect_only,
    )?;
    let elapsed = start.elapsed();
    let latency_us = elapsed.as_micros();

    log::debug!(
        "coraza request: action={} rule_id={} latency_us={latency_us}",
        result.action_str(),
        result.rule_id,
    );

    let hits = emit_eval_metrics("request", &result, selected_app, elapsed);

    let variables = result_to_variables(&result, &tx_id, false, config.expose_matched_data, hits);

    Ok(ProcessingResult { variables })
}

/// A verdict, not an error: the host lets a request past on a plugin error
/// unless it is configured to fail closed. 503 is the engine-error status.
fn deny_without_application() -> ProcessingResult {
    METRICS.counter(
        "evaluations_total",
        &[("phase", "request"), ("action", "deny"), ("app", "")],
        1,
    );
    METRICS.counter(
        "denials_total",
        &[("phase", "request"), ("rule_id", "0"), ("app", "")],
        1,
    );
    let mut variables = RVec::with_capacity(5);
    for (name, value) in [
        ("action", SpoeValue::String(RString::from("deny"))),
        ("status", SpoeValue::Int32(503)),
        ("rule_id", SpoeValue::Int32(0)),
        ("anomaly_score", SpoeValue::Int32(0)),
        ("rules_hit", SpoeValue::Int32(0)),
    ] {
        variables.push(TxnVariable::transaction(name, value));
    }
    ProcessingResult { variables }
}

/// Emit Prometheus metrics for one WAF evaluation. Called from both
/// `process_request` and `process_response`; centralises the label
/// shape so the two paths can't drift. Hub prefixes everything with
/// `plugin_coraza_`.
fn emit_eval_metrics(
    phase: &str,
    result: &Evaluation,
    app: &str,
    elapsed: Duration,
) -> Vec<RuleHit> {
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
    let hits = decode_rule_hits(result.matched_rules_str(), app);
    for hit in &hits {
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
    hits
}

#[derive(serde::Deserialize)]
struct RuleHit {
    i: i64,
    s: i64,
}

fn decode_rule_hits(raw: &str, app: &str) -> Vec<RuleHit> {
    if raw.is_empty() {
        return Vec::new();
    }
    serde_json::from_str(raw).unwrap_or_else(|err| {
        log::debug!("unparseable matched_rules payload ({err}): {raw}");
        METRICS.counter("rule_hits_decode_errors_total", &[("app", app)], 1);
        Vec::new()
    })
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

/// Most rule IDs `rule_ids` names on one request.
const MAX_RULE_IDS: usize = 10;

/// The IDs of the matched rules that carry a severity (emergency to notice:
/// the rules that make up the anomaly score), most severe first, then by ID,
/// each once and at most `MAX_RULE_IDS`, comma-separated. In CRS's anomaly
/// mode `rule_id` is the scoring rule (949110) for every would-block request;
/// these are the rules behind it. Setup and reporting rules (no severity) are
/// left out. Empty when no such rule matched or the payload does not decode.
fn scoring_rule_ids(mut hits: Vec<RuleHit>) -> String {
    hits.retain(|h| (0..=5).contains(&h.s) && h.i > 0);
    hits.sort_by_key(|h| (h.s, h.i));
    hits.dedup_by_key(|h| h.i);
    hits.iter()
        .take(MAX_RULE_IDS)
        .map(|h| h.i.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn process_response(
    message: &SpoeMessage,
    config: &PluginConfig,
    cache: &TransactionCache,
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

    let start = std::time::Instant::now();
    let result = backend::evaluate_response(
        cache,
        Response {
            tx_id,
            status: status_code,
            version,
            headers: &headers_buf,
            body: &body_buf,
        },
        detect_only,
    )?;
    let elapsed = start.elapsed();

    // No `app` label on the response path — the upstream coraza FFI
    // looks up the app context by tx_id, not by an arg. Pass empty
    // string for consistent labelset shape across phase=request and
    // phase=response.
    let hits = emit_eval_metrics("response", &result, "", elapsed);

    let variables = result_to_variables(&result, tx_id, true, false, hits);

    Ok(ProcessingResult { variables })
}

/// Convert a CorazaResult into SPOE transaction variables.
fn result_to_variables(
    result: &Evaluation,
    tx_id: &str,
    is_response: bool,
    expose_matched_data: bool,
    hits: Vec<RuleHit>,
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
            SpoeValue::Int32(i32::try_from(hits.len()).unwrap_or(i32::MAX)),
        ));

        // The scoring rules behind the verdict, e.g. "930130,920420": rule
        // IDs only, so like `matched_var` it carries no request content.
        let rule_ids = scoring_rule_ids(hits);
        if !rule_ids.is_empty() {
            vars.push(TxnVariable::transaction(
                "rule_ids",
                SpoeValue::String(RString::from(rule_ids)),
            ));
        }

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
mod rule_ids_tests {
    use super::*;

    fn scoring_ids(raw: &str) -> String {
        scoring_rule_ids(decode_rule_hits(raw, ""))
    }

    #[test]
    fn names_the_scoring_rules_most_severe_first() {
        // 901100 (setup, no severity) and 949110 (scoring, no severity in CRS 4) stay out
        let raw = r#"[{"i":901100,"s":-1},{"i":920420,"s":2},{"i":930130,"s":2},{"i":920350,"s":4},{"i":949110,"s":-1}]"#;
        assert_eq!(scoring_ids(raw), "920420,930130,920350");
    }

    #[test]
    fn names_each_rule_once_and_at_most_ten() {
        let mut hits: Vec<String> = (0..15)
            .map(|n| format!(r#"{{"i":{},"s":2}}"#, 942100 + n))
            .collect();
        hits.push(r#"{"i":942100,"s":2}"#.to_string());
        let ids = scoring_ids(&format!("[{}]", hits.join(",")));
        assert_eq!(ids.split(',').count(), MAX_RULE_IDS);
        assert!(ids.starts_with("942100,942101,"));
    }

    #[test]
    fn is_empty_without_a_scoring_rule_or_with_a_damaged_payload() {
        assert_eq!(scoring_ids(""), "");
        assert_eq!(scoring_ids(r#"[{"i":901100,"s":-1}]"#), "");
        assert_eq!(scoring_ids("not json"), "");
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
    fn memory_budget_requires_dedicated_validation_context() {
        assert!(!is_validation_only(&ctx_with(vec![])));
        for value in [ConfigValue::Bool(false), ConfigValue::String("true".into())] {
            assert!(!is_validation_only(&ctx_with(vec![(
                "__validation_only",
                value
            )])));
        }
        assert!(is_validation_only(&ctx_with(vec![(
            "__validation_only",
            ConfigValue::Bool(true)
        )])));
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

    #[test]
    fn haptic_custom_policy_admission_matches_runtime_grammar() {
        let plugin = CorazaPlugin::__new();
        for (directives, accepted) in [
            ("SecComponentSignature catalog", true),
            ("SecComponentSignature", false),
            (r#"SecDefaultAction "phase:1,pass,t:lowercase""#, true),
            (
                r#"SecDefaultAction "phase:1,pass,t:lowercase"
SecRule REQUEST_METHOD "@streq GET" "id:10701,phase:1,pass""#,
                false,
            ),
            (
                r#"SecRule TIME_YEAR "@rx ^[0-9]{4}$" "id:10701,phase:1,pass""#,
                true,
            ),
            ("SecAuditEngine Off", true),
            ("SecRxPreFilter invalid", false),
        ] {
            let context = ctx_with(vec![("directives", ConfigValue::String(directives.into()))]);
            let diagnostics = plugin.__validate(&context);
            assert_eq!(
                diagnostics
                    .iter()
                    .all(|d| d.severity != DiagnosticSeverity::Error),
                accepted,
                "{directives}: {diagnostics:?}"
            );
        }
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

    #[test]
    fn equal_effective_directives_still_report_each_applications_errors() {
        let plugin = CorazaPlugin::__new();
        let mut applications = RHashMap::new();
        for (name, directives) in [
            ("alpha", "# policy:alpha\nSecBogusShared foo\n"),
            ("bravo", "# policy:bravo\n\nSecBogusShared foo\n"),
            ("clean", "# policy:clean\nSecRuleEngine On\n"),
            ("clean-copy", "# policy:clean-copy\nSecRuleEngine On\n"),
        ] {
            let mut app = RHashMap::new();
            app.insert(
                RString::from("directives"),
                ConfigValue::String(directives.into()),
            );
            applications.insert(RString::from(name), ConfigValue::Table(app));
        }
        let ctx = ctx_with(vec![("applications", ConfigValue::Table(applications))]);

        let messages: Vec<String> = plugin
            .__validate(&ctx)
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .map(|d| d.message.as_str().to_string())
            .collect();
        for name in ["alpha", "bravo"] {
            assert!(
                messages
                    .iter()
                    .any(|m| m.contains(&format!("application '{name}':"))),
                "{name} must be reported, got {messages:?}"
            );
        }
        assert!(
            !messages.iter().any(|m| m.contains("clean")),
            "clean applications must not be reported, got {messages:?}"
        );
    }

    #[test]
    fn disabled_default_waf_directives_are_not_validated() {
        let plugin = CorazaPlugin::__new();
        let mut app = RHashMap::new();
        app.insert(
            RString::from("directives"),
            ConfigValue::String("SecBogusApp foo\n".into()),
        );
        let mut applications = RHashMap::new();
        applications.insert(RString::from("app"), ConfigValue::Table(app));
        let ctx = ctx_with(vec![
            (
                "directives",
                ConfigValue::String("SecBogusDefault foo\n".into()),
            ),
            ("default_waf", ConfigValue::Bool(false)),
            ("applications", ConfigValue::Table(applications)),
        ]);

        let messages: Vec<String> = plugin
            .__validate(&ctx)
            .iter()
            .map(|d| d.message.as_str().to_string())
            .collect();
        assert!(!messages.is_empty(), "applications are still validated");
        assert!(
            messages.iter().all(|m| m.starts_with("application 'app':")),
            "the default directives never compile, got {messages:?}"
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

    #[cfg(feature = "go-backend")]
    #[test]
    fn malformed_validator_json_fails_closed() {
        let diags = backend::parse_validation_json("not-json");
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

// Serializes tests that observe the number of live WAF generations.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

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
    fn disabled_default_waf_files_are_not_watched() {
        let dir = "/etc/haproxy/general";
        let mut context = make_context_with_app(
            &format!("Include {dir}/crs-*.conf\n"),
            "shop",
            &format!("Include {dir}/shop-*.conf\n"),
        );
        context
            .config
            .insert(RString::from("default_waf"), ConfigValue::Bool(false));
        context.config.insert(
            RString::from("directives_file"),
            ConfigValue::String(format!("{dir}/default.conf").into()),
        );
        // An application inherits the default directives_file unless it names its own.
        if let Some(ConfigValue::Table(apps)) = context.config.get_mut("applications") {
            if let Some(ConfigValue::Table(shop)) = apps.get_mut("shop") {
                shop.insert(
                    RString::from("directives_file"),
                    ConfigValue::String(format!("{dir}/shop.conf").into()),
                );
            }
        }

        assert_eq!(
            PluginConfig::from_context(&context).rule_watch_globs(),
            vec![format!("{dir}/shop-*.conf"), format!("{dir}/shop.conf")],
            "a default WAF that is never compiled must not trigger rebuilds"
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
        generation
            .default
            .as_ref()
            .expect("default WAF")
            .rule_count()
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

    fn make_context_with_apps(
        default_directives: &str,
        apps: &[(&str, &str, Option<i64>)],
    ) -> PluginContext {
        let mut applications = RHashMap::new();
        for (name, directives, request_body_limit) in apps {
            let mut app = RHashMap::new();
            app.insert(
                RString::from("directives"),
                ConfigValue::String((*directives).into()),
            );
            if let Some(limit) = request_body_limit {
                app.insert(
                    RString::from("request_body_limit"),
                    ConfigValue::Integer(*limit),
                );
            }
            applications.insert(RString::from(*name), ConfigValue::Table(app));
        }
        let mut context = make_context(default_directives);
        context.config.insert(
            RString::from("applications"),
            ConfigValue::Table(applications),
        );
        context
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

    #[test]
    fn rule_hit_metrics_keep_detections_and_optionally_count_crs_controls() {
        use haproxy_spoa_hub_plugin_api::{MetricKind, MetricLabel, RSlice, RStr};

        const APP: &str = "test-rule-hit-metrics";
        static HITS: Mutex<Vec<String>> = Mutex::new(Vec::new());
        extern "C" fn collect(
            _: *const std::ffi::c_void,
            name: RStr<'_>,
            labels: RSlice<'_, MetricLabel<'_>>,
            _: f64,
            _: MetricKind,
        ) {
            let label = |key| {
                labels
                    .iter()
                    .find(|(k, _)| k.as_str() == key)
                    .map(|(_, v)| v.as_str())
            };
            if name.as_str() == "rule_hits_total" && label("app") == Some(APP) {
                if let Some(id) = label("rule_id") {
                    HITS.lock().unwrap().push(id.to_owned());
                }
            }
        }

        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        METRICS.install(collect, std::ptr::null());
        let directives = r#"SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,tag:OWASP_CRS"
SecRule REQUEST_URI "@streq /test" "id:2,phase:1,pass,nolog,severity:INFO,tag:OWASP_CRS"
SecRule REQUEST_URI "@streq /test" "id:3,phase:1,pass,nolog"
SecRule REQUEST_URI "@streq /test" "id:4,phase:1,deny,status:403,tag:OWASP_CRS"
"#;
        for include_controls in [false, true] {
            let mut context = make_context_with_app("SecRuleEngine On", APP, directives);
            if include_controls {
                context.config.insert(
                    "include_crs_control_rule_hits".into(),
                    ConfigValue::Bool(true),
                );
            }
            let mut plugin = CorazaPlugin::__new();
            plugin.__init(&context).unwrap();
            let clean_hits: &[&str] = if include_controls { &["1"] } else { &[] };
            let detection_hits: &[&str] = if include_controls {
                &["1", "2", "3", "4"]
            } else {
                &["2", "3", "4"]
            };
            for (uri, rule_id, expected) in
                [("/clean", 0, clean_hits), ("/test", 4, detection_hits)]
            {
                let mut request = make_app_request(uri, APP);
                request
                    .args
                    .insert("detect-only".into(), SpoeValue::Bool(true));
                let verdict = plugin.__process(&request).unwrap();
                assert!(
                    matches!(find_var(&verdict, "rule_id"), SpoeValue::Int32(id) if *id == rule_id)
                );
                assert!(
                    matches!(find_var(&verdict, "rules_hit"), SpoeValue::Int32(n) if *n == expected.len() as i32)
                );
                assert_eq!(std::mem::take(&mut *HITS.lock().unwrap()), expected);
            }
        }
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
    fn pending_response_keeps_its_request_policy_across_a_plugin_reload() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut old_config = make_context(
            r#"SecRuleEngine On
SecRule RESPONSE_STATUS "@streq 201" "id:9201,phase:3,deny,status:418""#,
        );
        old_config
            .config
            .insert("response_check".into(), ConfigValue::Bool(true));
        let mut original = CorazaPlugin::__new();
        original.__init(&old_config).unwrap();
        let result = original.__process(&make_check_request("/created")).unwrap();
        let id = find_var(&result, "id").clone();

        let mut replacement = CorazaPlugin::__new();
        replacement
            .__init(&make_context("SecRuleEngine On"))
            .unwrap();
        drop(original);
        let mut response = SpoeMessage {
            name: "check-response".into(),
            args: RHashMap::new(),
            stream_id: 1,
            frame_id: 2,
        };
        response.args.insert("id".into(), id);
        response.args.insert("status".into(), SpoeValue::Int32(201));
        response
            .args
            .insert("version".into(), SpoeValue::String("HTTP/1.1".into()));
        let first = replacement.__process(&response).unwrap();
        assert!(matches!(
            find_var(&first, "resp_status"),
            SpoeValue::Int32(418)
        ));
        assert!(matches!(
            find_var(&first, "resp_rule_id"),
            SpoeValue::Int32(9201)
        ));

        let replay = replacement.__process(&response).unwrap();
        assert!(matches!(
            find_var(&replay, "resp_status"),
            SpoeValue::Int32(503)
        ));
    }

    #[test]
    fn failed_generation_build_leaves_serving_instance_unchanged_and_leak_free() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let baseline = backend::active_count();
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
            backend::active_count(),
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
        assert_eq!(backend::active_count(), baseline);
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
        let baseline = backend::active_count();
        for generation in 0..3 {
            let mut plugin = CorazaPlugin::__new();
            plugin
                .__init(&make_context_with_app(
                    "SecRuleEngine On\n",
                    "app",
                    "SecRuleEngine DetectionOnly\n",
                ))
                .unwrap_or_else(|error| panic!("generation {generation} failed: {error}"));
            assert_eq!(backend::active_count(), baseline + 2);
            drop(plugin);
            assert_eq!(
                backend::active_count(),
                baseline,
                "generation {generation} leaked WAF handles"
            );
        }
    }

    #[test]
    fn applications_with_equal_effective_configuration_share_one_waf() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let baseline = backend::active_count();
        let base = "SecRuleEngine On\n\
                    SecRule REQUEST_URI \"@streq /a\" \"id:9301,phase:1,deny,status:403\"\n\
                    SecRule REQUEST_URI \"@streq /b\" \"id:9302,phase:1,deny,status:403\"\n";
        let excluded = format!("{base}SecRuleRemoveById 9301\n");
        let context = make_context_with_apps(
            base,
            &[
                ("same-as-default", &format!("{base}\n# policy:same\n"), None),
                ("excluded", &format!("{excluded}# policy:excluded\n"), None),
                (
                    "excluded-copy",
                    &format!("  {excluded}\n# policy:copy\n"),
                    None,
                ),
                ("larger-body", &excluded, Some(65_536)),
            ],
        );
        let mut plugin = CorazaPlugin::__new();
        plugin.__init(&context).expect("init");
        assert_eq!(
            backend::active_count(),
            baseline + 3,
            "default+same-as-default, excluded+excluded-copy and larger-body compile once each"
        );

        let rule = |path: &str, app: &str| {
            let result = plugin
                .__process(&make_app_request(path, app))
                .unwrap_or_else(|error| panic!("{app} {path}: {error}"));
            match find_var(&result, "rule_id") {
                SpoeValue::Int32(id) => *id,
                other => panic!("rule_id should be Int32, got {other:?}"),
            }
        };
        assert_eq!(rule("/a", ""), 9301);
        assert_eq!(rule("/a", "same-as-default"), 9301);
        for app in ["excluded", "excluded-copy", "larger-body"] {
            assert_eq!(rule("/a", app), 0, "{app} removed rule 9301");
            assert_eq!(rule("/b", app), 9302, "{app} keeps rule 9302");
        }

        drop(plugin);
        assert_eq!(backend::active_count(), baseline);
    }

    #[test]
    fn disabled_default_waf_is_not_compiled_and_denies_requests_without_an_application() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let baseline = backend::active_count();
        let rules = "SecRuleEngine On\n\
                     SecRule REQUEST_URI \"@streq /a\" \"id:9401,phase:1,deny,status:403\"\n";
        for apps in [vec![("app", rules, None)], vec![]] {
            let mut context = make_context_with_apps(rules, &apps);
            context
                .config
                .insert(RString::from("default_waf"), ConfigValue::Bool(false));
            let mut plugin = CorazaPlugin::__new();
            plugin.__init(&context).expect("init");
            assert_eq!(
                backend::active_count(),
                baseline + apps.len() as i32,
                "only applications compile"
            );

            for request in [make_check_request("/b"), make_app_request("/b", "")] {
                let result = plugin
                    .__process(&request)
                    .expect("a request without an application gets a verdict, not an error");
                assert!(
                    matches!(find_var(&result, "action"), SpoeValue::String(a) if a.as_str() == "deny")
                );
                assert!(matches!(find_var(&result, "status"), SpoeValue::Int32(503)));
            }
            if !apps.is_empty() {
                let result = plugin
                    .__process(&make_app_request("/a", "app"))
                    .expect("app");
                assert!(matches!(
                    find_var(&result, "rule_id"),
                    SpoeValue::Int32(9401)
                ));
            }

            drop(plugin);
            assert_eq!(backend::active_count(), baseline);
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
