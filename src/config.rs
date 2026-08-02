use std::time::Duration;

use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext, RHashMap, RString, Tuple2};

const MAX_BODY_LIMIT: i64 = 1_073_741_824;
const MAX_MATCHED_DATA_BYTES: i64 = 4096;
const MAX_TRANSACTION_TTL_MS: i64 = 86_400_000;
const MAX_CACHED_TRANSACTIONS: i64 = 1_000_000;
const MAX_RULE_WATCH_INTERVAL_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedDataLog {
    None,
    Hash,
    Truncate,
}

impl MatchedDataLog {
    #[must_use]
    pub const fn ffi_value(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Hash => 1,
            Self::Truncate => 2,
        }
    }

    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("hash") => Self::Hash,
            Some("truncate") => Self::Truncate,
            _ => Self::None,
        }
    }
}

/// WAF directives and body limit fields shared between the top-level
/// plugin config and per-application configs.
#[derive(Debug, Clone)]
struct WafFields {
    directives: String,
    directives_file: Option<String>,
    request_body_limit: i32,
    request_body_in_memory_limit: i32,
    response_body_limit: i32,
}

/// Per-application WAF configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub name: String,
    pub directives: String,
    pub directives_file: Option<String>,
    pub request_body_limit: i32,
    pub request_body_in_memory_limit: i32,
    pub response_body_limit: i32,
}

/// Plugin configuration parsed from hub's `[plugins.params]` TOML table.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    pub directives: String,
    pub directives_file: Option<String>,
    pub request_body_limit: i32,
    pub request_body_in_memory_limit: i32,
    pub response_body_limit: i32,
    pub response_check: bool,
    pub detect_only: bool,
    pub transaction_ttl_ms: i32,
    pub max_cached_transactions: i32,
    pub rule_match_log: bool,
    pub matched_data_log: MatchedDataLog,
    pub matched_data_max_bytes: i32,
    pub expose_matched_data: bool,
    pub rule_watch_interval_ms: i32,
    pub applications: Vec<AppConfig>,
}

/// Marks an `Include` target that lives in the binary rather than on disk
/// (`@coraza.conf-recommended`, `@owasp_crs/*.conf`). Those cannot change
/// without a new image, so watching them would be pure cost.
const EMBEDDED_INCLUDE_PREFIX: char = '@';

impl PluginConfig {
    pub fn rule_watch_interval(&self) -> Duration {
        Duration::from_millis(self.rule_watch_interval_ms.max(0) as u64)
    }

    /// The on-disk paths the compiled rule set was built from.
    ///
    /// Derived from the directives rather than configured separately, so the
    /// watch set is by construction the set of files that were compiled —
    /// including every application's own directives, and including a glob
    /// whose matches change as rule files come and go.
    pub fn rule_watch_globs(&self) -> Vec<String> {
        let mut globs: Vec<String> = Vec::new();
        let blocks = std::iter::once(&self.directives)
            .chain(self.applications.iter().map(|app| &app.directives));
        for block in blocks {
            collect_include_paths(block, &mut globs);
        }
        globs.extend(
            std::iter::once(&self.directives_file)
                .chain(self.applications.iter().map(|app| &app.directives_file))
                .flatten()
                .cloned(),
        );
        globs.sort();
        globs.dedup();
        globs
    }
}

/// Pull the on-disk targets out of a SecLang block's `Include` directives.
fn collect_include_paths(directives: &str, out: &mut Vec<String>) {
    for line in directives.lines() {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("Include ")
            .or_else(|| line.strip_prefix("include "))
        else {
            continue;
        };
        let target = rest.trim().trim_matches('"');
        if target.is_empty() || target.starts_with(EMBEDDED_INCLUDE_PREFIX) {
            continue;
        }
        out.push(target.to_string());
    }
}

const DEFAULT_DIRECTIVES: &str = concat!(
    "Include @coraza.conf-recommended\n",
    "SecRxPreFilter On\n",
    "Include @crs-setup.conf.example\n",
    "Include @owasp_crs/*.conf\n",
    // coraza.conf-recommended selects DetectionOnly. Keep the enforcement
    // override last so the standalone default actually blocks.
    "SecRuleEngine On\n",
);

impl Default for PluginConfig {
    fn default() -> Self {
        PluginConfig {
            directives: DEFAULT_DIRECTIVES.to_string(),
            directives_file: None,
            request_body_limit: 4096,
            request_body_in_memory_limit: 4096,
            response_body_limit: 4096,
            response_check: false,
            detect_only: false,
            transaction_ttl_ms: 10000,
            max_cached_transactions: 1024,
            rule_match_log: false,
            matched_data_log: MatchedDataLog::None,
            matched_data_max_bytes: 128,
            expose_matched_data: false,
            rule_watch_interval_ms: 15000,
            applications: Vec::new(),
        }
    }
}

fn bounded_i32(value: Option<i64>, default: i32, maximum: i64) -> i32 {
    value
        .filter(|value| (0..=maximum).contains(value))
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(default)
}

/// Extract WAF directives and body limit fields from a config table,
/// falling back to defaults for missing keys.
fn parse_waf_fields(table: &RHashMap<RString, ConfigValue>, defaults: &WafFields) -> WafFields {
    let directives = table
        .get("directives")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| defaults.directives.clone());

    let directives_file = table
        .get("directives_file")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| defaults.directives_file.clone());

    let request_body_limit = bounded_i32(
        table.get("request_body_limit").and_then(|v| v.as_integer()),
        defaults.request_body_limit,
        MAX_BODY_LIMIT,
    );

    let request_body_in_memory_limit = bounded_i32(
        table
            .get("request_body_in_memory_limit")
            .and_then(|v| v.as_integer()),
        defaults.request_body_in_memory_limit,
        MAX_BODY_LIMIT,
    );

    let response_body_limit = bounded_i32(
        table
            .get("response_body_limit")
            .and_then(|v| v.as_integer()),
        defaults.response_body_limit,
        MAX_BODY_LIMIT,
    );

    WafFields {
        directives,
        directives_file,
        request_body_limit,
        request_body_in_memory_limit,
        response_body_limit,
    }
}

impl PluginConfig {
    pub fn from_context(context: &PluginContext) -> Self {
        let defaults = Self::default();
        let default_waf = WafFields {
            directives: defaults.directives.clone(),
            directives_file: defaults.directives_file.clone(),
            request_body_limit: defaults.request_body_limit,
            request_body_in_memory_limit: defaults.request_body_in_memory_limit,
            response_body_limit: defaults.response_body_limit,
        };
        let waf = parse_waf_fields(&context.config, &default_waf);

        let response_check = context
            .get_config("response_check")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.response_check);

        let detect_only = context
            .get_config("detect_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.detect_only);

        let transaction_ttl_ms = bounded_i32(
            context
                .get_config("transaction_ttl_ms")
                .and_then(|v| v.as_integer()),
            defaults.transaction_ttl_ms,
            MAX_TRANSACTION_TTL_MS,
        )
        .max(1);

        let max_cached_transactions = bounded_i32(
            context
                .get_config("max_cached_transactions")
                .and_then(|v| v.as_integer()),
            defaults.max_cached_transactions,
            MAX_CACHED_TRANSACTIONS,
        )
        .max(1);

        let rule_watch_interval_ms = bounded_i32(
            context
                .get_config("rule_watch_interval_ms")
                .and_then(|v| v.as_integer()),
            defaults.rule_watch_interval_ms,
            MAX_RULE_WATCH_INTERVAL_MS,
        );

        let rule_match_log = context
            .get_config("rule_match_log")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.rule_match_log);

        let matched_data_log = MatchedDataLog::parse(
            context
                .get_config("matched_data_log")
                .and_then(|v| v.as_str()),
        );

        let matched_data_max_bytes = bounded_i32(
            context
                .get_config("matched_data_max_bytes")
                .and_then(|v| v.as_integer()),
            defaults.matched_data_max_bytes,
            MAX_MATCHED_DATA_BYTES,
        );

        let expose_matched_data = context
            .get_config("expose_matched_data")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.expose_matched_data);

        let applications = context
            .get_config("applications")
            .and_then(|v| v.as_table())
            .map(|table| {
                table
                    .iter()
                    .filter_map(|Tuple2(name, val)| {
                        let app_table = val.as_table()?;
                        // Application settings inherit the effective top-level
                        // policy. Previously omitted body limits silently fell
                        // back to the 4 KiB factory defaults, even when the
                        // operator configured a larger top-level bound.
                        let app_waf = parse_waf_fields(app_table, &waf);
                        Some(AppConfig {
                            name: name.to_string(),
                            directives: app_waf.directives,
                            directives_file: app_waf.directives_file,
                            request_body_limit: app_waf.request_body_limit,
                            request_body_in_memory_limit: app_waf.request_body_in_memory_limit,
                            response_body_limit: app_waf.response_body_limit,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        PluginConfig {
            directives: waf.directives,
            directives_file: waf.directives_file,
            request_body_limit: waf.request_body_limit,
            request_body_in_memory_limit: waf.request_body_in_memory_limit,
            response_body_limit: waf.response_body_limit,
            response_check,
            detect_only,
            transaction_ttl_ms,
            max_cached_transactions,
            rule_match_log,
            matched_data_log,
            matched_data_max_bytes,
            expose_matched_data,
            rule_watch_interval_ms,
            applications,
        }
    }

    pub fn config_schema() -> &'static str {
        r#"{
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "directives": {
                    "type": "string",
                    "maxLength": 4194304,
                    "description": "SecLang WAF directives. Default loads embedded OWASP CRS v4."
                },
                "directives_file": {
                    "type": "string",
                    "maxLength": 4096,
                    "description": "Path to additional directives file loaded after inline directives."
                },
                "request_body_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1073741824,
                    "default": 4096,
                    "description": "Maximum request body bytes to buffer."
                },
                "request_body_in_memory_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1073741824,
                    "default": 4096,
                    "description": "Maximum request body bytes kept in memory."
                },
                "response_body_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1073741824,
                    "default": 4096,
                    "description": "Maximum response body bytes to buffer."
                },
                "response_check": {
                    "type": "boolean",
                    "default": false,
                    "description": "Enable response-phase WAF inspection."
                },
                "detect_only": {
                    "type": "boolean",
                    "default": false,
                    "description": "Default log-only mode for request and response inspection. May be overridden per SPOE message."
                },
                "rule_watch_interval_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 3600000,
                    "default": 15000,
                    "description": "How often to check the rule files named by Include directives for changes, recompiling the WAF in place when they change. 0 disables watching."
                },
                "transaction_ttl_ms": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86400000,
                    "default": 10000,
                    "description": "TTL in milliseconds for cached transactions (response correlation)."
                },
                "max_cached_transactions": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000000,
                    "default": 1024,
                    "description": "Hard cap on request transactions retained for response inspection. New requests fail closed when the cache is full."
                },
                "rule_match_log": {
                    "type": "boolean",
                    "default": false,
                    "description": "Emit one structured warning for each matched rule. Disabled by default to prevent payload leakage and log-amplification attacks."
                },
                "matched_data_log": {
                    "type": "string",
                    "enum": ["none", "hash", "truncate"],
                    "default": "none",
                    "description": "How matched payload data is represented when rule_match_log is enabled."
                },
                "matched_data_max_bytes": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 4096,
                    "default": 128,
                    "description": "Maximum sanitized matched-data bytes logged in truncate mode or exposed as a transaction variable."
                },
                "expose_matched_data": {
                    "type": "boolean",
                    "default": false,
                    "description": "Expose bounded Coraza interruption data to HAProxy as the data variable. Disabled by default because it can contain request payloads."
                },
                "applications": {
                    "type": "object",
                    "description": "Per-application WAF configurations. Each key is an app name with its own directives and body limits.",
                    "maxProperties": 4096,
                    "propertyNames": { "minLength": 1, "maxLength": 512 },
                    "additionalProperties": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "directives": { "type": "string", "maxLength": 4194304 },
                            "directives_file": { "type": "string", "maxLength": 4096 },
                            "request_body_limit": { "type": "integer", "minimum": 0, "maximum": 1073741824 },
                            "request_body_in_memory_limit": { "type": "integer", "minimum": 0, "maximum": 1073741824 },
                            "response_body_limit": { "type": "integer", "minimum": 0, "maximum": 1073741824 }
                        }
                    }
                }
            }
        }"#
    }
}
