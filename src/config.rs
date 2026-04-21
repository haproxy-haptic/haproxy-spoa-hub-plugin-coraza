use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext, RHashMap, RString, Tuple2};

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
#[derive(Debug)]
pub struct PluginConfig {
    pub directives: String,
    pub directives_file: Option<String>,
    pub request_body_limit: i32,
    pub request_body_in_memory_limit: i32,
    pub response_body_limit: i32,
    pub response_check: bool,
    pub detect_only: bool,
    pub transaction_ttl_ms: i32,
    pub applications: Vec<AppConfig>,
}

const DEFAULT_DIRECTIVES: &str = concat!(
    "SecRuleEngine On\n",
    "Include @coraza.conf-recommended\n",
    "Include @crs-setup.conf.example\n",
    "Include @owasp_crs/*.conf\n",
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
            applications: Vec::new(),
        }
    }
}

/// Extract WAF directives and body limit fields from a config table,
/// falling back to defaults for missing keys.
fn parse_waf_fields(table: &RHashMap<RString, ConfigValue>, defaults: &PluginConfig) -> WafFields {
    let directives = table
        .get("directives")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| defaults.directives.clone());

    let directives_file = table
        .get("directives_file")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let request_body_limit = table
        .get("request_body_limit")
        .and_then(|v| v.as_integer())
        .map(|n| n as i32)
        .unwrap_or(defaults.request_body_limit);

    let request_body_in_memory_limit = table
        .get("request_body_in_memory_limit")
        .and_then(|v| v.as_integer())
        .map(|n| n as i32)
        .unwrap_or(defaults.request_body_in_memory_limit);

    let response_body_limit = table
        .get("response_body_limit")
        .and_then(|v| v.as_integer())
        .map(|n| n as i32)
        .unwrap_or(defaults.response_body_limit);

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
        let waf = parse_waf_fields(&context.config, &defaults);

        let response_check = context
            .get_config("response_check")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.response_check);

        let detect_only = context
            .get_config("detect_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(defaults.detect_only);

        let transaction_ttl_ms = context
            .get_config("transaction_ttl_ms")
            .and_then(|v| v.as_integer())
            .map(|n| n as i32)
            .unwrap_or(defaults.transaction_ttl_ms);

        let applications = context
            .get_config("applications")
            .and_then(|v| v.as_table())
            .map(|table| {
                table
                    .iter()
                    .filter_map(|Tuple2(name, val)| {
                        let app_table = val.as_table()?;
                        let app_waf = parse_waf_fields(app_table, &defaults);
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
            applications,
        }
    }

    pub fn config_schema() -> &'static str {
        r#"{
            "type": "object",
            "properties": {
                "directives": {
                    "type": "string",
                    "description": "SecLang WAF directives. Default loads embedded OWASP CRS v4."
                },
                "directives_file": {
                    "type": "string",
                    "description": "Path to additional directives file loaded after inline directives."
                },
                "request_body_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 4096,
                    "description": "Maximum request body bytes to buffer."
                },
                "request_body_in_memory_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 4096,
                    "description": "Maximum request body bytes kept in memory."
                },
                "response_body_limit": {
                    "type": "integer",
                    "minimum": 0,
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
                    "description": "Log-only mode for response inspection (non-blocking)."
                },
                "transaction_ttl_ms": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 10000,
                    "description": "TTL in milliseconds for cached transactions (response correlation)."
                },
                "applications": {
                    "type": "object",
                    "description": "Per-application WAF configurations. Each key is an app name with its own directives and body limits.",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "directives": { "type": "string" },
                            "directives_file": { "type": "string" },
                            "request_body_limit": { "type": "integer", "minimum": 0 },
                            "request_body_in_memory_limit": { "type": "integer", "minimum": 0 },
                            "response_body_limit": { "type": "integer", "minimum": 0 }
                        }
                    }
                }
            }
        }"#
    }
}
