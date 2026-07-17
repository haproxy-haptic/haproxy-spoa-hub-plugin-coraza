use coraza_plugin::config::PluginConfig;
use haproxy_spoa_hub_plugin_api::{ConfigValue, PluginContext, RHashMap, RString};

#[test]
fn test_default_config() {
    let config = PluginConfig::default();
    assert!(config.directives.contains("SecRuleEngine On"));
    assert!(config.directives.contains("@owasp_crs/*.conf"));
    assert!(config.directives_file.is_none());
    assert_eq!(config.request_body_limit, 4096);
    assert_eq!(config.request_body_in_memory_limit, 4096);
    assert_eq!(config.response_body_limit, 4096);
    assert!(!config.response_check);
    assert!(!config.detect_only);
    assert_eq!(config.transaction_ttl_ms, 10000);
    assert_eq!(config.max_cached_transactions, 1024);
    assert!(!config.rule_match_log);
    assert_eq!(
        config.matched_data_log,
        coraza_plugin::config::MatchedDataLog::None
    );
    assert_eq!(config.matched_data_max_bytes, 128);
    assert!(!config.expose_matched_data);
    assert!(config.directives.contains("SecRxPreFilter On"));
    assert!(
        config.directives.rfind("SecRuleEngine On")
            > config.directives.find("@coraza.conf-recommended"),
        "the recommended config selects DetectionOnly, so the enforcement override must follow it"
    );
}

#[test]
fn application_inherits_effective_top_level_waf_fields() {
    let mut app = RHashMap::new();
    app.insert(
        RString::from("directives"),
        ConfigValue::String("SecRuleEngine On\n".into()),
    );
    let mut applications = RHashMap::new();
    applications.insert(RString::from("forgejo"), ConfigValue::Table(app));

    let mut config = RHashMap::new();
    config.insert(
        RString::from("directives_file"),
        ConfigValue::String("/etc/coraza/base.conf".into()),
    );
    config.insert(
        RString::from("request_body_limit"),
        ConfigValue::Integer(131_072),
    );
    config.insert(
        RString::from("request_body_in_memory_limit"),
        ConfigValue::Integer(65_536),
    );
    config.insert(
        RString::from("response_body_limit"),
        ConfigValue::Integer(32_768),
    );
    config.insert(
        RString::from("applications"),
        ConfigValue::Table(applications),
    );

    let parsed = PluginConfig::from_context(&PluginContext {
        name: RString::from("coraza"),
        config,
    });
    let app = &parsed.applications[0];
    assert_eq!(app.directives, "SecRuleEngine On\n");
    assert_eq!(
        app.directives_file.as_deref(),
        Some("/etc/coraza/base.conf")
    );
    assert_eq!(app.request_body_limit, 131_072);
    assert_eq!(app.request_body_in_memory_limit, 65_536);
    assert_eq!(app.response_body_limit, 32_768);
}

#[test]
fn test_config_schema_valid_json() {
    let schema = PluginConfig::config_schema();
    let parsed: serde_json::Value =
        serde_json::from_str(schema).expect("config schema should be valid JSON");
    assert_eq!(parsed["type"], "object");
    assert!(parsed["properties"]["directives"].is_object());
    assert!(parsed["properties"]["response_check"].is_object());
    assert!(parsed["properties"]["transaction_ttl_ms"].is_object());
    assert!(parsed["properties"]["max_cached_transactions"].is_object());
    assert_eq!(parsed["additionalProperties"], false);
}
