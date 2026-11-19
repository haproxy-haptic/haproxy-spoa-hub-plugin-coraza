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
    assert!(!config.include_crs_control_rule_hits);
    assert_eq!(
        config.matched_data_log,
        coraza_plugin::config::MatchedDataLog::None
    );
    assert_eq!(config.matched_data_max_bytes, 128);
    assert!(!config.expose_matched_data);
    assert!(config.default_waf);
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
    assert_eq!(parsed["properties"]["default_waf"]["type"], "boolean");
    assert_eq!(
        parsed["properties"]["include_crs_control_rule_hits"]["default"],
        false
    );
    assert_eq!(parsed["additionalProperties"], false);
}

#[test]
fn default_waf_can_be_disabled() {
    let mut config = RHashMap::new();
    config.insert(RString::from("default_waf"), ConfigValue::Bool(false));
    let parsed = PluginConfig::from_context(&PluginContext {
        name: RString::from("coraza"),
        config,
    });
    assert!(!parsed.default_waf);
}

#[test]
fn effective_directives_drop_what_corazas_parser_skips() {
    use coraza_plugin::config::effective_directives;
    let a = "Include @owasp_crs/*.conf\n\n# policy:a\nSecRuleRemoveById 942100\n";
    let b = "  Include @owasp_crs/*.conf  \r\n# policy:b\n\t# indented comment\nSecRuleRemoveById 942100";
    assert_eq!(effective_directives(a), effective_directives(b));
    assert_ne!(
        effective_directives(a),
        effective_directives("Include @owasp_crs/*.conf\nSecRuleRemoveById 942101\n"),
        "a different exclusion is a different rule set"
    );
    assert_ne!(
        effective_directives("SecAction \"id:1,pass,msg:'a#b'\"\n"),
        effective_directives("SecAction \"id:1,pass,msg:'a'\"\n"),
        "`#` only starts a comment at the beginning of a line"
    );
}

#[test]
fn effective_directives_keep_a_line_corazas_scanner_cannot_read() {
    use coraza_plugin::config::effective_directives;
    let long_comment = format!("# {}\n", "x".repeat(70 * 1024));
    let with = format!("SecRuleEngine On\n{long_comment}SecRuleRemoveById 1\n");
    let without = "SecRuleEngine On\nSecRuleRemoveById 1\n";
    assert_ne!(
        effective_directives(&with),
        effective_directives(without),
        "Coraza stops parsing at an over-long line, so the two blocks compile differently"
    );
}
