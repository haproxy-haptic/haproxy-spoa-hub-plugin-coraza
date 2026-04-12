use coraza_plugin::config::PluginConfig;

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
}
