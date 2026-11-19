use std::collections::HashMap;

use sha2::{Digest, Sha256};
use zentinel_modsec::{
    ModSecurity, Transaction,
    engine::{RuleMessage, phase::Phase},
    parser::{Action, LoggingAction, MetadataAction},
};

use crate::config::{MatchedDataLog, PluginConfig};

#[derive(Debug)]
pub(crate) struct Evaluation {
    pub(crate) rule_id: i32,
    pub(crate) action: &'static str,
    pub(crate) status: i32,
    pub(crate) data: String,
    pub(crate) anomaly_score: i32,
    pub(crate) rules_hit: i32,
    pub(crate) matched_rules: String,
    pub(crate) matched_var: String,
}

impl Evaluation {
    pub(super) fn allow() -> Self {
        Self {
            action: "allow",
            rule_id: 0,
            status: 0,
            data: String::new(),
            anomaly_score: 0,
            rules_hit: 0,
            matched_rules: String::new(),
            matched_var: String::new(),
        }
    }

    pub(super) fn error(status: i32) -> Self {
        Self {
            action: "deny",
            status,
            ..Self::allow()
        }
    }

    pub(super) fn allow_through(&mut self) {
        self.action = "allow";
        self.status = 0;
    }

    pub(super) fn denied(&self) -> bool {
        self.status != 0 || self.action != "allow"
    }
}

#[derive(Debug)]
struct RuleInfo {
    id: i64,
    severity: Option<u8>,
    log: bool,
    hit_json: String,
    report_hit: bool,
}

#[derive(Debug)]
pub(crate) struct RuleCatalog {
    rules: HashMap<String, RuleInfo>,
    pub(super) log_matches: bool,
    data_log: MatchedDataLog,
    data_limit: i32,
}

impl RuleCatalog {
    pub(crate) fn new(engine: &ModSecurity, config: &PluginConfig) -> Self {
        let mut rules = HashMap::new();
        for phase in Phase::ALL {
            for rule in engine.ruleset().rules_for_phase(phase) {
                let Some(name) = &rule.id else { continue };
                let Ok(id) = name.parse::<i64>() else {
                    continue;
                };
                let mut severity = None;
                let mut crs_tag = false;
                let mut log = rule.phase == Phase::RequestBody;
                for action in &rule.actions {
                    match action {
                        Action::Metadata(MetadataAction::Severity(n)) => severity = Some(*n),
                        Action::Metadata(MetadataAction::Tag(tag)) if tag == "OWASP_CRS" => {
                            crs_tag = true
                        }
                        Action::Logging(LoggingAction::Log) => log = true,
                        Action::Logging(LoggingAction::NoLog) => log = false,
                        _ => (),
                    }
                }
                let priority = severity.map_or(-1, i16::from);
                rules.insert(
                    name.clone(),
                    RuleInfo {
                        id,
                        severity,
                        log,
                        report_hit: config.include_crs_control_rule_hits
                            || severity.is_some()
                            || !crs_tag,
                        hit_json: format!(r#"{{"i":{id},"s":{priority}}}"#),
                    },
                );
            }
        }
        Self {
            rules,
            log_matches: config.rule_match_log,
            data_log: config.matched_data_log,
            data_limit: config.matched_data_max_bytes,
        }
    }

    pub(super) fn configure_reporting(&self, tx: &mut Transaction) {
        tx.set_source_qualified_argument_names(true);
        tx.record_matched_fields(MAX_MATCHED_FIELDS, request_field);
        tx.set_record_rule_messages(self.log_matches);
    }

    pub(super) fn result(&self, tx: &Transaction, expose_data: bool, limit: i32) -> Evaluation {
        let mut result = Evaluation::allow();
        let matched = tx.matched_rules();
        result.rules_hit = matched.len() as i32;
        let interruption = tx.intervention();
        result.rule_id = interruption
            .and_then(|i| i.rule_ids.first())
            .and_then(|id| id.parse().ok())
            .unwrap_or(0);
        let mut json = String::new();
        for id in matched {
            let Some(info) = self.rules.get(id) else {
                continue;
            };
            if result.rule_id == 0
                && interruption.is_none()
                && matches!(info.id, 949110 | 949111 | 959100 | 959101)
            {
                result.rule_id = info.id as i32;
            }
            if info.id > 0 && (info.report_hit || info.id == i64::from(result.rule_id)) {
                json.push(if json.is_empty() { '[' } else { ',' });
                json.push_str(&info.hit_json);
            }
            if let Some(severity @ 2..=5) = info.severity {
                result.anomaly_score += i32::from(7 - severity);
            }
        }
        if !json.is_empty() {
            json.push(']');
        }
        result.matched_rules = json;

        if let Some(interruption) = interruption {
            result.status = i32::from(interruption.status);
            result.action = if interruption.drop_connection {
                "drop"
            } else if interruption.url.is_some() {
                "redirect"
            } else {
                "deny"
            };
            if let Some(url) = interruption.url.as_ref().filter(|_| expose_data) {
                result.data = bounded(url.as_bytes(), limit);
            }
        } else if result.rule_id != 0 {
            result.action = "deny";
            result.status = 403;
        } else {
            return result;
        }
        result.matched_var = self.matched_variables(tx, result.rule_id);
        result
    }

    fn matched_variables(&self, tx: &Transaction, preferred: i32) -> String {
        let mut matches = Vec::new();
        for (id, name) in tx.matched_fields() {
            let Some(info) = id.and_then(|id| self.rules.get(id)) else {
                continue;
            };
            let rank = if preferred != 0 && info.id == i64::from(preferred) {
                0
            } else {
                1 + u16::from(info.severity.unwrap_or(u8::MAX))
            };
            matches.push((rank, name));
        }
        matches.sort_by_key(|&(rank, _)| rank);
        let mut names = Vec::with_capacity(MAX_MATCHED_FIELDS);
        for (_, name) in matches {
            if !names.contains(&name) {
                names.push(name);
                if names.len() == MAX_MATCHED_FIELDS {
                    break;
                }
            }
        }
        names.join(",")
    }

    pub(super) fn log(&self, messages: &[RuleMessage]) {
        for message in messages {
            if !self.rules.get(&message.rule_id).is_some_and(|r| r.log) {
                continue;
            }
            let text = bounded(message.message.as_deref().unwrap_or_default(), 512);
            let bytes = message.logdata.as_deref().unwrap_or_default();
            let data = match self.data_log {
                MatchedDataLog::None => String::new(),
                MatchedDataLog::Truncate => bounded(bytes, self.data_limit),
                MatchedDataLog::Hash => format!("sha256:{:x}", Sha256::digest(bytes)),
            };
            if data.is_empty() {
                log::warn!("WAF rule matched rule_id={} msg={text:?}", message.rule_id);
            } else {
                log::warn!(
                    "WAF rule matched rule_id={} msg={text:?} data={data:?}",
                    message.rule_id
                );
            }
        }
    }
}

const MAX_MATCHED_FIELDS: usize = 5;

fn request_field(name: &str) -> Option<&str> {
    const INPUTS: &[&str] = &[
        "ARGS",
        "REQUEST_HEADERS",
        "REQUEST_COOKIES",
        "REQUEST_URI",
        "REQUEST_BODY",
        "REQUEST_LINE",
        "REQUEST_FILENAME",
        "REQUEST_METHOD",
        "REQUEST_PROTOCOL",
        "QUERY_STRING",
        "PATH_INFO",
        "FILES",
        "MULTIPART",
        "XML",
        "JSON",
    ];
    let (collection, key) = name.split_once(':').unwrap_or((name, ""));
    INPUTS
        .iter()
        .any(|prefix| collection.starts_with(prefix))
        .then_some(if key.is_empty() { collection } else { name })
}

fn bounded(bytes: &[u8], limit: i32) -> String {
    if limit <= 0 {
        return String::new();
    }
    let limit = limit as usize;
    let mut value: String = bytes
        .iter()
        .take(limit)
        .map(|&b| {
            if (b' '..=b'~').contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    if bytes.len() > limit {
        value.push_str("...");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_retains_ordered_rule_hits_and_input_names_on_detect_only() {
        let engine = ModSecurity::from_string(
            r#"
SecRuleEngine On
SecRule ARGS_NAMES "@streq category" "id:1,phase:1,pass,severity:NOTICE"
SecRule ARGS:category "@streq books" "id:2,phase:1,deny,status:418,severity:CRITICAL"
"#,
        )
        .unwrap();
        let catalog = RuleCatalog::new(&engine, &PluginConfig::default());
        let mut tx = engine.new_transaction();
        catalog.configure_reporting(&mut tx);
        tx.process_uri("/?category=books", "GET", "HTTP/1.1")
            .unwrap();
        tx.process_request_headers().unwrap();
        let mut result = catalog.result(&tx, true, 512);
        assert_eq!(
            (result.status, result.rule_id, result.rules_hit),
            (418, 2, 2)
        );
        assert_eq!(result.anomaly_score, 7);
        assert_eq!(result.matched_rules, r#"[{"i":1,"s":5},{"i":2,"s":2}]"#);
        assert_eq!(
            result.matched_var,
            "ARGS_GET:category,ARGS_GET_NAMES:category"
        );
        assert!(result.data.is_empty());
        result.allow_through();
        assert!(!result.denied());
        assert_eq!(result.rule_id, 2);
        assert_eq!(result.anomaly_score, 7);
    }

    #[test]
    fn matched_field_list_includes_later_targets_and_ranks_whole_chains() {
        let engine = ModSecurity::from_string(
            r#"
SecRuleEngine On
SecRule ARGS:fallback|ARGS:extra "@streq green" "id:1,phase:1,pass,severity:NOTICE"
SecRule ARGS:a|ARGS:other "@streq green" "id:2,phase:1,pass,severity:CRITICAL"
SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,pass,chain"
SecRule ARGS:missing "@streq green" "t:none"
SecRule ARGS:a|ARGS:b "@streq green" "id:4,phase:1,deny,chain"
SecRule ARGS:b|ARGS:c "@streq green" "t:none"
"#,
        )
        .unwrap();
        let catalog = RuleCatalog::new(&engine, &PluginConfig::default());
        let mut tx = engine.new_transaction();
        catalog.configure_reporting(&mut tx);
        tx.process_uri(
            "/?fallback=green&extra=green&other=green&a=green&b=green&c=green",
            "GET",
            "HTTP/1.1",
        )
        .unwrap();
        tx.process_request_headers().unwrap();
        let result = catalog.result(&tx, true, 512);
        assert_eq!((result.status, result.rule_id), (403, 4));
        assert_eq!(
            result.matched_var,
            "ARGS_GET:a,ARGS_GET:b,ARGS_GET:c,ARGS_GET:other,ARGS_GET:fallback"
        );
    }

    #[test]
    fn exposed_redirect_data_uses_the_configured_byte_limit() {
        let engine = ModSecurity::from_string(
            r#"SecRuleEngine On
SecRule REQUEST_METHOD "@streq GET" "id:3,phase:1,redirect:/target,status:307""#,
        )
        .unwrap();
        let catalog = RuleCatalog::new(&engine, &PluginConfig::default());
        let mut tx = engine.new_transaction();
        catalog.configure_reporting(&mut tx);
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let result = catalog.result(&tx, true, 4);
        assert_eq!((result.action, result.status), ("redirect", 307));
        assert_eq!(result.data, "/tar...");
        assert!(catalog.result(&tx, false, 4).data.is_empty());
        assert_eq!(bounded(b"a\n\xff", 3), "a..");
    }
}
