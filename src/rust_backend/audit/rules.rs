//! Match messages use effective compiled actions and the original rule source.
use serde_json::{Value, json};
use std::{borrow::Cow, collections::HashMap, fmt::Write as _, path::PathBuf};
use zentinel_modsec::{
    ModSecurity, Transaction,
    engine::{RuleMessage, phase::Phase},
    parser::{Action, Directive, DisruptiveAction, FlowAction, LoggingAction, MetadataAction},
};

#[derive(Default)]
pub(crate) struct RuleSources {
    origins: HashMap<String, Source>,
    components: Vec<String>,
}

#[derive(Default)]
struct Source {
    file: String,
    line: usize,
    raw: String,
}

impl RuleSources {
    pub(crate) fn collect(
        directives: &[Directive],
        inline: &str,
        sources: &HashMap<PathBuf, String>,
        logical: impl Fn(&str) -> String,
    ) -> Result<Self, String> {
        let mut result = Self::default();
        let files: HashMap<_, Vec<_>> = sources
            .iter()
            .map(|(path, text)| (path, text.lines().collect()))
            .collect();
        let inline: Vec<_> = inline.lines().collect();
        let mut chain_starter: Option<String> = None;
        for directive in directives {
            let (actions, location) = match directive {
                Directive::SecRule(rule) => (&rule.actions, &rule.location),
                Directive::SecAction(rule) => (&rule.actions, &rule.location),
                Directive::SecComponentSignature(name) => {
                    result.components.push(name.clone());
                    continue;
                }
                _ => continue,
            };
            let id = actions.iter().find_map(|action| match action {
                Action::Metadata(MetadataAction::Id(n)) => Some(n.to_string()),
                _ => None,
            });
            let (lines, file) = if let Some(path) = &location.file {
                let lines = files
                    .get(path)
                    .ok_or_else(|| format!("missing parsed rule source {}", path.display()))?;
                (lines, logical(&path.to_string_lossy()))
            } else {
                (&inline, "_inline_".into())
            };
            let mut source = Source {
                file,
                line: location.line,
                raw: String::new(),
            };
            for (i, line) in lines
                .iter()
                .enumerate()
                .skip(location.line.saturating_sub(1))
            {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                source.line = i + 1;
                if let Some(prefix) = line.strip_suffix('\\') {
                    source.raw.push_str(prefix);
                } else {
                    source.raw.push_str(line);
                    break;
                }
            }
            let chained = actions
                .iter()
                .any(|a| matches!(a, Action::Flow(FlowAction::Chain)));
            if let Some(starter) = chain_starter.take() {
                if let Some(parent) = result.origins.get_mut(&starter) {
                    parent.raw.push_str(" \n");
                    parent.raw.push_str(&source.raw);
                }
                if chained {
                    chain_starter = Some(starter);
                }
            } else if let Some(id) = id {
                if chained {
                    chain_starter = Some(id.clone());
                }
                result.origins.insert(id, source);
            }
        }
        Ok(result)
    }
}

struct AuditRule {
    id: u64,
    enabled: bool,
    phase: u8,
    action: &'static str,
    severity: i16,
    rev: String,
    version: String,
    maturity: u8,
    accuracy: u8,
    tags: Vec<String>,
    source: Source,
}

pub(super) struct AuditRules {
    by_id: HashMap<String, AuditRule>,
    pub(super) components: Vec<String>,
    actionset: String,
}

impl AuditRules {
    pub(super) fn new(engine: &ModSecurity, mut sources: RuleSources) -> Self {
        let mut by_id = HashMap::new();
        for phase in Phase::ALL {
            for rule in engine.ruleset().rules_for_phase(phase) {
                let Some(name) = &rule.id else { continue };
                let Some(source) = sources.origins.remove(name) else {
                    continue;
                };
                let Ok(id) = name.parse() else { continue };
                let mut info = AuditRule {
                    id,
                    enabled: phase == Phase::RequestBody,
                    phase: phase.number(),
                    action: "Warning",
                    severity: -1,
                    rev: String::new(),
                    version: String::new(),
                    maturity: 0,
                    accuracy: 0,
                    tags: Vec::new(),
                    source,
                };
                for action in &rule.actions {
                    match action {
                        Action::Logging(LoggingAction::Log | LoggingAction::AuditLog) => {
                            info.enabled = true
                        }
                        Action::Logging(LoggingAction::NoLog | LoggingAction::NoAuditLog) => {
                            info.enabled = false
                        }
                        Action::Metadata(MetadataAction::Severity(n)) => {
                            info.severity = i16::from(*n)
                        }
                        Action::Metadata(MetadataAction::Rev(s)) => info.rev.clone_from(s),
                        Action::Metadata(MetadataAction::Ver(s)) => info.version.clone_from(s),
                        Action::Metadata(MetadataAction::Maturity(n)) => info.maturity = *n,
                        Action::Metadata(MetadataAction::Accuracy(n)) => info.accuracy = *n,
                        Action::Metadata(MetadataAction::Tag(s)) => info.tags.push(s.clone()),
                        Action::Disruptive(d) => {
                            info.action = match d {
                                DisruptiveAction::Deny | DisruptiveAction::Block => "Access denied",
                                DisruptiveAction::Drop => "Access dropped",
                                DisruptiveAction::Allow
                                | DisruptiveAction::AllowPhase
                                | DisruptiveAction::AllowRequest => "Access allowed",
                                DisruptiveAction::Redirect(_) => "Access redirected",
                                DisruptiveAction::Pass => "Warning",
                            }
                        }
                        _ => (),
                    }
                }
                by_id.insert(name.clone(), info);
            }
        }
        Self {
            by_id,
            actionset: sources.components.join(" "),
            components: sources.components,
        }
    }

    pub(super) fn relevant(&self, tx: &Transaction) -> bool {
        tx.matched_rules()
            .iter()
            .any(|id| self.by_id.get(id).is_some_and(|r| r.enabled))
    }

    pub(super) fn messages(&self, tx: &Transaction, parts: &str) -> Vec<Value> {
        let mut messages = Vec::new();
        let (trailer, details) = (parts.find('H'), parts.find('K'));
        if trailer.is_none() && details.is_none() {
            return messages;
        }
        for group in tx.audit_messages() {
            let Some(rule) = group
                .first()
                .and_then(|m| self.by_id.get(&m.rule_id))
                .filter(|r| r.enabled)
            else {
                continue;
            };
            let error = if trailer.is_some_and(|h| details.is_none_or(|k| h < k)) {
                rule.error_message(group, tx)
            } else {
                String::new()
            };
            if details.is_none() {
                messages
                    .push(json!({"actionset":"","message":"","error_message":error,"data":null}));
                continue;
            }
            for item in group {
                let msg = string(&item.message);
                messages.push(json!({"actionset": self.actionset, "message":msg, "error_message":error,
                    "data":{"file":rule.source.file, "line":rule.source.line, "id":rule.id, "rev":rule.rev, "msg":msg,
                    "data":string(&item.logdata), "severity":rule.severity, "ver":rule.version,
                    "maturity":rule.maturity, "accuracy":rule.accuracy, "tags":rule.tags, "raw":rule.source.raw}}));
            }
        }
        messages
    }
}

fn string(bytes: &Option<Vec<u8>>) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes.as_deref().unwrap_or_default())
}

fn shortened(bytes: &Option<Vec<u8>>) -> Cow<'_, str> {
    let value = bytes.as_deref().unwrap_or_default();
    String::from_utf8_lossy(&value[..value.len().min(280)])
}

impl AuditRule {
    fn error_message(&self, group: &[RuleMessage], tx: &Transaction) -> String {
        let request = tx.request_data();
        let first = &group[0];
        let display = group
            .iter()
            .find(|m| m.message.as_ref().is_some_and(|s| !s.is_empty()))
            .unwrap_or(first);
        let action = if tx.engine_mode() == zentinel_modsec::engine::ruleset::RuleEngineMode::On {
            self.action
        } else {
            "Warning"
        };
        let mut text = format!("[client {:?}] Coraza: {}", request.client_ip, action);
        if action != "Warning" {
            let _ = write!(text, " (phase {})", self.phase);
        }
        let severity = [
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "info",
            "debug",
        ]
        .get(self.severity as usize)
        .unwrap_or(&"unknown");
        let _ = write!(
            text,
            ". {} [file {:?}] [line \"{}\"] [id \"{}\"] [rev {:?}] [msg {:?}] [data {:?}] [severity {:?}] [ver {:?}] [maturity \"{}\"] [accuracy \"{}\"]",
            shortened(&display.message),
            self.source.file,
            self.source.line,
            self.id,
            self.rev,
            shortened(&first.message),
            shortened(&first.logdata),
            severity,
            self.version,
            self.maturity,
            self.accuracy
        );
        for tag in &self.tags {
            let _ = write!(text, " [tag {tag:?}]");
        }
        let _ = write!(
            text,
            " [hostname {:?}] [uri {:?}] [unique_id {:?}]",
            request.server_addr,
            request.uri_raw,
            tx.id()
        );
        for (i, m) in group.iter().enumerate().skip(1) {
            if !string(&m.message).is_empty() || !string(&m.logdata).is_empty() {
                let _ = write!(
                    text,
                    "[msg_match_{i} {:?}] [data_match_{i} {:?}]",
                    shortened(&m.message),
                    shortened(&m.logdata)
                );
            }
        }
        text
    }
}
