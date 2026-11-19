//! Serial JSON transaction audit settings. Admission never opens the audit destination.
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
};

use regex::Regex;
use zentinel_modsec::{
    Error, ModSecurity,
    engine::control::AuditEngineMode,
    parser::{Action, Directive},
};

use super::{AuditWriter, RuleSources, rules::AuditRules};

#[derive(Clone)]
pub(crate) struct AuditConfig {
    pub(super) mode: AuditEngineMode,
    pub(super) relevant_status: Option<Regex>,
    pub(super) parts: String,
    format: String,
    target: String,
    file_mode: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            mode: AuditEngineMode::Off,
            relevant_status: None,
            parts: "ABCFHZ".into(),
            format: "Native".into(),
            target: String::new(),
            file_mode: 0o600,
        }
    }
}

fn valid_parts(parts: &str) -> bool {
    parts.starts_with('A')
        && parts.ends_with('Z')
        && parts[1..parts.len() - 1]
            .bytes()
            .all(|c| b"BCDEFGHIJK".contains(&c))
}

fn supported_parts(parts: &str) -> bool {
    parts.bytes().all(|c| b"ABFHKZ".contains(&c))
}

impl AuditConfig {
    pub(crate) fn has_target(&self) -> bool {
        !self.target.is_empty()
    }

    pub(crate) fn set(&mut self, name: &str, value: &str) -> Result<bool, String> {
        match name.to_ascii_lowercase().as_str() {
            "secauditengine" => {
                self.mode = match value.to_ascii_lowercase().as_str() {
                    "on" => AuditEngineMode::On,
                    "off" => AuditEngineMode::Off,
                    "relevantonly" => AuditEngineMode::RelevantOnly,
                    _ => return Err(format!("{name} expects On, Off or RelevantOnly")),
                }
            }
            "secauditlogrelevantstatus" => {
                if value.is_empty() {
                    return Err(format!("{name} requires a status expression"));
                }
                self.relevant_status = Some(Regex::new(value).map_err(|e| format!("{name}: {e}"))?);
            }
            "secauditlogparts" if valid_parts(value) => self.parts = value.to_owned(),
            "secauditlogparts" => return Err(format!("{name}: invalid audit parts {value:?}")),
            "secauditlogformat"
                if matches!(value.to_ascii_lowercase().as_str(), "native" | "json") =>
            {
                self.format = value.to_owned()
            }
            "secauditlogformat" => return Err(format!("{name}: unsupported format {value:?}")),
            "secauditlogtype" if value.eq_ignore_ascii_case("serial") => (),
            "secauditlogtype" => return Err(format!("{name}: only Serial is supported")),
            "secauditlogfilemode" => {
                self.file_mode = u32::from_str_radix(value, 8)
                    .map_err(|_| format!("{name}: invalid octal file mode {value:?}"))?;
            }
            "secauditlog" if !value.is_empty() => self.target = value.to_owned(),
            "secauditlog" => return Err(format!("{name} requires a destination")),
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub(crate) fn validate(&self, directives: &[Directive]) -> zentinel_modsec::Result<()> {
        if !self.has_target() {
            return Ok(());
        }
        let error = |msg: &str| Error::Config {
            message: msg.into(),
        };
        if !self.format.eq_ignore_ascii_case("json") {
            return Err(error(
                "Rust transaction audit output requires SecAuditLogFormat JSON",
            ));
        }
        if !supported_parts(&self.parts) {
            return Err(error(
                "Rust transaction audit output supports SecAuditLogParts ABFHKZ and subsets",
            ));
        }
        for directive in directives {
            let actions = match directive {
                Directive::SecRule(r) => &r.actions,
                Directive::SecAction(r) => &r.actions,
                Directive::SecDefaultAction(actions) => actions,
                Directive::SecRuleUpdateActionById { actions, .. }
                | Directive::SecRuleUpdateActionByIdRanges { actions, .. } => actions,
                _ => continue,
            };
            for action in actions {
                if let Action::Control(ctl) = action {
                    if ctl.directive.eq_ignore_ascii_case("auditLogParts")
                        && !ctl.value.starts_with('-')
                        && !supported_parts(ctl.value.trim_start_matches('+'))
                    {
                        return Err(error(
                            "Rust transaction audit output supports ctl:auditLogParts with ABFHKZ only",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn open(
        self,
        engine: &ModSecurity,
        sources: RuleSources,
    ) -> Result<Option<AuditWriter>, String> {
        if !self.has_target() {
            return Ok(None);
        }
        let sink = match self.target.as_str() {
            "/dev/stdout" => Sink::Stdout,
            "/dev/stderr" => Sink::Stderr,
            path => {
                let file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(self.file_mode)
                    .open(path)
                    .map_err(|e| format!("opening SecAuditLog {path:?}: {e}"))?;
                Sink::File(file)
            }
        };
        Ok(Some(AuditWriter {
            config: self,
            sink,
            rules: AuditRules::new(engine, sources),
        }))
    }
}

pub(super) enum Sink {
    Stdout,
    Stderr,
    File(File),
}
