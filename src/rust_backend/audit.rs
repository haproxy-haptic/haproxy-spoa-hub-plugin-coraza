//! Coraza-compatible serial audit records, emitted once at transaction retirement.
mod config;
mod rules;

use chrono::{DateTime, Local};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Instant,
};
use zentinel_modsec::{
    Transaction,
    engine::control::AuditEngineMode,
    variables::{ByteCollection, HashMapCollection},
};

pub(crate) use self::{config::AuditConfig, rules::RuleSources};
use self::{config::Sink, rules::AuditRules};

pub(crate) struct AuditWriter {
    config: AuditConfig,
    sink: Sink,
    rules: AuditRules,
}

// Generations and policies may share a file or stdout. Hold this lock only
// for the append, after the complete record and its newline are serialized.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

pub(super) struct AuditSession {
    writer: Arc<AuditWriter>,
    start: DateTime<Local>,
    timer: Instant,
    phases: [u64; 5],
    response_status: Option<u16>,
}

impl AuditSession {
    pub(super) fn start(writer: &Arc<AuditWriter>) -> Box<Self> {
        Box::new(Self {
            writer: Arc::clone(writer),
            start: Local::now(),
            timer: Instant::now(),
            phases: [0; 5],
            response_status: None,
        })
    }
    pub(super) fn finish(&self, tx: &Transaction) -> io::Result<()> {
        self.writer.finish(tx, self)
    }
    pub(super) fn response(&mut self, status: u16) {
        self.response_status = Some(status);
    }
    fn stopwatch(&self) -> String {
        let [p1, p2, p3, p4, p5] = self.phases;
        format!(
            "{} {}; combined={}, p1={p1}, p2={p2}, p3={p3}, p4={p4}, p5={p5}",
            self.start.timestamp_nanos_opt().unwrap_or_default(),
            self.timer.elapsed().as_nanos(),
            self.phases.iter().sum::<u64>()
        )
    }
}

pub(super) fn timed<T>(
    audit: &mut Option<Box<AuditSession>>,
    phase: usize,
    run: impl FnOnce() -> T,
) -> T {
    if let Some(t) = audit {
        let start = Instant::now();
        let result = run();
        t.phases[phase - 1] = start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        result
    } else {
        run()
    }
}

fn headers(collection: &HashMapCollection) -> BTreeMap<String, Vec<String>> {
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, _, value) in collection.all_bytes_with_names() {
        headers
            .entry(String::from_utf8_lossy(key).to_lowercase())
            .or_default()
            .push(String::from_utf8_lossy(value).into_owned());
    }
    headers
}

impl AuditWriter {
    fn relevant(&self, tx: &Transaction, time: &AuditSession) -> bool {
        match tx.audit_engine_override().unwrap_or(self.config.mode) {
            AuditEngineMode::Off => false,
            AuditEngineMode::On => true,
            AuditEngineMode::RelevantOnly => {
                if let Some(expr) = &self.config.relevant_status {
                    let status = tx
                        .intervention()
                        .map(|interruption| interruption.status)
                        .or_else(|| tx.detection_only_status())
                        .or(time.response_status);
                    expr.is_match(&status.map(|n| n.to_string()).unwrap_or_default())
                } else {
                    self.rules.relevant(tx)
                }
            }
        }
    }

    pub(super) fn finish(&self, tx: &Transaction, time: &AuditSession) -> io::Result<()> {
        if !self.relevant(tx, time) {
            return Ok(());
        }
        let parts = tx.audit_log_parts(&self.config.parts);
        let request = tx.request_data();
        let mut transaction = json!({
            "timestamp":time.start.format("%Y/%m/%d %H:%M:%S").to_string(),
            "unix_timestamp":time.start.timestamp_nanos_opt().unwrap_or_default(), "id":tx.id(),
            "client_ip":request.client_ip, "client_port":request.client_port,
            "host_ip":request.server_addr, "host_port":request.server_port, "server_id":request.server_name,
            "highest_severity":"", "is_interrupted":tx.has_intervention(),
            "request":{"method":request.method,"protocol":request.protocol,"uri":request.uri,
                "http_version":"","headers":parts.contains('B').then(|| headers(&request.headers)),
                "body":"","files":null,"args":{},"length":0}
        });
        if parts.contains('F') {
            transaction["response"] = json!({"protocol":"","status":time.response_status.unwrap_or(0),
                "headers":headers(&tx.response_data().headers),"body":""});
        }
        if parts.contains('H') {
            transaction["producer"] = json!({"connector":"","version":"","server":"",
                "rule_engine":format!("{:?}",tx.engine_mode()),"stopwatch":time.stopwatch(),
                "rulesets":(!self.rules.components.is_empty()).then_some(&self.rules.components)});
        }
        let mut record = json!({"transaction":transaction});
        let messages = self.rules.messages(tx, &parts);
        if !messages.is_empty() {
            record["messages"] = Value::Array(messages);
        }
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match &self.sink {
            Sink::Stdout => io::stdout().lock().write_all(&bytes),
            Sink::Stderr => io::stderr().lock().write_all(&bytes),
            Sink::File(file) => (&*file).write_all(&bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::PluginConfig;
    use crate::rust_backend::config::{create_waf, validate_directives};

    #[test]
    fn admission_checks_parts_and_format_without_opening_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("audit.log");
        let policy = format!(
            "SecAuditLog {}\nSecAuditLogFormat JSON\nSecAuditLogParts ABFHKZ",
            target.display()
        );
        let included = serde_json::json!({"/staged/audit.conf": policy}).to_string();
        assert!(validate_directives("Include /staged/audit.conf", &included).is_empty());
        assert!(!target.exists());
        for invalid in [
            "SecAuditLogType concurrent",
            "SecAuditLogFormat native",
            "SecAuditLogParts ACZ",
            "SecAuditLogParts BFHK",
            "SecAuditLogRelevantStatus (",
            "SecAuditLogFileMode 99",
            "SecAuditEngine sometimes",
            r#"SecAction "id:501,phase:1,pass,ctl:auditLogParts=+E""#,
        ] {
            assert!(
                !validate_directives(&format!("{policy}\n{invalid}"), "").is_empty(),
                "{invalid}"
            );
        }
        assert!(!target.exists());
    }

    #[test]
    fn new_generations_append_complete_records_and_keep_existing_permissions() {
        let _lock = crate::plugin::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("audit.log");
        let policy = format!(
            "SecAuditLog {}\nSecAuditEngine On\nSecAuditLogParts AZ\nSecAuditLogFormat JSON",
            target.display()
        );
        let create = || create_waf(&policy, None, 0, 0, 0, &PluginConfig::default()).unwrap();
        let first = create();
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(&target, "existing\n").unwrap();
        let second = create();
        std::thread::scope(|scope| {
            for (id, waf) in [("old", &first), ("new", &second)] {
                scope.spawn(move || {
                    let tx = waf.engine.new_transaction_with_id(id);
                    let session = AuditSession::start(waf.audit.as_ref().unwrap());
                    session.finish(&tx).unwrap();
                });
            }
        });
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o640
        );
        let log = fs::read_to_string(target).unwrap();
        let mut lines = log.lines();
        assert_eq!(lines.next(), Some("existing"));
        let mut ids: Vec<_> = lines
            .map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["transaction"]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        ids.sort();
        assert_eq!(ids, ["new", "old"]);
    }
}
