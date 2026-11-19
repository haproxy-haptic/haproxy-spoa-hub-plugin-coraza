//! Translate structured engine load diagnostics into admission errors. The
//! subscriber is scoped to the compilation thread and never installed globally.
use std::fmt;
use std::sync::{Arc, Mutex};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Default)]
struct Fields {
    feature: String,
    name: String,
    reason: String,
    rule_ids: String,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let target = match field.name() {
            "feature" => &mut self.feature,
            "name" => &mut self.name,
            "directive" => {
                self.feature = "ctl".to_owned();
                &mut self.name
            }
            "rule_ids" => &mut self.rule_ids,
            "reason" => &mut self.reason,
            _ => return,
        };
        *target = format!("{value:?}");
    }
}

struct Unsupported(Arc<Mutex<Vec<String>>>);
impl<S: Subscriber> Layer<S> for Unsupported {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if !event
            .metadata()
            .target()
            .starts_with("zentinel_modsec::engine::")
        {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.reason.is_empty() || fields.name.is_empty() {
            return;
        }
        // ParserHost checked every external directive. Rule log flags are
        // consumed by the connector's catalog. The transaction writer observes audit controls directly. Coraza
        // 3.8.1's initcol.Evaluate is itself empty.
        if fields.feature == "directive"
            || (fields.feature == "action"
                && matches!(
                    fields.name.as_str(),
                    "log" | "nolog" | "auditlog" | "noauditlog" | "initcol"
                ))
        {
            return;
        }
        self.0.lock().unwrap().push(format!(
            "{} {} in rules {}: {}",
            fields.feature, fields.name, fields.rule_ids, fields.reason
        ));
    }
}

pub(super) fn checked<T>(
    compile: impl FnOnce() -> zentinel_modsec::Result<T>,
) -> zentinel_modsec::Result<T> {
    let issues = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Unsupported(Arc::clone(&issues)));
    let value = tracing::subscriber::with_default(subscriber, compile)?;
    let issues = issues.lock().unwrap();
    if issues.is_empty() {
        Ok(value)
    } else {
        Err(super::config_error(issues.join("\n")))
    }
}
