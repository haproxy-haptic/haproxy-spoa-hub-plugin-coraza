//! Native evaluation, with a lease spanning the request and response callbacks.
mod cache;
mod result;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use zentinel_modsec::{Transaction, engine::ruleset::RuleEngineMode};

use super::audit::{AuditSession, timed};
use super::config::Waf;
use crate::backend::{Request, Response};
use crate::config::PluginConfig;

pub(crate) use cache::TransactionCache;
pub(crate) use result::{Evaluation, RuleCatalog};

/// The transaction owns its compiled rules. The matching catalog must survive
/// reloads alongside them, so the response uses metadata from the same policy.
struct Lease {
    tx: Transaction,
    catalog: Arc<RuleCatalog>,
    logged: usize,
    audit: Option<Box<AuditSession>>,
}

impl Lease {
    fn log_new_matches(&mut self) {
        if self.catalog.log_matches {
            let messages = self.tx.rule_messages();
            self.catalog.log(&messages[self.logged..]);
            self.logged = messages.len();
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Err(err) = timed(&mut self.audit, 5, || self.tx.process_logging()) {
            log::debug!("Rust WAF logging phase failed: {err}");
        }
        self.log_new_matches();
        if let Some(audit) = &self.audit {
            if let Err(err) = audit.finish(&self.tx) {
                log::error!("Rust WAF transaction audit write failed: {err}");
            }
        }
    }
}

fn headers(bytes: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut parts = bytes.split(|&c| c == 0);
    std::iter::from_fn(move || {
        loop {
            let (key, value) = (parts.next()?, parts.next()?);
            if !key.is_empty() {
                return Some((key, value));
            }
        }
    })
}

fn checked_metadata(value: i32, field: &str) -> zentinel_modsec::Result<u16> {
    u16::try_from(value).map_err(|_| zentinel_modsec::Error::Config {
        message: format!("out-of-range {field}"),
    })
}

fn request_phases(
    tx: &mut Transaction,
    request: &Request<'_>,
    time: &mut Option<Box<AuditSession>>,
) -> zentinel_modsec::Result<()> {
    tx.set_client_addr(
        request.src_ip,
        checked_metadata(request.src_port, "source port")?,
    );
    tx.set_server_addr(
        request.dst_ip,
        checked_metadata(request.dst_port, "destination port")?,
    );
    let uri = if request.query.is_empty() {
        Cow::Borrowed(request.path)
    } else {
        Cow::Owned(format!("{}?{}", request.path, request.query))
    };
    tx.process_uri(&uri, request.method, request.version)?;
    for (key, value) in headers(request.headers) {
        tx.add_request_header_bytes(key, value)?;
    }
    timed(time, 1, || tx.process_request_headers())?;
    if !tx.has_intervention() && !request.body.is_empty() {
        tx.write_request_body(request.body)?;
    }
    if !tx.has_intervention() {
        timed(time, 2, || tx.process_request_body())?;
    }
    Ok(())
}

fn response_phases(
    tx: &mut Transaction,
    response: &Response<'_>,
    time: &mut Option<Box<AuditSession>>,
) -> zentinel_modsec::Result<()> {
    for (key, value) in headers(response.headers) {
        tx.add_response_header_bytes(key, value)?;
    }
    let status = checked_metadata(response.status, "HTTP status")?;
    if let Some(t) = time {
        t.response(status);
    }
    timed(time, 3, || {
        tx.process_response_headers_with_status(status, response.version)
    })?;
    if !tx.has_intervention() && !response.body.is_empty() {
        tx.write_response_body(response.body)?;
    }
    if !tx.has_intervention() {
        timed(time, 4, || tx.process_response_body())?;
    }
    Ok(())
}

pub(crate) fn evaluate_request(
    waf: &Waf,
    cache: &TransactionCache,
    request: Request<'_>,
    config: &PluginConfig,
    detect_only: bool,
) -> Result<Evaluation, String> {
    request.validate()?;
    let mut tx = waf.engine.new_transaction_with_id(request.tx_id);
    waf.catalog.configure_reporting(&mut tx);
    tx.set_record_audit_messages(waf.audit.is_some());
    let mut lease = Lease {
        tx,
        catalog: Arc::clone(&waf.catalog),
        logged: 0,
        audit: waf.audit.as_ref().map(AuditSession::start),
    };
    if waf.engine.ruleset().engine_mode() == RuleEngineMode::Off {
        let allowed = Evaluation::allow();
        cache.record(&allowed, true, false);
        return Ok(allowed);
    }
    let processed = request_phases(&mut lease.tx, &request, &mut lease.audit);
    lease.log_new_matches();
    let mut failed = processed.is_err();
    let mut verdict = match processed {
        Err(err) => {
            log::debug!("Rust WAF request processing failed: {err}");
            Evaluation::error(400)
        }
        Ok(()) => {
            let mut result = lease.catalog.result(
                &lease.tx,
                config.expose_matched_data,
                config.matched_data_max_bytes,
            );
            if detect_only {
                result.allow_through();
            }
            result
        }
    };
    if config.response_check && config.transaction_ttl_ms > 0 && !verdict.denied() {
        let ttl = Duration::from_millis(config.transaction_ttl_ms as u64);
        if !cache.insert(
            request.tx_id,
            lease,
            ttl,
            config.max_cached_transactions.max(0) as usize,
        ) {
            failed = true;
            verdict = Evaluation::error(503);
        }
    }
    cache.record(&verdict, true, failed);
    Ok(verdict)
}

pub(crate) fn evaluate_response(
    cache: &TransactionCache,
    response: Response<'_>,
    detect_only: bool,
) -> Result<Evaluation, String> {
    response.validate()?;
    let Some(mut lease) = cache.take(response.tx_id) else {
        cache.missing_response();
        return Ok(Evaluation::error(503));
    };
    let processed = response_phases(&mut lease.tx, &response, &mut lease.audit);
    let failed = processed.is_err();
    let verdict = match processed {
        Err(err) => {
            log::debug!("Rust WAF response processing failed: {err}");
            Evaluation::error(502)
        }
        Ok(()) => {
            let mut result = lease.catalog.result(&lease.tx, false, 0);
            // The Go response callback uses an HTTP status as its override
            // condition; a statusless drop remains a drop.
            if detect_only && result.status != 0 {
                result.allow_through();
            }
            result
        }
    };
    cache.record(&verdict, false, failed);
    Ok(verdict)
}
