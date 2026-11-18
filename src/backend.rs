//! Types at the SPOA connector's boundary with the selected WAF.
#[cfg(feature = "go-backend")]
mod go;
#[cfg(feature = "go-backend")]
pub(crate) use go::*;

#[cfg(all(test, feature = "rust-backend"))]
pub(crate) use crate::rust_backend::config::active_count;
#[cfg(feature = "rust-backend")]
pub(crate) use crate::rust_backend::{
    config::{Waf, create_waf, validate_directives},
    transaction::{Evaluation, TransactionCache, evaluate_request, evaluate_response},
};

pub(crate) struct Request<'a> {
    pub tx_id: &'a str,
    pub src_ip: &'a str,
    pub src_port: i32,
    pub dst_ip: &'a str,
    pub dst_port: i32,
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub version: &'a str,
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

pub(crate) struct Response<'a> {
    pub tx_id: &'a str,
    pub status: i32,
    pub version: &'a str,
    pub headers: &'a [u8],
    pub body: &'a [u8],
}

#[cfg(feature = "rust-backend")]
impl Evaluation {
    pub fn action_str(&self) -> &str {
        self.action
    }
    pub fn data_str(&self) -> &str {
        &self.data
    }
    pub fn matched_rules_str(&self) -> &str {
        &self.matched_rules
    }
    pub fn matched_var_str(&self) -> &str {
        &self.matched_var
    }
}

#[cfg(feature = "rust-backend")]
fn validate_message<'a>(
    text: impl IntoIterator<Item = (&'static str, &'a str)>,
    headers: &[u8],
    body: &[u8],
) -> Result<(), String> {
    for (name, value) in text {
        if value.as_bytes().contains(&0) {
            return Err(format!("{name} contains an interior NUL byte"));
        }
    }
    for (name, size) in [("headers", headers.len()), ("body", body.len())] {
        i32::try_from(size).map_err(|_| format!("{name} exceeds i32::MAX bytes"))?;
    }
    Ok(())
}

#[cfg(feature = "rust-backend")]
impl Request<'_> {
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_message(
            [
                ("transaction ID", self.tx_id),
                ("source IP", self.src_ip),
                ("destination IP", self.dst_ip),
                ("method", self.method),
                ("path", self.path),
                ("query", self.query),
                ("HTTP version", self.version),
            ],
            self.headers,
            self.body,
        )
    }
}

#[cfg(feature = "rust-backend")]
impl Response<'_> {
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_message(
            [
                ("transaction ID", self.tx_id),
                ("HTTP version", self.version),
            ],
            self.headers,
            self.body,
        )
    }
}
