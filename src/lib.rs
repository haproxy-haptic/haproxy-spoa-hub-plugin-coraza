#![allow(non_camel_case_types, non_local_definitions)]

#[cfg(any(
    all(feature = "go-backend", feature = "rust-backend"),
    not(any(feature = "go-backend", feature = "rust-backend"))
))]
compile_error!("select exactly one WAF backend: go-backend or rust-backend");

mod backend;
pub mod config;
#[cfg(feature = "go-backend")]
pub mod ffi;
#[cfg(feature = "rust-backend")]
mod rust_backend;

mod plugin;
pub mod watcher;
