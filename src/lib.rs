#![feature(specialization)]
#![feature(trait_upcasting)]
#![allow(incomplete_features)]
// To suppress warning messages appearing in recent nightly rust. See https://github.com/rust-lang/rust/issues/121315
#![allow(unused_imports)]

mod cert;
mod crypto;
mod errors;
pub mod tee;
pub mod transport;

pub use crate::cert::{verify_cert_der, CertBuilder};

#[cfg(all(feature = "is_sync", feature = "async-tokio"))]
compile_error!("features `is_sync` and `async-tokio` are mutually exclusive");
