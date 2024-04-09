#![feature(specialization)]
#![allow(incomplete_features)]

mod cert;
mod crypto;
mod errors;
pub mod tee;
pub mod transport;

pub use crate::cert::{verify_cert_der, CertBuilder};

#[cfg(all(feature = "is_sync", feature = "async-tokio"))]
compile_error!("features `is_sync` and `async-tokio` are mutually exclusive");
