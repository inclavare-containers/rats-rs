#![feature(specialization)]
#![feature(trait_upcasting)]
#![allow(incomplete_features)]
// To suppress warning messages appearing in recent nightly rust. See https://github.com/rust-lang/rust/issues/121315
#![allow(unused_imports)]

pub mod cert;
pub mod crypto;
pub mod errors;
pub mod tee;

#[cfg(all(feature = "is-sync", feature = "async-tokio"))]
compile_error!("features `is-sync` and `async-tokio` are mutually exclusive");
