pub mod attester;
pub mod converter;
pub mod evidence;
mod ttrpc_protocol;
pub mod verifier;

pub const TTRPC_DEFAULT_TIMEOUT_NANO: i64 = 50 * 1000 * 1000 * 1000;
