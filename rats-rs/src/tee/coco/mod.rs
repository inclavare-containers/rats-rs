pub mod attester;
pub mod converter;
pub mod evidence;
mod ttrpc_protocol;
pub mod verifier;

pub const DEFAULT_TIMEOUT: i64 = 50 * 1000 * 1000 * 1000;
