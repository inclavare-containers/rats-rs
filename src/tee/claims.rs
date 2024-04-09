use std::collections::HashMap;

// TODO: replace with indexmap::map::IndexMap for deterministic order
pub type Claims = HashMap<String, Vec<u8>>;

/* Common built-in claims */
pub const BUILT_IN_CLAIM_COMMON_QUOTE: &'static str = "common_quote";
pub const BUILT_IN_CLAIM_COMMON_QUOTE_TYPE: &'static str = "common_quote_type";
