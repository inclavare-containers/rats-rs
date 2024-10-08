use indexmap::map::IndexMap;

pub type Claims = IndexMap<String, Vec<u8>>;

/* Common built-in claims */
pub const BUILT_IN_CLAIM_COMMON_QUOTE: &'static str = "common_quote";
pub const BUILT_IN_CLAIM_COMMON_QUOTE_TYPE: &'static str = "common_quote_type";
