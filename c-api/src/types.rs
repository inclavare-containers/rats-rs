use std::ffi::c_char;

use rats_rs::crypto::AsymmetricAlgo;
use rats_rs::crypto::HashAlgo;

#[allow(non_camel_case_types)]
pub type hash_algo_t = HashAlgo;

#[allow(non_camel_case_types)]
pub type asymmetric_algo_t = AsymmetricAlgo;

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum LocalAttesterType {
    Auto,
    SgxDcap,
    Tdx,
}

#[allow(non_camel_case_types)]
pub type local_attester_type_t = LocalAttesterType;

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum AttesterType {
    Local(local_attester_type_t),
    Coco {
        aa_addr: *const c_char,
        timeout: i64,
    },
}

#[allow(non_camel_case_types)]
pub type attester_type_t = AttesterType;
