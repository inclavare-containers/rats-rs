use rats_rs::crypto::AsymmetricAlgo;
use rats_rs::crypto::HashAlgo;

#[allow(non_camel_case_types)]
pub type hash_algo_t = HashAlgo;

#[allow(non_camel_case_types)]
pub type asymmetric_algo_t = AsymmetricAlgo;

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum AttesterType {
    Auto,
    SgxDcap,
    Tdx,
}

#[allow(non_camel_case_types)]
pub type attester_type_t = AttesterType;
