use crate::claims::Claims;
use crate::errors::*;
use sgx_dcap_quoteverify_sys::sgx_quote3_t;

/* SGX built-in claims */
/* Refer to: https://github.com/intel/linux-sgx/blob/a1eeccba5a72b3b9b342569d2cc469ece106d3e9/common/inc/sgx_report.h#L93-L111 */
/* Security Version of the CPU */
pub const BUILT_IN_CLAIM_SGX_CPU_SVN: &'static str = "sgx_cpu_svn";
/* ISV assigned Extended Product ID */
pub const BUILT_IN_CLAIM_SGX_ISV_EXT_PROD_ID: &'static str = "sgx_isv_ext_prod_id";
/* Any special Capabilities the Enclave possess */
pub const BUILT_IN_CLAIM_SGX_ATTRIBUTES: &'static str = "sgx_attributes";
/* The value of the enclave's ENCLAVE measurement */
pub const BUILT_IN_CLAIM_SGX_MR_ENCLAVE: &'static str = "sgx_mr_enclave";
/* The value of the enclave's SIGNER measurement */
pub const BUILT_IN_CLAIM_SGX_MR_SIGNER: &'static str = "sgx_mr_signer";
/* CONFIGID */
pub const BUILT_IN_CLAIM_SGX_CONFIG_ID: &'static str = "sgx_config_id";
/* Product ID of the Enclave */
pub const BUILT_IN_CLAIM_SGX_ISV_PROD_ID: &'static str = "sgx_isv_prod_id";
/* Security Version of the Enclave */
pub const BUILT_IN_CLAIM_SGX_ISV_SVN: &'static str = "sgx_isv_svn";
/* CONFIGSVN */
pub const BUILT_IN_CLAIM_SGX_CONFIG_SVN: &'static str = "sgx_config_svn";
/* ISV assigned Family ID */
pub const BUILT_IN_CLAIM_SGX_ISV_FAMILY_ID: &'static str = "sgx_isv_family_id";


// TODO: test this with mulformed quote
pub fn gen_claims_from_quote(quote: &sgx_quote3_t) -> Result<Claims> {
    let mut claims = Claims::default();

    /* common claims */
    claims.insert(crate::claims::BUILT_IN_CLAIM_COMMON_QUOTE.into(), unsafe {
        core::slice::from_raw_parts(
            quote as *const sgx_quote3_t as *const u8,
            core::mem::size_of::<sgx_quote3_t>() + quote.signature_data_len as usize,
        )
        .into()
    });
    claims.insert(
        crate::claims::BUILT_IN_CLAIM_COMMON_QUOTE_TYPE.into(),
        "sgx_ecdsa".as_bytes().into(),
    );

    /* sgx claims */

    macro_rules! as_slice {
        ($value: expr) => {
            unsafe {
                let v = core::ptr::addr_of!($value);
                let v = core::ptr::read_unaligned(v);
                let s = core::slice::from_raw_parts(
                    &v as *const _ as *const u8,
                    core::mem::size_of_val(&v),
                );
                #[allow(forgetting_copy_types)]
                core::mem::forget(v);
                s
            }
        };
    }
    claims.insert(
        BUILT_IN_CLAIM_SGX_CPU_SVN.into(),
        as_slice!(quote.report_body.cpu_svn).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_ISV_EXT_PROD_ID.into(),
        as_slice!(quote.report_body.isv_ext_prod_id).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_ATTRIBUTES.into(),
        as_slice!(quote.report_body.attributes).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_MR_ENCLAVE.into(),
        as_slice!(quote.report_body.mr_enclave).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_MR_SIGNER.into(),
        as_slice!(quote.report_body.mr_signer).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_CONFIG_ID.into(),
        as_slice!(quote.report_body.config_id).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_ISV_PROD_ID.into(),
        as_slice!(quote.report_body.isv_prod_id).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_ISV_SVN.into(),
        as_slice!(quote.report_body.isv_svn).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_CONFIG_SVN.into(),
        as_slice!(quote.report_body.config_svn).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_SGX_ISV_FAMILY_ID.into(),
        as_slice!(quote.report_body.isv_family_id).into(),
    );

    Ok(claims)
}
