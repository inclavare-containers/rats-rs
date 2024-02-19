mod claims;

use std::{
    mem,
    time::{Duration, SystemTime},
};

use super::GenericVerifier;
use crate::{attester::sgx_dcap::SgxDcapEvidence, claims::Claims, errors::*};

use log::{debug, warn};
use sgx_dcap_quoteverify_rs::{
    sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use sgx_dcap_quoteverify_sys::sgx_quote3_t;

#[derive(Debug, Default)]
pub struct SgxDcapVerifier {}

impl SgxDcapVerifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl GenericVerifier for SgxDcapVerifier {
    type Evidence = SgxDcapEvidence;

    fn verify_evidence(&self, evidence: &Self::Evidence, report_data: &[u8]) -> Result<Claims> {
        /* Verify quote with intel sgx trsut chain */
        ecdsa_quote_verification(&evidence.data)
            .context("Evidence's identity verification error.")?;

        /* Parsing quote to get user-data and some fields */
        if evidence.data.len() < std::mem::size_of::<sgx_quote3_t>() {
            Err(Error::kind_with_msg(
                ErrorKind::VerifierSgxEcdsaMulformedQuote,
                format!(
                    "evidence too short, evidence.data.len(): {}",
                    evidence.data.len()
                ),
            ))?;
        }

        let quote = unsafe { &*(evidence.data.as_ptr() as *const sgx_quote3_t) };
        let expected_quote_len =
            std::mem::size_of::<sgx_quote3_t>() + quote.signature_data_len as usize;
        if evidence.data.len() < expected_quote_len {
            Err(Error::kind_with_msg(
                ErrorKind::VerifierSgxEcdsaMulformedQuote,
                format!(
                    "evidence too short and probably got truncated, evidence.data.len(): {}, expected: {}",
                    evidence.data.len(), expected_quote_len
                ),
            ))?;
        }

        /* Check report data */
        let mut extended = sgx_dcap_quoteverify_sys::sgx_report_data_t::default();
        extended.d[..report_data.len()].clone_from_slice(report_data);
        if quote.report_body.report_data.d != extended.d {
            Err(Error::kind_with_msg(
                ErrorKind::VerifierSgxEcdsaReportDataMismatch,
                "report data mismatch",
            ))?;
        }

        /* generate claims */
        self::claims::gen_claims_from_quote(&quote)
    }
}

// https://github.com/confidential-containers/kbs/blob/84432a2a97da306399db5bc863c9324dbd8b95ac/attestation-service/verifier/src/sgx/mod.rs#L101C1-L195C1
fn ecdsa_quote_verification(quote: &[u8]) -> Result<()> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    match tee_get_supplemental_data_version_and_size(quote) {
        std::result::Result::Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                debug!("tee_get_quote_supplemental_data_version_and_size successfully returned.");
                debug!(
                    "Info: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into()?),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into()?),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => Err(Error::kind_with_msg(
            ErrorKind::VerifierSgxEcdsaGetSupplementalDataFailed,
            format!(
                "tee_get_quote_supplemental_data_size failed: {:#04x}",
                e as u32
            ),
        ))?,
    }

    // get collateral
    let _collateral = match tee_qv_get_collateral(quote) {
        std::result::Result::Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

    let p_collateral: Option<&[u8]> = None;

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) =
        tee_verify_quote(quote, p_collateral, current_time, None, p_supplemental_data).map_err(
            |e| {
                Error::kind_with_msg(
                    ErrorKind::VerifierSgxEcdsaVerifyQuoteFailed,
                    format!("tee_verify_quote failed: {:#04x}", e as u32),
                )
            },
        )?;

    debug!("tee_verify_quote successfully returned.");

    // check verification result
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                debug!("Verification completed successfully.");
            } else {
                warn!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!(
                "Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        _ => {
            Err(Error::kind_with_msg(
                ErrorKind::VerifierSgxEcdsaVerifyQuoteFailed,
                format!(
                    "Verification completed with Terminal result: {:x}",
                    quote_verification_result as u32
                ),
            ))?;
        }
    }

    Ok(())
}
