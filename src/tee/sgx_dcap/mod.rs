#[cfg(feature = "attester-sgx-dcap")]
pub mod attester;
pub mod evidence;
#[cfg(feature = "verifier-sgx-dcap")]
pub mod verifier;

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        errors::*,
        tee::{
            claims::{BUILT_IN_CLAIM_COMMON_QUOTE, BUILT_IN_CLAIM_COMMON_QUOTE_TYPE},
            GenericAttester, GenericEvidence, GenericVerifier, TeeType,
        },
    };
    use tests::{
        attester::SgxDcapAttester,
        verifier::{
            claims::{BUILT_IN_CLAIM_SGX_MR_ENCLAVE, BUILT_IN_CLAIM_SGX_MR_SIGNER},
            SgxDcapVerifier,
        },
    };

    #[test]
    fn test_attester_and_verifier() -> Result<()> {
        if TeeType::detect_env() != Some(TeeType::SgxDcap) {
            /* skip */
            return Ok(());
        }

        let report_data = b"test_report_data";
        let attester = SgxDcapAttester::new();
        let evidence = attester.get_evidence(report_data)?;
        assert_eq!(evidence.get_tee_type(), TeeType::SgxDcap);
        let verifier = SgxDcapVerifier::new();
        let claims = verifier.verify_evidence(&evidence, report_data)?;
        println!("generated claims:\n{:?}", claims);

        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_QUOTE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_QUOTE_TYPE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_SGX_MR_ENCLAVE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_SGX_MR_SIGNER));

        Ok(())
    }
}
