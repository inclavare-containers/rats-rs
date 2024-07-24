#[cfg(feature = "attester-tdx")]
pub mod attester;
pub mod claims;
pub mod evidence;
#[cfg(feature = "verifier-tdx")]
pub mod verifier;

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        errors::*,
        tee::{
            auto::LocalEvidence,
            claims::{BUILT_IN_CLAIM_COMMON_EVIDENCE, BUILT_IN_CLAIM_COMMON_TEE_TYPE},
            GenericAttester, GenericEvidence, GenericVerifier, TeeType,
        },
    };
    use tests::{
        attester::TdxAttester,
        claims::{
            BUILT_IN_CLAIM_TDX_MR_TD, BUILT_IN_CLAIM_TDX_RT_MR0, BUILT_IN_CLAIM_TDX_RT_MR1,
            BUILT_IN_CLAIM_TDX_RT_MR2, BUILT_IN_CLAIM_TDX_RT_MR3,
        },
        verifier::TdxVerifier,
    };

    #[test]
    fn test_attester_and_verifier() -> Result<()> {
        if TeeType::detect_env() != Some(TeeType::Tdx) {
            /* skip */
            return Ok(());
        }

        let report_data = b"test_report_data";
        let attester = TdxAttester::new();
        let evidence = attester.get_evidence(report_data)?;
        assert_eq!(evidence.get_tee_type(), TeeType::Tdx);
        let verifier = TdxVerifier::new();
        assert_eq!(verifier.verify_evidence(&evidence, report_data), Ok(()));

        let claims = evidence.get_claims()?;
        println!("generated claims:\n{:?}", claims);

        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_EVIDENCE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_TEE_TYPE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_TDX_MR_TD));
        assert!(claims.contains_key(BUILT_IN_CLAIM_TDX_RT_MR0));
        assert!(claims.contains_key(BUILT_IN_CLAIM_TDX_RT_MR1));
        assert!(claims.contains_key(BUILT_IN_CLAIM_TDX_RT_MR2));
        assert!(claims.contains_key(BUILT_IN_CLAIM_TDX_RT_MR3));

        assert_eq!(
            claims.get(BUILT_IN_CLAIM_COMMON_TEE_TYPE),
            Some(&"tdx".as_bytes().into())
        );
        Ok(())
    }
}
