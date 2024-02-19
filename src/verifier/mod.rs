pub mod sgx_dcap;

use crate::{attester::GenericEvidence, claims::Claims, errors::Result};

pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    fn verify_evidence(&self, evidence: &Self::Evidence, report_data: &[u8]) -> Result<Claims>;
}
