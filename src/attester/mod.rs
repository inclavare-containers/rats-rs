pub mod sgx_dcap;

use crate::errors::Result;

pub trait GenericAttester {
    type Evidence: GenericEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence>;
}

pub trait GenericEvidence {
    const DICE_OCBR_TAG: u64;

    fn get_raw_evidence_dice(&self) -> &[u8];

    fn from_raw_evidence(bytes: &[u8]) -> Self;
}
