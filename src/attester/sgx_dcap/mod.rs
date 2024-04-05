use super::{GenericAttester, GenericEvidence};
use crate::{cert::dice::fields::OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE, errors::*};

use occlum_dcap::{sgx_report_data_t, DcapQuote};

#[derive(Debug, Default)]
pub struct SgxDcapAttester {}

impl SgxDcapAttester {
    pub fn new() -> Self {
        Self {}
    }
}

impl GenericAttester for SgxDcapAttester {
    type Evidence = SgxDcapEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> crate::errors::Result<Self::Evidence> {
        if cfg!(feature = "build-mode-occlum") {
            if report_data.len() > 64 {
                Err(Error::kind_with_msg(
                    ErrorKind::InvalidParameter,
                    format!("report data length too long: {} > 64", report_data.len()),
                ))?;
            }
            let mut handler = DcapQuote::new()?;
            let quote_size = handler.get_quote_size()? as usize;
            let mut occlum_quote = Vec::new();

            occlum_quote.resize(quote_size, b'\0');

            let mut sgx_report_data = sgx_report_data_t::default();
            sgx_report_data.d[..report_data.len()].clone_from_slice(report_data);

            handler
                .generate_quote(
                    occlum_quote.as_mut_ptr(),
                    &sgx_report_data as *const sgx_report_data_t,
                )
                .kind(ErrorKind::AttesterSgxEcdsaGenerateQuoteFailed)
                .context("failed at generate_quote()")?;

            Ok(SgxDcapEvidence { data: occlum_quote })
        } else {
            todo!()
        }
    }
}

#[derive(Debug)]
pub struct SgxDcapEvidence {
    pub(crate) data: Vec<u8>,
}

impl GenericEvidence for SgxDcapEvidence {
    const DICE_OCBR_TAG: u64 = OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE;

    fn get_raw_evidence_dice(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn from_raw_evidence(bytes: &[u8]) -> Self {
        Self { data: bytes.into() }
    }
}
