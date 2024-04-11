#[cfg(not(any(feature = "attester-sgx-dcap-occlum")))]
compile_error!("At least one `attester-sgx-dcap-*` feature should be enabled");

use super::evidence::SgxDcapEvidence;
use crate::errors::*;
use crate::tee::GenericAttester;
use occlum_dcap::{sgx_report_data_t, DcapQuote};

pub struct SgxDcapAttester {}

impl SgxDcapAttester {
    pub fn new() -> Self {
        Self {}
    }
}

impl GenericAttester for SgxDcapAttester {
    type Evidence = SgxDcapEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence> {
        if cfg!(feature = "attester-sgx-dcap-occlum") {
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
                .kind(ErrorKind::SgxDcapAttesterGenerateQuoteFailed)
                .context("failed at generate_quote()")?;

            SgxDcapEvidence::new_from_checked(occlum_quote)
        } else {
            unreachable!()
        }
    }
}

pub fn detect_env() -> bool {
    /* We only support occlum now */
    if cfg!(feature = "attester-sgx-dcap-occlum") && std::env::var("OCCLUM").is_ok() {
        return true;
    }
    return false;
}
