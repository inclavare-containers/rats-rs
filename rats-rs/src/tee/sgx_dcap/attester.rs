#[cfg(not(any(feature = "attester-sgx-dcap-occlum")))]
compile_error!("At least one `attester-sgx-dcap-*` feature should be enabled");

use super::evidence::SgxDcapEvidence;
use crate::errors::*;
use crate::tee::GenericAttester;
use occlum_dcap::{sgx_report_data_t, DcapQuote};

#[cfg(feature = "async-tokio")]
use tokio::task;

pub struct SgxDcapAttester {}

impl SgxDcapAttester {
    pub fn new() -> Self {
        Self {}
    }
}

#[maybe_async::maybe_async]
impl GenericAttester for SgxDcapAttester {
    type Evidence = SgxDcapEvidence;

    async fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence> {
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

            #[cfg(feature = "async-tokio")]
            {
                let handle = task::spawn_blocking(move || {
                    handler
                        .generate_quote(
                            occlum_quote.as_mut_ptr(),
                            &sgx_report_data as *const sgx_report_data_t,
                        )
                        .kind(ErrorKind::SgxDcapAttesterGenerateQuoteFailed)
                        .context("failed at generate_quote()")
                        .map(|_| occlum_quote)
                });
                occlum_quote = handle.await.context("the quote generation task panics")??;
            }

            #[cfg(not(feature = "async-tokio"))]
            {
                handler
                    .generate_quote(
                        occlum_quote.as_mut_ptr(),
                        &sgx_report_data as *const sgx_report_data_t,
                    )
                    .kind(ErrorKind::SgxDcapAttesterGenerateQuoteFailed)
                    .context("failed at generate_quote()")?;
            }

            SgxDcapEvidence::new_from_checked(occlum_quote)
        } else {
            unreachable!()
        }
    }
}
