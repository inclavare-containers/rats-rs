use super::evidence::TdxEvidence;
use crate::errors::*;
use crate::tee::GenericAttester;

pub struct TdxAttester {}

impl TdxAttester {
    pub fn new() -> Self {
        Self {}
    }
}

impl GenericAttester for TdxAttester {
    type Evidence = TdxEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence> {
        if report_data.len() > 64 {
            Err(Error::kind_with_msg(
                ErrorKind::InvalidParameter,
                format!("report data length too long: {} > 64", report_data.len()),
            ))?;
        }

        let mut tdx_report_data = tdx_attest_rs::tdx_report_data_t { d: [0u8; 64usize] };
        tdx_report_data.d[..report_data.len()].clone_from_slice(report_data);

        let mut selected_att_key_id = tdx_attest_rs::tdx_uuid_t { d: [0; 16usize] };

        let (result, quote) = tdx_attest_rs::tdx_att_get_quote(
            Some(&tdx_report_data),
            None,
            Some(&mut selected_att_key_id),
            0,
        );

        if result != tdx_attest_rs::tdx_attest_error_t::TDX_ATTEST_SUCCESS {
            Err(Error::kind_with_msg(
                ErrorKind::TdxAttesterGenerateQuoteFailed,
                format!(
                    "tdx_attest_rs::tdx_att_get_quote failed: {:#04x}",
                    result as u32
                ),
            ))?;
        }

        TdxEvidence::new_from_checked(quote.unwrap())
    }
}
