use crate::cert::dice::fields::OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT;
use crate::errors::*;
use crate::{
    cert::dice::fields::OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE,
    tee::{GenericEvidence, TeeType},
};

#[derive(Debug)]
pub struct SgxDcapEvidence {
    pub(crate) data: Vec<u8>,
}

impl GenericEvidence for SgxDcapEvidence {
    fn get_raw_evidence_dice(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE
    }

    fn get_tee_type(&self) -> TeeType {
        TeeType::SgxDcap
    }
}

pub(crate) fn create_evidence_from_dice(
    cbor_tag: u64,
    raw_evidence: &[u8],
) -> Option<Result<SgxDcapEvidence>> {
    if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE {
        /* Use a simplified header structure to distinguish between SGX (EPID and ECDSA) and TDX (ECDSA) quote types.
         * See: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/cd27223301e7c2bc80c9c5084ad6f5c2b9d24f5c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L111-L120
         */
        #[repr(C, packed)]
        #[derive(Debug, Default, Copy, Clone)]
        #[allow(non_camel_case_types)]
        pub struct sgx_quote_header_part_t {
            pub version: u16,
            pub att_key_type: u16,
            pub tee_type: u32,
        }

        if raw_evidence.len() < std::mem::size_of::<sgx_quote_header_part_t>() {
            return Some(Err(Error::kind_with_msg(
                ErrorKind::SgxDcapMulformedQuote,
                format!(
                    "Invalid quote: quote length {} is too short",
                    raw_evidence.len()
                ),
            )));
        }

        let header = unsafe { &*(raw_evidence.as_ptr() as *const sgx_quote_header_part_t) };
        if (header.version == 3 && (header.att_key_type == 2 || header.att_key_type == 3))
            || ((header.version == 4 || header.version == 5) && header.tee_type == 0)
        {
            return Some(Ok(SgxDcapEvidence {
                data: raw_evidence.into(),
            }));
        } else {
            let version = header.version;
            let att_key_type = header.att_key_type;
            let tee_type = header.tee_type;

            return Some(Err(Error::kind_with_msg(
                ErrorKind::SgxDcapUnsupportedEvidenceType,
                format!(
                    "Unsupported quote type, version: {:02x}, att_key_type: {:02x}, tee_type: {:02x}",
                    version, att_key_type, tee_type
                ),
            )));
        }
    } else if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT {
        return Some(Err(Error::kind_with_msg(
            ErrorKind::SgxDcapUnsupportedEvidenceType,
            "Unsupported evidence type: Intel TEE report (TDX report or SGX report type 2)",
        )));
    }
    return None;
}
