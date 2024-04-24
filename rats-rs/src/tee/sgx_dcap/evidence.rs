use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::intel_dcap::{sgx_quote3_t, sgx_quote4_header_t};
use crate::{
    cert::dice::cbor::OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE,
    tee::{GenericEvidence, TeeType},
};

/// This `SgxDcapEvidence` struct Represents an SGX DCAP quote of version 3
///
/// The `data` field stores a vector of bytes representing the SGX DCAP quote of version 3.
/// And it is ensured that the length of the `data` vector is properly checked to avoid memory safety issues.
#[derive(Debug)]
pub struct SgxDcapEvidence {
    data: Vec<u8>,
}

impl SgxDcapEvidence {
    pub(crate) fn new_from_checked(checked_quote: Vec<u8>) -> Result<Self> {
        Ok(Self {
            data: checked_quote,
        })
    }

    pub fn new_from_unchecked(unchecked_quote: &[u8]) -> Result<Self> {
        if unchecked_quote.len() < std::mem::size_of::<sgx_quote4_header_t>() {
            return Err(Error::kind_with_msg(
                ErrorKind::SgxDcapMulformedQuote,
                format!(
                    "Invalid quote: quote length {} is too short",
                    unchecked_quote.len()
                ),
            ));
        }

        let header = unsafe { &*(unchecked_quote.as_ptr() as *const sgx_quote4_header_t) };
        if (header.version == 3 && (header.att_key_type == 2 || header.att_key_type == 3))
            || ((header.version == 4 || header.version == 5) && header.tee_type == 0)
        {
            if unchecked_quote.len() < std::mem::size_of::<sgx_quote3_t>() {
                Err(Error::kind_with_msg(
                    ErrorKind::SgxDcapMulformedQuote,
                    format!(
                        "Invalid quote: quote length {} is too short",
                        unchecked_quote.len()
                    ),
                ))?;
            }

            let quote = unsafe { &*(unchecked_quote.as_ptr() as *const sgx_quote3_t) };
            let expected_quote_len =
                std::mem::size_of::<sgx_quote3_t>() + quote.signature_data_len as usize;
            if unchecked_quote.len() != expected_quote_len {
                Err(Error::kind_with_msg(
                    ErrorKind::SgxDcapMulformedQuote,
                    format!(
                        "Invalid SGX DCAP quote version 3: quote length mismatch and probably got truncated, unchecked_quote.len(): {}, expected: {}",
                        unchecked_quote.len(), expected_quote_len
                    ),
                ))?;
            }
            // TODO: support version 4 and version 5
        } else {
            let version = header.version;
            let att_key_type = header.att_key_type;
            let tee_type = header.tee_type;

            return Err(Error::kind_with_msg(
                ErrorKind::SgxDcapUnsupportedEvidenceType,
                format!(
                    "Unsupported quote type, version: {:02x}, att_key_type: {:02x}, tee_type: {:02x}",
                    version, att_key_type, tee_type
                ),
            ));
        }

        Ok(Self {
            data: unchecked_quote.into(),
        })
    }

    pub(crate) fn as_quote(&self) -> &sgx_quote3_t {
        return unsafe { &*(self.data.as_ptr() as *const sgx_quote3_t) };
    }

    pub(crate) fn as_quote_data(&self) -> &[u8] {
        return &self.data;
    }
}

impl GenericEvidence for SgxDcapEvidence {
    fn get_dice_raw_evidence(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE
    }

    fn get_tee_type(&self) -> TeeType {
        TeeType::SgxDcap
    }

    fn get_claims(&self) -> Result<Claims> {
        super::claims::gen_claims_from_quote(self.as_quote())
    }
}

/// Creates SgxDcapEvidence from DICE cert data.
///
/// # Arguments
///
/// * `cbor_tag` - The CBOR tag associated with the evidence, which is recorded in the cert.
/// * `raw_evidence` - The raw evidence data. It may be maliciously constructed and should be carefully validated.
///
/// # Returns
///
/// - `None` if the provided raw evidence is not supported by this TEE type.
/// - `Some(Result<SgxDcapEvidence>)`:
///   - `Ok(SgxDcapEvidence)` if the evidence is supported and passes integrity checks.
///   - `Err(Error)` if the evidence is supported but fails integrity checks or is an unsupported version.

pub(crate) fn create_evidence_from_dice(
    cbor_tag: u64,
    raw_evidence: &[u8],
) -> Option<Result<SgxDcapEvidence>> {
    if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE {
        return Some(SgxDcapEvidence::new_from_unchecked(raw_evidence));
    } else if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT {
        return Some(Err(Error::kind_with_msg(
            ErrorKind::SgxDcapUnsupportedEvidenceType,
            "Unsupported evidence type: Intel TEE report (TDX report or SGX report type 2)",
        )));
    }
    return None;
}
