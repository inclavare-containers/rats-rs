use log::error;

use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::{
    cert::dice::cbor::OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE,
    tee::{GenericEvidence, TeeType},
};
use intel_dcap::{
    sgx_quote4_header_t, sgx_quote4_t, sgx_quote5_t, sgx_report2_body_t, sgx_report2_body_v1_5_t,
};

/// This `TdxEvidence` struct Represents an TDX quote of version 4 or version 5
///
/// The `data` field stores a vector of bytes representing the TDX quote of version 4 or version 5.
/// And it is ensured that the length of the `data` vector is properly checked to avoid memory safety issues.
#[derive(Debug)]
pub struct TdxEvidence {
    data: Vec<u8>,
}

pub enum Quote<'a> {
    /// quote4 TDX quote
    Quote4(&'a sgx_quote4_t),
    /// quote5 with TDX 1.0
    Quote5Tdx10(&'a sgx_quote5_t, &'a sgx_report2_body_t),
    /// quote5 with TDX 1.5
    Quote5Tdx15(&'a sgx_quote5_t, &'a sgx_report2_body_v1_5_t),
}

impl TdxEvidence {
    pub(crate) fn new_from_trusted(checked_quote: Vec<u8>) -> Result<Self> {
        Ok(Self {
            data: checked_quote,
        })
    }

    pub fn new_from_untrusted(unchecked_quote: &[u8]) -> Result<Self> {
        if unchecked_quote.len() < std::mem::size_of::<sgx_quote4_header_t>() {
            return Err(Error::kind_with_msg(
                ErrorKind::TdxMulformedQuote,
                format!(
                    "Invalid quote: quote length {} is too short",
                    unchecked_quote.len()
                ),
            ));
        }

        let header = unsafe { &*(unchecked_quote.as_ptr() as *const sgx_quote4_header_t) };
        if header.version == 4 && header.tee_type == 0x81 {
            if unchecked_quote.len() < std::mem::size_of::<sgx_quote4_t>() {
                return Err(Error::kind_with_msg(
                    ErrorKind::TdxMulformedQuote,
                    format!(
                        "Invalid quote: quote length {} is too short",
                        unchecked_quote.len()
                    ),
                ));
            }

            let quote = unsafe { &*(unchecked_quote.as_ptr() as *const sgx_quote4_t) };
            let expected_quote_len =
                std::mem::size_of::<sgx_quote4_t>() + quote.signature_data_len as usize;
            if unchecked_quote.len() != expected_quote_len {
                Err(Error::kind_with_msg(
                ErrorKind::TdxMulformedQuote,
                format!(
                    "Invalid TDX quote version 4: quote length mismatch and probably got truncated, unchecked_quote.len(): {}, expected: {}",
                    unchecked_quote.len(), expected_quote_len),
                ))?;
            }
        } else if header.version == 5 && header.tee_type == 0x81 {
            if unchecked_quote.len() < std::mem::size_of::<sgx_quote5_t>() {
                return Err(Error::kind_with_msg(
                    ErrorKind::TdxMulformedQuote,
                    format!(
                        "Invalid TDX quote version 5: quote length {} is too short",
                        unchecked_quote.len()
                    ),
                ));
            }

            let quote = unsafe { &*(unchecked_quote.as_ptr() as *const sgx_quote5_t) };

            let tee_report_type = quote.type_;
            if tee_report_type == 2 {
                /* quote5 with TDX 1.0 */
                if std::mem::size_of::<sgx_report2_body_t>() != (quote.size as usize)
                    || unchecked_quote.len()
                        < std::mem::offset_of!(sgx_quote5_t, body)
                            + std::mem::size_of::<sgx_report2_body_t>()
                            + std::mem::size_of::<u32>()
                    || unchecked_quote.len()
                        != std::mem::offset_of!(sgx_quote5_t, body)
                            + std::mem::size_of::<sgx_report2_body_t>()
                            + std::mem::size_of::<u32>()
                            + unsafe {
                                core::ptr::read_unaligned(
                                    quote
                                        .body
                                        .as_ptr()
                                        .byte_add(std::mem::size_of::<sgx_report2_body_t>())
                                        as *const u32,
                                )
                            } as usize
                {
                    /* sgx_report2_body_t + (uint32_t)signature_data_len + signature */
                    Err(Error::kind_with_msg(
                            ErrorKind::TdxMulformedQuote,
                                "Invalid TDX 1.0 quote version 5: quote length mismatch and probably got truncated",
                            ))?;
                }
            } else if tee_report_type == 3 {
                /* quote5 with TDX 1.5 */
                if std::mem::size_of::<sgx_report2_body_v1_5_t>() != (quote.size as usize)
                    || unchecked_quote.len()
                        < std::mem::offset_of!(sgx_quote5_t, body)
                            + std::mem::size_of::<sgx_report2_body_v1_5_t>()
                            + std::mem::size_of::<u32>()
                    || unchecked_quote.len()
                        != std::mem::offset_of!(sgx_quote5_t, body)
                            + std::mem::size_of::<sgx_report2_body_v1_5_t>()
                            + std::mem::size_of::<u32>()
                            + unsafe {
                                core::ptr::read_unaligned(
                                    quote
                                        .body
                                        .as_ptr()
                                        .byte_add(std::mem::size_of::<sgx_report2_body_v1_5_t>())
                                        as *const u32,
                                )
                            } as usize
                {
                    /* sgx_report2_body_v1_5_t + (uint32_t)signature_data_len + signature */
                    Err(Error::kind_with_msg(
                            ErrorKind::TdxMulformedQuote,
                                "Invalid TDX 1.5 quote version 5: quote length mismatch and probably got truncated",
                            ))?;
                }
            } else {
                return Err(Error::kind_with_msg(
                    ErrorKind::TdxUnsupportedEvidenceType,
                    format!("unsupoorted quote body type {tee_report_type}"),
                ));
            }
        } else {
            let version = header.version;
            let att_key_type = header.att_key_type;
            let tee_type = header.tee_type;

            return Err(Error::kind_with_msg(
                ErrorKind::TdxUnsupportedEvidenceType,
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

    pub(crate) fn as_quote(&self) -> Result<Quote> {
        unsafe {
            let p_quote = self.data.as_ptr();
            let quote_header = &*(p_quote as *const sgx_quote4_header_t);
            if quote_header.version == 4 {
                let quote = &*(p_quote as *const sgx_quote4_t);
                return Ok(Quote::Quote4(quote));
            } else if quote_header.version == 5 {
                let quote = &*(p_quote as *const sgx_quote5_t);
                let tee_report_type = quote.type_;
                if tee_report_type == 2 {
                    /* quote5 with TDX 1.0 */
                    let report_body = &*(quote.body.as_ptr() as *const sgx_report2_body_t);
                    return Ok(Quote::Quote5Tdx10(quote, report_body));
                } else if tee_report_type == 3 {
                    /* quote5 with TDX 1.5 */
                    let report_body = &*(quote.body.as_ptr() as *const sgx_report2_body_v1_5_t);
                    return Ok(Quote::Quote5Tdx15(quote, report_body));
                } else {
                    return Err(Error::kind_with_msg(
                        ErrorKind::TdxUnsupportedEvidenceType,
                        format!("unsupoorted quote body type {tee_report_type}"),
                    ));
                }
            } else {
                let version = quote_header.version;
                return Err(Error::kind_with_msg(
                    ErrorKind::TdxUnsupportedEvidenceType,
                    format!("unsupoorted quote version {version}"),
                ));
            }
        }
    }

    pub(crate) fn as_quote_data(&self) -> &[u8] {
        return &self.data;
    }

    pub(crate) fn get_report_data_field(&self) -> Result<&[u8]> {
        let quote = self.as_quote()?;
        Ok(match quote {
            Quote::Quote4(quote) => &quote.report_body.report_data.d,
            Quote::Quote5Tdx10(_, report_body) => &report_body.report_data.d,
            Quote::Quote5Tdx15(_, report_body) => &report_body.report_data.d,
        })
    }
}

impl GenericEvidence for TdxEvidence {
    fn get_dice_raw_evidence(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE
    }

    fn get_tee_type(&self) -> TeeType {
        TeeType::Tdx
    }

    fn get_claims(&self) -> Result<Claims> {
        self.gen_claims_from_quote()
    }
}

/// Creates TdxEvidence from DICE cert data.
///
/// # Arguments
///
/// * `cbor_tag` - The CBOR tag associated with the evidence, which is recorded in the cert.
/// * `raw_evidence` - The raw evidence data. It may be maliciously constructed and should be carefully validated.
///
/// # Returns
///
/// - `None` if the provided raw evidence is not supported by this TEE type.
/// - `Some(Result<TdxEvidence>)`:
///   - `Ok(TdxEvidence)` if the evidence is supported and passes integrity checks.
///   - `Err(Error)` if the evidence is supported but fails integrity checks or is an unsupported version.

pub(crate) fn create_evidence_from_dice(
    cbor_tag: u64,
    raw_evidence: &[u8],
) -> Option<Result<TdxEvidence>> {
    if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE {
        return Some(TdxEvidence::new_from_untrusted(raw_evidence));
    } else if cbor_tag == OCBR_TAG_EVIDENCE_INTEL_TEE_REPORT {
        return Some(Err(Error::kind_with_msg(
            ErrorKind::TdxUnsupportedEvidenceType,
            "Unsupported evidence type: Intel TEE report (TDX report or SGX report type 2)",
        )));
    }
    return None;
}
