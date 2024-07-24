use std::{any::Any, path::Path};

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use self::claims::Claims;
use crate::errors::*;

pub mod auto;
pub mod claims;

#[cfg(any(feature = "attester-sgx-dcap", feature = "verifier-sgx-dcap"))]
pub mod sgx_dcap;

#[cfg(any(feature = "attester-tdx", feature = "verifier-tdx"))]
pub mod tdx;

#[cfg(any(feature = "coco"))]
pub mod coco;

pub enum DiceParseEvidenceOutput<T> {
    NotMatch,
    MatchButInvalid(Error),
    Ok(T),
}

impl<T> From<DiceParseEvidenceOutput<T>> for Result<T> {
    fn from(value: DiceParseEvidenceOutput<T>) -> Self {
        match value {
            crate::tee::DiceParseEvidenceOutput::NotMatch => {
                return Err(Error::kind_with_msg(
                    ErrorKind::UnrecognizedEvidenceType,
                    "Unrecognized evidence type",
                ))
            }
            crate::tee::DiceParseEvidenceOutput::MatchButInvalid(e) => return Err(e),
            crate::tee::DiceParseEvidenceOutput::Ok(v) => Ok(v),
        }
    }
}

/// Trait representing generic evidence.
pub trait GenericEvidence: Any {
    /// Return the CBOR tag used for generating DICE cert.
    fn get_dice_cbor_tag(&self) -> u64;

    /// Return the raw evidence data used for generating DICE cert.
    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>>;

    /// Create evidence from cbor tag and raw evidence of a DICE cert.
    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self>
    where
        Self: Sized;

    /// Parse the evidence and return a set of claims.
    fn get_claims(&self) -> Result<Claims>;
}

/// Trait representing a generic attester.
pub trait GenericAttester {
    type Evidence: GenericEvidence;

    /// Generate evidence based on the provided report data.
    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence>;
}

/// Trait representing a generic verifier.
pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    /// Verify the provided evidence with the Trust Anchor and checking the report data matches the one in the evidence.
    fn verify_evidence(&self, evidence: &Self::Evidence, report_data: &[u8]) -> Result<()>;
}

pub trait GenericConverter {
    type InEvidence: GenericEvidence;
    type OutEvidence: GenericEvidence;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence>;
}

pub struct AttesterPipeline<A: GenericAttester, C: GenericConverter<InEvidence = A::Evidence>> {
    attester: A,
    converter: C,
}

impl<A: GenericAttester, C: GenericConverter<InEvidence = A::Evidence>> AttesterPipeline<A, C> {
    pub fn new(attester: A, converter: C) -> Self {
        Self {
            attester,
            converter,
        }
    }
}

impl<A: GenericAttester, C: GenericConverter<InEvidence = A::Evidence>> GenericAttester
    for AttesterPipeline<A, C>
{
    type Evidence = C::OutEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence> {
        let evidence = self.attester.get_evidence(report_data)?;
        self.converter.convert(&evidence)
    }
}

/// Enum representing different types of TEEs.
#[derive(Debug, PartialEq, EnumIter, Clone, Copy)]
pub enum TeeType {
    SgxDcap,
    Tdx,
}

pub fn sgx_dcap_detect_env() -> bool {
    /* We only support occlum now */
    if cfg!(feature = "attester-sgx-dcap-occlum") && std::env::var("OCCLUM").is_ok() {
        return true;
    }
    return false;
}

pub fn tdx_detect_env() -> bool {
    if cfg!(feature = "attester-tdx")
        && (Path::new("/dev/tdx-attest").exists()
            || Path::new("/dev/tdx-guest").exists()
            || Path::new("/dev/tdx_guest").exists())
    {
        return true;
    }
    return false;
}

impl TeeType {
    /// Detects the current TEE environment and returns the detected TeeType.
    pub fn detect_env() -> Option<Self> {
        if sgx_dcap_detect_env() {
            return Some(Self::SgxDcap);
        }
        if tdx_detect_env() {
            return Some(Self::Tdx);
        }
        return None;
    }

    pub fn id_str(&self) -> &'static str {
        match self {
            TeeType::SgxDcap => "sgx-dcap",
            TeeType::Tdx => "tdx",
        }
    }

    pub fn from_id_str(id_str: &str) -> Result<Self> {
        for tee_type in TeeType::iter() {
            if tee_type.id_str().eq(id_str) {
                return Ok(tee_type);
            }
        }
        return Err(Error::kind_with_msg(
            ErrorKind::UnsupportedTeeType,
            format!("Unknown tee type id_str `{id_str}`"),
        ));
    }
}
