use std::any::Any;

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

    /// Return the type of Trusted Execution Environment (TEE) associated with the evidence.
    fn get_tee_type(&self) -> TeeType;

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

    /// Verifiy the provided evidence with the Trust Anchor and checking the report data matches the one in the evidence.
    fn verify_evidence(&self, evidence: &Self::Evidence, report_data: &[u8]) -> Result<()>;
}

pub trait GenericConverter {
    type InEvidence: GenericEvidence;
    type OutEvidence: GenericEvidence;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence>;
}

/// Enum representing different types of TEEs.
#[derive(Debug, PartialEq, EnumIter, Clone, Copy)]
pub enum TeeType {
    SgxDcap,
    Tdx,
}

impl TeeType {
    /// Detects the current TEE environment and returns the detected TeeType.
    pub fn detect_env() -> Option<Self> {
        #[cfg(feature = "attester-sgx-dcap")]
        if sgx_dcap::detect_env() {
            return Some(Self::SgxDcap);
        }
        #[cfg(feature = "attester-tdx")]
        if tdx::detect_env() {
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
