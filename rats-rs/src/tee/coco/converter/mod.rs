use grpc::CocoGrpcConverter;
use restful::CocoRestfulConverter;

use super::evidence::{CocoAsToken, CocoEvidence};
use crate::errors::*;
use crate::{
    crypto::HashAlgo,
    tee::{GenericConverter, TeeType},
};

pub mod grpc;
pub mod restful;

pub(crate) struct AttestationAgentTeeType(&'static str);

impl AttestationAgentTeeType {
    pub fn str_id(&self) -> &'static str {
        self.0
    }
}

impl From<TeeType> for AttestationAgentTeeType {
    // See https://github.com/confidential-containers/trustee/blob/09bef2e2a53d54c2d3107635a65337f409eeaebe/attestation-service/attestation-service/src/bin/grpc/mod.rs#L29-L41
    fn from(value: TeeType) -> Self {
        AttestationAgentTeeType(match value {
            TeeType::Sample => "sample",
            TeeType::SgxDcap => "sgx",
            TeeType::Tdx => "tdx",
            TeeType::Csv => "csv",
        })
    }
}

pub(crate) struct AttestationServiceHashAlgo(&'static str);

impl AttestationServiceHashAlgo {
    pub fn str_id(&self) -> &'static str {
        self.0
    }
}

impl From<HashAlgo> for AttestationServiceHashAlgo {
    fn from(hash_algo: HashAlgo) -> Self {
        AttestationServiceHashAlgo(match hash_algo {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha384 => "sha384",
            HashAlgo::Sha512 => "sha512",
        })
    }
}

pub enum CocoConverter {
    Grpc(CocoGrpcConverter),
    Restful(CocoRestfulConverter),
}

impl CocoConverter {
    pub fn new(as_addr: &str, policy_ids: &Vec<String>, as_is_grpc: bool) -> Result<Self> {
        Ok(if as_is_grpc {
            Self::Grpc(CocoGrpcConverter::new(&as_addr, &policy_ids)?)
        } else {
            Self::Restful(CocoRestfulConverter::new(&as_addr, &policy_ids)?)
        })
    }
}

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        match self {
            CocoConverter::Grpc(converter) => converter.convert(in_evidence),
            CocoConverter::Restful(converter) => converter.convert(in_evidence),
        }
    }
}
