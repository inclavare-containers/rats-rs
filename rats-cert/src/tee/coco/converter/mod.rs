use grpc::CocoGrpcConverter;
use restful::CocoRestfulConverter;
use serde::{Deserialize, Serialize};

use super::evidence::{CocoAsToken, CocoEvidence};
use crate::errors::*;
use crate::{
    crypto::HashAlgo,
    tee::{GenericConverter, TeeType},
};

pub mod grpc;
pub mod restful;

#[derive(Serialize, Deserialize)]
pub(crate) enum AttestationServiceHashAlgo {
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha384")]
    Sha384,
    #[serde(rename = "sha512")]
    Sha512,
}

impl AttestationServiceHashAlgo {
    pub fn str_id(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

impl From<HashAlgo> for AttestationServiceHashAlgo {
    fn from(hash_algo: HashAlgo) -> Self {
        match hash_algo {
            HashAlgo::Sha256 => Self::Sha256,
            HashAlgo::Sha384 => Self::Sha384,
            HashAlgo::Sha512 => Self::Sha512,
        }
    }
}

impl From<AttestationServiceHashAlgo> for HashAlgo {
    fn from(as_hash_algo: AttestationServiceHashAlgo) -> Self {
        match as_hash_algo {
            AttestationServiceHashAlgo::Sha256 => Self::Sha256,
            AttestationServiceHashAlgo::Sha384 => Self::Sha384,
            AttestationServiceHashAlgo::Sha512 => Self::Sha512,
        }
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

    pub async fn get_nonce(&self) -> Result<CoCoNonce> {
        match self {
            CocoConverter::Grpc(converter) => converter.get_nonce().await,
            CocoConverter::Restful(converter) => converter.get_nonce().await,
        }
    }
}

pub enum CoCoNonce {
    Jwt(String),
}

#[async_trait::async_trait]

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        match self {
            CocoConverter::Grpc(converter) => converter.convert(in_evidence).await,
            CocoConverter::Restful(converter) => converter.convert(in_evidence).await,
        }
    }
}
