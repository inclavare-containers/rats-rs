use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use self::as_api::attestation_request::RuntimeData;
use self::as_api::attestation_service_client::AttestationServiceClient;
use super::evidence::{CocoAsToken, CocoEvidence};
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::coco::converter::as_api::AttestationRequest;
use crate::tee::coco::converter::as_api::AttestationResponse;
use crate::tee::coco::converter::as_api::Tee as GrpcTee;
use crate::tee::GenericConverter;
use crate::tee::GenericEvidence;
use crate::tee::TeeType;

pub mod as_api {
    tonic::include_proto!("attestation");
}

pub struct CocoConverter {
    client: Mutex<AttestationServiceClient<tonic::transport::Channel>>,
    policy_ids: Vec<String>,
}

impl CocoConverter {
    pub fn new(as_addr: &str, policy_ids: &Vec<String>) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // TODO: change to .await when async in rats-rs is ready
        let client = Mutex::new(
            rt.block_on(AttestationServiceClient::connect(as_addr.to_string()))
                .with_context(|| {
                    format!("Failed to connect attestation-service grpc address {as_addr}",)
                })?,
        );

        Ok(Self {
            client,
            policy_ids: policy_ids.to_owned(),
        })
    }
}

impl From<TeeType> for GrpcTee {
    fn from(value: TeeType) -> Self {
        match value {
            TeeType::SgxDcap => GrpcTee::Sgx,
            TeeType::Tdx => GrpcTee::Tdx,
        }
    }
}

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        let runtime_data_hash_algorithm = match in_evidence.get_aa_runtime_data_hash_algo() {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha384 => "sha384",
            HashAlgo::Sha512 => "sha512",
        };

        let request = tonic::Request::new(AttestationRequest {
            tee: Into::<GrpcTee>::into(in_evidence.get_tee_type()).into(),
            evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
            init_data: None, // TODO: add support for init_data when support on AA is ready
            init_data_hash_algorithm: "".into(),
            policy_ids: self.policy_ids.clone(),
            runtime_data: Some(RuntimeData::StructuredRuntimeData(
                in_evidence.aa_runtime_data_ref().into(),
            )),
            runtime_data_hash_algorithm: runtime_data_hash_algorithm.into(),
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut client = self.client.lock()?;
        let response: AttestationResponse = rt
            .block_on(client.attestation_evaluate(request))
            .context("Call attestation_evaluate() on AS via grpc failed")?
            .into_inner();

        let attestation_token = response.attestation_token;

        Ok(CocoAsToken::new(attestation_token)?)
    }
}
