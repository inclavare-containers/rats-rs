use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::debug;
use serde_json::json;
use tokio::runtime::Runtime;

use self::as_api::attestation_request::RuntimeData;
use self::as_api::attestation_service_client::AttestationServiceClient;
use self::as_api::AttestationRequest;
use self::as_api::AttestationResponse;
use super::super::evidence::{CocoAsToken, CocoEvidence};
use super::AttestationAgentTeeType;
use super::AttestationServiceHashAlgo;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::GenericConverter;
use crate::tee::GenericEvidence;
use crate::tee::TeeType;

pub mod as_api {
    tonic::include_proto!("attestation");
}

pub struct CocoGrpcConverter {
    tokio_rt: Runtime,
    client: Mutex<AttestationServiceClient<tonic::transport::Channel>>,
    policy_ids: Vec<String>,
}

impl CocoGrpcConverter {
    pub fn new(as_addr: &str, policy_ids: &Vec<String>) -> Result<Self> {
        let tokio_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // TODO: change to .await when async in rats-rs is ready
        let client = Mutex::new(
            tokio_rt
                .block_on(AttestationServiceClient::connect(as_addr.to_string()))
                .with_context(|| format!("Failed to connect grpc-as address `{as_addr}`",))?,
        );

        Ok(Self {
            tokio_rt,
            client,
            policy_ids: policy_ids.to_owned(),
        })
    }
}

impl GenericConverter for CocoGrpcConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        debug!(
            "Convert CoCo evidence to CoCo AS token via grpc-as with policy ids: {:?}",
            self.policy_ids
        );

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let request = tonic::Request::new(AttestationRequest {
            tee: Into::<AttestationAgentTeeType>::into(in_evidence.get_tee_type())
                .str_id()
                .to_owned(),
            evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
            init_data: None, // TODO: add support for init_data when support on AA is ready
            init_data_hash_algorithm: "".into(),
            policy_ids: self.policy_ids.clone(),
            runtime_data: Some(RuntimeData::StructuredRuntimeData(
                in_evidence.aa_runtime_data_ref().into(),
            )),
            runtime_data_hash_algorithm: runtime_data_hash_algorithm.into(),
        });

        let mut client = self.client.lock()?;
        let response: AttestationResponse = self
            .tokio_rt
            .block_on(client.attestation_evaluate(request))
            .context("Call attestation_evaluate() on grpc-as failed")?
            .into_inner();

        let attestation_token = response.attestation_token;

        Ok(CocoAsToken::new(attestation_token)?)
    }
}
