use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::json;

use self::as_api::attestation_request::RuntimeData;
use self::as_api::attestation_service_client::AttestationServiceClient;
use self::as_api::AttestationRequest;
use self::as_api::AttestationResponse;
use super::super::evidence::{CocoAsToken, CocoEvidence};
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
    as_addr: String,
    policy_ids: Vec<String>,
}

impl CocoGrpcConverter {
    pub fn new(as_addr: &str, policy_ids: &Vec<String>) -> Result<Self> {
        Ok(Self {
            as_addr: as_addr.to_string(),
            policy_ids: policy_ids.to_owned(),
        })
    }
}

#[async_trait::async_trait]
impl GenericConverter for CocoGrpcConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!(
            "Convert CoCo evidence to CoCo AS token via grpc-as with policy ids: {:?}",
            self.policy_ids
        );

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let request = tonic::Request::new(AttestationRequest {
            tee: in_evidence
                .get_tee_type()
                .as_attestation_service_str_id()
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

        let mut client = async {
            Ok::<_, anyhow::Error>(AttestationServiceClient::new(
                #[cfg(not(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                )))]
                tonic::transport::Endpoint::new(self.as_addr.to_string())?
                    .connect()
                    .await?,
                #[cfg(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                ))]
                tonic_web_wasm_client::Client::new(self.as_addr.to_string()),
            ))
        }
        .await
        .with_context(|| format!("Failed to connect grpc-as address `{}`", self.as_addr))?;

        let fut = async move {
            let response: AttestationResponse = client
                .attestation_evaluate(request)
                .await
                .map_err(IntoRatsError::into_rats_error)
                .context("Call attestation_evaluate() on grpc-as failed")?
                .into_inner();
            Ok::<_, anyhow::Error>(response)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the tonic Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Sen. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let response = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(anyhow::Error::from)
            .and_then(|e| e)?;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let response = fut.await?;

        let attestation_token = response.attestation_token;

        Ok(CocoAsToken::new(attestation_token)?)
    }
}
