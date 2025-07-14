use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;

use super::super::evidence::{CocoAsToken, CocoEvidence};
use super::AttestationServiceHashAlgo;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::GenericConverter;
use crate::tee::GenericEvidence;
use crate::tee::TeeType;

pub struct CocoRestfulConverter {
    as_addr: String,
    policy_ids: Vec<String>,
    client: Client,
}

impl CocoRestfulConverter {
    pub fn new(as_addr: &str, policy_ids: &Vec<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("rats-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            as_addr: as_addr.trim_end_matches('/').to_owned(),
            client,
            policy_ids: policy_ids.to_owned(),
        })
    }
}

// Copy from https://github.com/confidential-containers/trustee/blob/7dbd42f0baeb3d26d75d43ab73b29a168d584472/attestation-service/attestation-service/src/bin/restful/mod.rs#L36-L45
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    tee: String,
    evidence: String,
    runtime_data: Option<Data>,
    init_data: Option<Data>,
    runtime_data_hash_algorithm: Option<String>,
    init_data_hash_algorithm: Option<String>,
    policy_ids: Vec<String>,
}

// Copy from https://github.com/confidential-containers/trustee/blob/7dbd42f0baeb3d26d75d43ab73b29a168d584472/attestation-service/attestation-service/src/bin/restful/mod.rs#L55-L60
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Data {
    Raw(String),
    Structured(Value),
}

#[async_trait::async_trait]
impl GenericConverter for CocoRestfulConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        tracing::debug!(
            "Convert CoCo evidence to CoCo AS token via restful-as with policy ids: {:?}",
            self.policy_ids
        );

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let url = format!("{}/attestation", self.as_addr);
        let body = AttestationRequest {
            tee: in_evidence
                .get_tee_type()
                .as_attestation_service_str_id()
                .to_owned(),
            evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
            init_data: None, // TODO: add support for init_data when support on AA is ready
            init_data_hash_algorithm: None,
            policy_ids: self.policy_ids.clone(),
            runtime_data: Some(Data::Structured(serde_json::from_str(
                in_evidence.aa_runtime_data_ref(),
            )?)),
            runtime_data_hash_algorithm: Some(runtime_data_hash_algorithm.into()),
        };
        let client = self.client.clone();

        let fut = async move {
            let response = client
                .post(url)
                .json(&body)
                .send()
                .await
                .context("Send /attestation request to restful-as failed")?;

            let status = response.status();
            let text = response
                .text()
                .await
                .context("Failed to read attestation_token from restful-as response")?;
            Ok::<_, anyhow::Error>((status, text))
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        // In wasm32 (web), the reqwest Response future is not `Send` but #[async_trait::async_trait] requires the function body to be Sen. So we have to spawn it with tokio_with_wasm::task::spawn and await for it.
        let (status, text) = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(anyhow::Error::from)
            .and_then(|e| e)?;
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let (status, text) = fut.await?;

        let attestation_token = match status {
            reqwest::StatusCode::OK => text,
            _ => {
                return Err(Error::msg(format!(
                    "Error returned from restful-as. status: {} response: {}",
                    status, text,
                )));
            }
        };

        Ok(CocoAsToken::new(attestation_token)?)
    }
}
