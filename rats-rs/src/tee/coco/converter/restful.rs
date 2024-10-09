use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::debug;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use tokio::runtime::Runtime;

use super::super::evidence::{CocoAsToken, CocoEvidence};
use super::AttestationAgentTeeType;
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
        let client = reqwest::blocking::Client::builder()
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

impl GenericConverter for CocoRestfulConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;

    fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        debug!(
            "Convert CoCo evidence to CoCo AS token via restful-as with policy ids: {:?}",
            self.policy_ids
        );

        let runtime_data_hash_algorithm =
            AttestationServiceHashAlgo::from(in_evidence.get_aa_runtime_data_hash_algo()).str_id();

        let response = self
            .client
            .post(format!("{}/attestation", self.as_addr))
            .json(&AttestationRequest {
                tee: Into::<AttestationAgentTeeType>::into(in_evidence.get_tee_type())
                    .str_id()
                    .to_owned(),
                evidence: URL_SAFE_NO_PAD.encode(in_evidence.aa_evidence_ref()),
                init_data: None, // TODO: add support for init_data when support on AA is ready
                init_data_hash_algorithm: None,
                policy_ids: self.policy_ids.clone(),
                runtime_data: Some(Data::Structured(serde_json::from_str(
                    in_evidence.aa_runtime_data_ref(),
                )?)),
                runtime_data_hash_algorithm: Some(runtime_data_hash_algorithm.into()),
            })
            .send()
            .context("Send /attestation request to restful-as failed")?;

        let attestation_token = match response.status() {
            reqwest::StatusCode::OK => response
                .text()
                .context("Failed to read attestation_token from restful-as response")?,
            _ => {
                return Err(Error::msg(format!(
                    "Error returned from restful-as. status: {} response: {:?}",
                    response.status(),
                    response.text()?,
                )));
            }
        };

        Ok(CocoAsToken::new(attestation_token)?)
    }
}
