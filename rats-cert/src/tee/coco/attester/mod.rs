use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use canon_json::CanonicalFormatter;
use serde::Serialize;
use serde_json::json;

use self::ttrpc_protocol::attestation_agent::{GetEvidenceRequest, GetTeeTypeRequest};
use self::ttrpc_protocol::attestation_agent_ttrpc::AttestationAgentServiceClient;
use super::evidence::AaTeeType;
use super::evidence::CocoEvidence;
use super::TTRPC_DEFAULT_TIMEOUT_NANO;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::{GenericAttester, GenericEvidence, ReportData, TeeType};

mod ttrpc_protocol;

pub struct CocoAttester {
    client: AttestationAgentServiceClient,
    timeout_nano: i64,
}

impl CocoAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout_nano(aa_addr, TTRPC_DEFAULT_TIMEOUT_NANO)
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        // TODO: turn ttrpc client to async client
        let inner = ttrpc::Client::connect(aa_addr)
            .kind(ErrorKind::CocoConnectTtrpcFailed)
            .context(format!(
                "Failed to connect to attestation-agent ttrpc address {}",
                aa_addr
            ))?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self {
            client,
            timeout_nano,
        })
    }
}

fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}

#[async_trait::async_trait]
impl GenericAttester for CocoAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        // Here we wrap rats-rs's report_data to a StructuredRuntimeData instead of RawRuntimeData, so that we can check the value in our verifier. See: https://github.com/confidential-containers/trustee/blob/86a407ecb1bc1897ef8fba5ee59e33e56e11ef4d/attestation-service/attestation-service/src/lib.rs#L245
        let aa_runtime_data = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384; // TODO: make this configable from user

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        // Get evidence from AA
        let get_evidence_req = GetEvidenceRequest {
            RuntimeData: aa_runtime_data_hash_value,
            ..Default::default()
        };
        let get_evidence_res = self
            .client
            .get_evidence(
                ttrpc::context::with_timeout(self.timeout_nano),
                &get_evidence_req,
            )
            .kind(ErrorKind::CocoRequestAAFailed)?;

        // Query tee type from AA
        let get_tee_type_req = GetTeeTypeRequest {
            ..Default::default()
        };
        let get_tee_type_res = self
            .client
            .get_tee_type(
                ttrpc::context::with_timeout(self.timeout_nano),
                &get_tee_type_req,
            )
            .kind(ErrorKind::CocoRequestAAFailed)?;
        let tee_type = AaTeeType::from_attestation_agent_str_id(&get_tee_type_res.tee);

        Ok(CocoEvidence::new(
            tee_type,
            get_evidence_res.Evidence,
            String::from_utf8(aa_runtime_data_bytes)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}
