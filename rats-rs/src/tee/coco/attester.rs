use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use super::ttrpc_protocol::attestation_agent::GetEvidenceRequest;
use super::TTRPC_DEFAULT_TIMEOUT;
use super::{
    evidence::CocoEvidence, ttrpc_protocol::attestation_agent_ttrpc::AttestationAgentServiceClient,
};
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::{GenericAttester, GenericEvidence, TeeType};

pub struct CocoAttester {
    client: AttestationAgentServiceClient,
    timeout: i64,
}

impl CocoAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout(aa_addr, TTRPC_DEFAULT_TIMEOUT)
    }

    pub fn new_with_timeout(aa_addr: &str, timeout: i64) -> Result<Self> {
        let inner = ttrpc::Client::connect(aa_addr)
            .kind(ErrorKind::CocoConnectTtrpcFailed)
            .context(format!(
                "Failed to connect to attestation-agent ttrpc address {}",
                aa_addr
            ))?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self { client, timeout })
    }
}

impl GenericAttester for CocoAttester {
    type Evidence = CocoEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<CocoEvidence> {
        // Here we wrap rats-rs's report_data to a StructuredRuntimeData instead of RawRuntimeData, so that we can check the value in our verifier. See: https://github.com/confidential-containers/trustee/blob/86a407ecb1bc1897ef8fba5ee59e33e56e11ef4d/attestation-service/attestation-service/src/lib.rs#L245
        let aa_runtime_data = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384; // TODO: make this configable from user

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, aa_runtime_data.as_bytes());

        let req = GetEvidenceRequest {
            RuntimeData: aa_runtime_data_hash_value,
            ..Default::default()
        };
        let res = self
            .client
            .get_evidence(ttrpc::context::with_timeout(self.timeout), &req)
            .kind(ErrorKind::CocoRequestAAFailed)?;

        // This is a workaround, since rats-rs attester is running in the same TEE instance as AA.
        // TODO: get tee type from AA
        let tee_type = TeeType::detect_env().ok_or(Error::kind_with_msg(
            ErrorKind::UnsupportedTeeType,
            format!("Cannot detect the tee type of environment"),
        ))?;

        Ok(CocoEvidence::new(
            tee_type,
            res.Evidence,
            aa_runtime_data,
            aa_runtime_data_hash_algo,
        )?)
    }
}
