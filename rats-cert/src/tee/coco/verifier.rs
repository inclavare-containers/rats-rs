use super::evidence::{CocoAsToken, CocoEvidence};
use crate::{errors::*, tee::GenericVerifier};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{debug, error, trace, warn};
use pkcs8::der::{Decode, DecodePem, Encode};
use pkcs8::EncodePublicKey;
use serde_json::Value;
use signature::Verifier;
use webpki::{EndEntityCert, TlsServerTrustAnchors, TrustAnchor};

use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::sync::Mutex;

// TODO: rewrite with RustCrypto and jwt crate

pub struct CocoVerifier {
    /// The trusted certs list used for validating JWT. Each of the certs are encoded in DER binary.
    trusted_certs: Option<Vec<Vec<u8>>>,
    /// The policy ids need to check
    policy_ids: Vec<String>,
}

static SUPPORTED_SIG_ALGS: &'static [&'static webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

impl CocoVerifier {
    pub fn new(
        trusted_certs_paths: &Option<Vec<String>>,
        policy_ids: &Vec<String>,
    ) -> Result<Self> {
        let trusted_certs = match trusted_certs_paths {
            Some(paths) => {
                let mut trusted_certs = vec![];
                for path in paths {
                    let trust_cert_pem = std::fs::read(path)
                        .kind(ErrorKind::InvalidParameter)
                        .with_context(|| {
                            format!("Load trusted certificate from `{}` failed", path)
                        })?;
                    let der = x509_cert::Certificate::from_pem(trust_cert_pem)?.to_der()?;
                    trusted_certs.push(der);
                }
                Some(trusted_certs)
            }
            None => None,
        };

        Ok(Self {
            trusted_certs,
            policy_ids: policy_ids.to_owned(),
        })
    }

    fn verify_evidence_internal(&self, evidence: &CocoAsToken, report_data: &[u8]) -> Result<()> {
        let token = evidence.as_str();
        debug!(
            "Verify CoCo AS token \"{token}\" with policy ids: {:?}",
            self.policy_ids
        );
        let split_token: Vec<&str> = token.split('.').collect();
        if !split_token.len() == 3 {
            return Err(Error::msg("Illegal JWT format"));
        }

        let header = URL_SAFE_NO_PAD.decode(split_token[0])?;
        let claims = URL_SAFE_NO_PAD.decode(split_token[1])?;
        let signature = URL_SAFE_NO_PAD.decode(split_token[2])?;

        let header_value = serde_json::from_slice::<Value>(&header)?;
        let claims_value = serde_json::from_slice::<Value>(&claims)?;

        /* Check report_data matchs */
        let runtime_data_expected = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;

        let runtime_data_in_token = serde_json::to_string(
            claims_value
                .get("customized_claims")
                .map(|o| o.as_object())
                .flatten()
                .map(|o| o.get("runtime_data"))
                .flatten()
                .ok_or_else(|| Error::msg("Can not found `runtime_data` in CoCo AS token"))?,
        )
        .context("Failed to serialize runtime_data got from token")?;

        if runtime_data_expected != runtime_data_in_token {
            return Err(Error::msg("runtime_data mismatch"));
        }

        /* Check timestamp of JWT */
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let Some(exp) = claims_value["exp"].as_i64() else {
            return Err(Error::msg("token expiration unset"));
        };
        if exp < now {
            return Err(Error::msg(format!(
                "token expired, current timestamp: {now} exp: {exp}"
            )));
        }
        if let Some(nbf) = claims_value["nbf"].as_i64() {
            if now < nbf {
                if now + 5 >= nbf {
                    warn!(
                        "The token is {}s (<5s) before validity, but is tolerated",
                        nbf - now
                    );
                } else {
                    return Err(Error::msg(format!(
                        "token is before validity, current timestamp: {now} nbf: {nbf}"
                    )));
                }
            }
        }

        /* Check signature of JWT */
        let jwk_value = claims_value["jwk"].as_object().ok_or_else(|| Error::msg(
            "CoCo Attestation Token Claims must contain public key (JWK format) to verify signature",
        ))?;
        let jwk = serde_json::to_string(&jwk_value)?;
        let rsa_jwk = serde_json::from_str::<RsaJWK>(&jwk)?;
        let payload = format!("{}.{}", &split_token[0], &split_token[1])
            .as_bytes()
            .to_vec();

        match header_value["alg"].as_str() {
            Some("RS384") => {
                if rsa_jwk.alg != *"RS384" {
                    return Err(Error::msg("Unmatched RSA JWK alg"));
                }
                rs384_verify(&payload, &signature, &rsa_jwk).context("RS384 verify failed")?;
            }
            None => {
                return Err(Error::msg("Miss `alg` in JWT header"));
            }
            _ => {
                return Err(Error::msg("Unsupported JWT algrithm"));
            }
        }

        /* Check that the key used for signing the JWT is valid */
        match &self.trusted_certs {
            None => {
                log::warn!("No trusted certificate provided, skip verification of JWK cert of Attestation Token");
            }
            Some(trusted_certs) => {
                let mut cert_chain_der: Vec<_> = vec![];

                /* Get certificate chain from 'x5c' or 'x5u' in JWK. */
                if let Some(x5c) = rsa_jwk.x5c {
                    for base64_der_cert in x5c {
                        cert_chain_der.push(URL_SAFE_NO_PAD.decode(base64_der_cert)?);
                    }
                } else if let Some(x5u) = rsa_jwk.x5u {
                    for c in download_cert_chain(x5u)?.iter() {
                        cert_chain_der.push(c.to_der()?);
                    }
                }

                if cert_chain_der.len() < 1 {
                    return Err(Error::msg("Missing certificate in Attestation Token JWK"));
                }

                /* Check certificate is valid and trustworthy */
                let end_entity_cert = EndEntityCert::try_from(cert_chain_der[0].as_slice())?;
                let mut intermediate_certs = vec![];
                for cert in cert_chain_der.iter().skip(1) {
                    intermediate_certs.push(cert.as_slice());
                }

                let mut trust_anchors = vec![];
                for der in trusted_certs.iter() {
                    trust_anchors.push(TrustAnchor::try_from_cert_der(&der)?);
                }

                let now = webpki::Time::try_from(std::time::SystemTime::now())?;
                end_entity_cert
                    .verify_is_valid_tls_server_cert(
                        SUPPORTED_SIG_ALGS,
                        &TlsServerTrustAnchors(&trust_anchors),
                        &intermediate_certs,
                        now,
                    )
                    .context("Untrusted certificate in Attestation Token JWK")?;

                /* Check the public key in JWK is consistent with the public key in certificate */
                let n = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&rsa_jwk.n)?);
                let e = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&rsa_jwk.e)?);
                let jwt_pubkey_spki = rsa::RsaPublicKey::new(n, e)?
                    .to_public_key_der()?
                    .to_der()?;

                let cert_pubkey_spki =
                    x509_cert::Certificate::from_der(cert_chain_der[0].as_slice())?
                        .tbs_certificate
                        .subject_public_key_info
                        .to_der()?;

                if cert_pubkey_spki != jwt_pubkey_spki {
                    return Err(Error::msg(
                        "Certificate Public Key Mismatched in Attestation Token",
                    ));
                }
            }
        }

        /* Check the evaluation-reports.
         * The content format of evaluation-reports is documented here: https://github.com/confidential-containers/trustee/blob/43d56f3a4a92a1cc691f63a8e1311bcc0d2b3fc8/attestation-service/docs/example.token.json#L6
         */
        let allowed_policy_ids = claims_value
                .get("evaluation-reports")
                .map(|o| o.as_array())
                .flatten()
                .ok_or_else(|| Error::msg("Can not found `evaluation-reports` array in CoCo AS token"))?
                .iter()
                .enumerate()
                .map(|(i, o)| -> Result<_> {
                    debug!("evaluation-reports[{i}]: {o}");
                    let policy_id =  o.get("policy-id")
                        .ok_or_else(|| {
                            Error::msg(format!(
                                "Can not found `policy-id` in evaluation-reports[{i}]: {o}"
                            ))
                        })?.as_str().ok_or_else(|| {
                            Error::msg(format!(
                                "The value of `policy-id` should be a string type in evaluation-reports[{i}]: {o}"
                            ))
                        })?;
                    Ok(policy_id)
                }).collect::<Result<HashSet<_>>>()?;

        /* We accept the token only when all of the expected policy ids has { "allow": true } */
        for policy_id in &self.policy_ids {
            if !allowed_policy_ids.contains(policy_id.as_str()) {
                return Err(Error::msg(format!(
                    "The token is not acceptable due to evaluation failure on policy_id `{policy_id}`"
                )));
            }
        }

        Ok(())
    }
}

impl GenericVerifier for CocoVerifier {
    type Evidence = CocoAsToken;

    fn verify_evidence(&self, evidence: &Self::Evidence, report_data: &[u8]) -> Result<()> {
        self.verify_evidence_internal(evidence, report_data)
            .context("Failed to verify CoCo AS token")
            .map_err(|e| {
                if e.get_kind() == ErrorKind::Unknown {
                    e.with_kind(ErrorKind::CocoVerifyTokenFailed)
                } else {
                    e
                }
            })
    }
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Clone, Debug)]
struct RsaJWK {
    kty: String,
    alg: String,
    n: String,
    e: String,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
}

// RS384 - RSA PKCS#1 signature with SHA-384
fn rs384_verify(payload: &[u8], signature: &[u8], jwk: &RsaJWK) -> Result<()> {
    let n = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.n)?);
    let e = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.e)?);

    let verify_key =
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(rsa::RsaPublicKey::new(n, e)?);
    verify_key.verify(payload, &signature.try_into()?)?;

    Ok(())
}

fn download_cert_chain(url: String) -> Result<Vec<x509_cert::Certificate>> {
    let res = reqwest::blocking::get(url)?;
    match res.status() {
        reqwest::StatusCode::OK => {
            let pem_cert_chain = res.text()?;
            return Ok(x509_cert::Certificate::load_pem_chain(
                pem_cert_chain.as_bytes(),
            )?);
        }
        _ => {
            return Err(Error::msg(format!(
                "Request x5u in Attestation Token JWK Failed, Response: {:?}",
                res.text()?,
            )));
        }
    }
}
