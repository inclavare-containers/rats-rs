use super::evidence::{CocoAsToken, CocoEvidence};
use crate::{errors::*, tee::GenericVerifier};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{debug, error, trace, warn};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509};
use serde_json::Value;

use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::sync::Mutex;

// TODO: rewrite with RustCrypto and jwt crate

pub struct CocoVerifier {
    /// The trusted certs list used for validating JWT
    trusted_certs: Option<X509Store>,
    /// The policy ids need to check
    policy_ids: Vec<String>,
}

impl CocoVerifier {
    pub fn new(
        trusted_certs_paths: &Option<Vec<String>>,
        policy_ids: &Vec<String>,
    ) -> Result<Self> {
        let trusted_certs = match trusted_certs_paths {
            Some(paths) => {
                let mut store_builder = X509StoreBuilder::new()?;
                for path in paths {
                    let trust_cert_pem = std::fs::read(path)
                        .kind(ErrorKind::InvalidParameter)
                        .with_context(|| {
                            format!("Load trusted certificate from `{}` failed", path)
                        })?;
                    let trust_cert = X509::from_pem(&trust_cert_pem)?;
                    store_builder.add_cert(trust_cert.to_owned())?;
                }
                Some(store_builder.build())
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
                rs384_verify(&payload, &signature, &rsa_jwk)?;
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
            Some(trusted_store) => {
                let mut cert_chain: Vec<X509> = vec![];

                /* Get certificate chain from 'x5c' or 'x5u' in JWK. */
                if let Some(x5c) = rsa_jwk.x5c {
                    for base64_der_cert in x5c {
                        let der_cert = URL_SAFE_NO_PAD.decode(base64_der_cert)?;
                        let cert = X509::from_der(&der_cert)?;
                        cert_chain.push(cert)
                    }
                } else if let Some(x5u) = rsa_jwk.x5u {
                    download_cert_chain(x5u, &mut cert_chain)?;
                } else {
                    return Err(Error::msg("Missing certificate in Attestation Token JWK"));
                }

                /* Check certificate is valid and trustworthy */
                let mut untrusted_stack = Stack::<X509>::new()?;
                for cert in cert_chain.iter().skip(1) {
                    untrusted_stack.push(cert.clone())?;
                }
                let mut context = X509StoreContext::new()?;
                if !context.init(trusted_store, &cert_chain[0], &untrusted_stack, |ctx| {
                    ctx.verify_cert()
                })? {
                    return Err(Error::msg("Untrusted certificate in Attestation Token JWK"));
                };

                /* Check the public key in JWK is consistent with the public key in certificate */
                let n = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&rsa_jwk.n)?)?;
                let e = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&rsa_jwk.e)?)?;
                let rsa_public_key = Rsa::from_public_components(n, e)?;
                let rsa_pkey = PKey::from_rsa(rsa_public_key)?;
                let cert_pub_key = cert_chain[0].public_key()?;
                if !cert_pub_key.public_eq(&rsa_pkey) {
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

fn rs384_verify(payload: &[u8], signature: &[u8], jwk: &RsaJWK) -> Result<()> {
    let n = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&jwk.n)?)?;
    let e = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&jwk.e)?)?;
    let rsa_public_key = Rsa::from_public_components(n, e)?;
    let rsa_pkey = PKey::from_rsa(rsa_public_key)?;

    let mut verifier = Verifier::new(MessageDigest::sha384(), &rsa_pkey)?;
    verifier.update(payload)?;

    if !verifier.verify(signature)? {
        return Err(Error::msg("RS384 verify failed"));
    }

    Ok(())
}

fn download_cert_chain(url: String, mut chain: &mut Vec<X509>) -> Result<()> {
    let res = reqwest::blocking::get(url)?;
    match res.status() {
        reqwest::StatusCode::OK => {
            let pem_cert_chain = res.text()?;
            parse_pem_cert_chain(pem_cert_chain, &mut chain)?;
        }
        _ => {
            return Err(Error::msg(format!(
                "Request x5u in Attestation Token JWK Failed, Response: {:?}",
                res.text()?,
            )));
        }
    }

    Ok(())
}

fn parse_pem_cert_chain(pem_cert_chain: String, chain: &mut Vec<X509>) -> Result<()> {
    for pem in pem_cert_chain.split("-----END CERTIFICATE-----") {
        let trimmed = format!("{}\n-----END CERTIFICATE-----", pem.trim());
        if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            continue;
        }
        let cert = X509::from_pem(trimmed.as_bytes()).context("Invalid PEM certificate chain")?;
        chain.push(cert);
    }

    Ok(())
}
