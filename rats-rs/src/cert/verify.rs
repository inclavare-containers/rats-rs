use super::dice::cbor::{
    parse_claims_buffer, parse_evidence_buffer_with_tag, parse_pubkey_hash_value_buffer,
};
use super::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::{claims::Claims, AutoVerifier, GenericEvidence, GenericVerifier};

use bstr::ByteSlice;
use const_oid::ObjectIdentifier;
use itertools::Itertools;
use log::{debug, error, log_enabled, warn, Level::Debug};
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::{Decode, DecodePem, Encode};
use pkcs8::spki::AlgorithmIdentifierOwned;
use signature::Verifier;
use x509_cert::Certificate;

/// Represents the different verification policies that can be applied to certificates.
pub enum VerifiyPolicy {
    /// Verifies if the certificate contains a specific set of claims.
    Contains(Claims),
    /// Enables the use of a custom verification function, providing flexibility for specialized validation logic.
    Custom(Box<dyn Fn(&Claims) -> VerifyPolicyOutput>),
}

/// Represents the outcome of a certificate verification.
#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum VerifyPolicyOutput {
    /// Indicates the verification has failed.
    Failed,
    /// Indicates the verification has passed successfully.
    Passed,
}

#[allow(dead_code)]
pub struct CertVerifier {
    policy: VerifiyPolicy,
}

#[allow(dead_code)]
impl CertVerifier {
    pub fn new(policy: VerifiyPolicy) -> Self {
        Self { policy }
    }

    pub fn verify_pem(&self, cert: &[u8]) -> Result<VerifyPolicyOutput> {
        let claims = verify_cert_pem(cert)?;
        self.check_claims(&claims)
    }

    pub fn verify_der(&self, cert: &[u8]) -> Result<VerifyPolicyOutput> {
        let claims = verify_cert_der(cert)?;
        self.check_claims(&claims)
    }

    fn check_claims(&self, claims: &Claims) -> Result<VerifyPolicyOutput> {
        if log_enabled!(Debug) {
            let iter =
                claims
                    .iter()
                    .map(|(name, value)| match std::str::from_utf8(value.as_ref()) {
                        Ok(s) if !s.contains('\0') => {
                            format!("\t{}:\t{} (b\"{}\")", name, hex::encode(value), s)
                        }
                        _ => format!("\t{}:\t{}", name, hex::encode(value)),
                    });
            let mergered: String = Itertools::intersperse(iter, "\n".into()).collect();
            debug!(
                "There are {} claims parsed from the cert:\n{}",
                claims.len(),
                mergered
            );
        }

        match &self.policy {
            VerifiyPolicy::Contains(expected_claims) => {
                let passed =  expected_claims
                    .iter()
                    .all(|(name, expected_value)| match claims.get(name) {
                        Some(value) => {
                            if expected_value != value {
                                error!("Claim mismatch detected, with claim name: {name}\n\t\t\texpected:\t{}\n\t\t\tgot:\t{}", ByteSlice::as_bstr(&value[..]), ByteSlice::as_bstr(&expected_value[..]));
                                return false;
                            }
                            true
                        }
                        None => {
                            error!("Claim missing detected, with claim name: {name}");
                            false
                        },
                    });
                if passed {
                    Ok(VerifyPolicyOutput::Passed)
                } else {
                    Ok(VerifyPolicyOutput::Failed)
                }
            }
            VerifiyPolicy::Custom(func) => Ok(func(claims)),
        }
    }
}

pub(crate) fn verify_cert_der(cert: &[u8]) -> Result<Claims> {
    let cert = Certificate::from_der(cert)
        .kind(ErrorKind::ParseCertError)
        .context("failed to parse certificate from der")?;
    verify_cert(&cert)
}

pub(crate) fn verify_cert_pem(cert: &[u8]) -> Result<Claims> {
    let cert = Certificate::from_pem(cert)
        .kind(ErrorKind::ParseCertError)
        .context("failed to parse certificate from pem")?;
    verify_cert(&cert)
}

pub(crate) fn verify_cert(cert: &Certificate) -> Result<Claims> {
    /* check self-signed cert */
    verify_cert_signature(&cert, &cert).kind(ErrorKind::CertVerifySignatureFailed)?;

    /* Extract the evidence_buffer and endorsements_buffer(optional) from the X.509 certificate extension. */
    let evidence_buffer = extract_ext_with_oid(&cert, &OID_TCG_DICE_TAGGED_EVIDENCE);
    let _endorsements_buffer = extract_ext_with_oid(&cert, &OID_TCG_DICE_ENDORSEMENT_MANIFEST);

    /* evidence extension is not optional */
    let evidence_buffer = match evidence_buffer {
        Some(v) => v,
        None => Err(Error::kind_with_msg(
            ErrorKind::CertExtractExtensionFailed,
            "failed to extract the evidence extensions from the certificate",
        ))?,
    };
    /* endorsements extension is optional */

    let (tag, raw_evidence, claims_buffer) = parse_evidence_buffer_with_tag(evidence_buffer)?;

    let evidence = crate::tee::AutoEvidence::create_evidence_from_dice(tag, &raw_evidence)?;
    let tee_type = evidence.get_tee_type();
    debug!("TEE type of this cert is {:?}", tee_type);
    let verifier = AutoVerifier::new();

    /* Note: the hash algo is hardcoded to sha256, as defined in the Interoperable RA-TLS */
    let claims_buffer_hash = DefaultCrypto::hash(HashAlgo::Sha256, &claims_buffer);
    verifier.verify_evidence(&evidence, &claims_buffer_hash)?;
    let builtin_claims = evidence.get_claims()?;
    let custom_claims = parse_claims_buffer(&claims_buffer)?;

    let pubkey_hash_value_buffer =
        custom_claims
            .get(CLAIM_NAME_PUBLIC_KEY_HASH)
            .ok_or_else(|| {
                Error::kind_with_msg(
                    ErrorKind::CertVerifyPublicKeyHashFailed,
                    format!(
                        "failed to find claim with name '{}' from claims list with length {}",
                        CLAIM_NAME_PUBLIC_KEY_HASH,
                        custom_claims.len()
                    ),
                )
            })?;

    /* Verify pubkey_hash */
    let (pubkey_hash_algo, pubkey_hash) =
        parse_pubkey_hash_value_buffer(&pubkey_hash_value_buffer)?;
    let spki_bytes = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let calculated_pubkey_hash = DefaultCrypto::hash(pubkey_hash_algo, &spki_bytes);

    if pubkey_hash != calculated_pubkey_hash {
        Err(Error::kind_with_msg(
            ErrorKind::CertVerifyPublicKeyHashFailed,
            "hash of public key mismatch",
        ))?
    }

    /* Merge builtin claims and custom claims */
    let mut claims = builtin_claims;
    custom_claims.into_iter().for_each(|(k, v)| {
        if claims.contains_key(&k) {
            /* Note that custom claims do not have the guarantees that come with hardware, so we need to prevent custom claims from overriding built-in claims (guaranteed by TEE hardware). */
            warn!("Claims overriding is detected and is prevented: a custom claim with key '{k}' duplicates existing built-in claims");
            return;
        }
        claims.insert(k, v);
    });

    Ok(claims)
}

fn verify_cert_signature(issuer: &Certificate, signed: &Certificate) -> Result<()> {
    if issuer.tbs_certificate.subject != signed.tbs_certificate.issuer {
        return Err("certificate issuer does not match".into());
    }

    let signed_data = signed.tbs_certificate.to_der()?;
    let signature = signed
        .signature
        .as_bytes()
        .ok_or("could not get cert signature")?;

    verify_signed_data(issuer, &signed_data, signature, &signed.signature_algorithm)
}

fn verify_signed_data(
    issuer: &Certificate,
    signed_data: &[u8],
    signature: &[u8],
    algo: &AlgorithmIdentifierOwned,
) -> Result<()> {
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();

    match algo.oid {
        const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::try_from(spki)?)
                .verify(signed_data, &signature.try_into()?)?;
        }
        const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(rsa::RsaPublicKey::try_from(spki)?)
                .verify(signed_data, &signature.try_into()?)?;
        }
        const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(rsa::RsaPublicKey::try_from(spki)?)
                .verify(signed_data, &signature.try_into()?)?;
        }

        const_oid::db::rfc5912::ECDSA_WITH_SHA_256 => {
            let signature = p256::ecdsa::DerSignature::try_from(signature)?;
            p256::ecdsa::VerifyingKey::try_from(spki)?.verify(signed_data, &signature)?;
        }

        _ => {
            return Err(format!(
                "unknown signature algo {}",
                issuer.tbs_certificate.signature.oid
            )
            .into())
        }
    }

    Ok(())
}

fn extract_ext_with_oid<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .map(|exts| {
            let mut it = exts.iter().filter(|ext| ext.extn_id == *oid);
            if let Some(ext) = it.next() {
                return Some(ext.extn_value.as_bytes());
            } else {
                return None;
            }
        })
        .flatten()
}

#[cfg(test)]
pub mod tests {

    use indexmap::IndexMap;

    use crate::{
        cert::create::CertBuilder,
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        errors::*,
        tee::{
            claims::{Claims, BUILT_IN_CLAIM_COMMON_TEE_TYPE},
            AutoAttester, TeeType,
        },
    };

    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_verify_cert_der() -> Result<()> {
        if TeeType::detect_env() == None {
            /* skip */
            return Ok(());
        }

        /* Test verifiy normal cert */
        let mut claims = Claims::new();
        claims.insert("key1".into(), "value1".into());
        claims.insert("key2".into(), "value2".into());

        let attester = AutoAttester::new();
        let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims.clone())
            .build(AsymmetricAlgo::P256)?;
        let cert = cert_bundle.cert_to_der()?;

        let parsed_claims = verify_cert_der(&cert)?;

        let hex_claims = parsed_claims
            .into_iter()
            .map(|(k, v)| (k, hex::encode(v)))
            .collect::<IndexMap<String, String>>();
        println!("{hex_claims:?}");

        Ok(())
    }

    #[test]
    fn test_verify_attestation_certificate() -> Result<()> {
        if TeeType::detect_env() == None {
            /* skip */
            return Ok(());
        }

        /* Test verifiy normal cert */
        let mut claims = Claims::new();
        claims.insert("key1".into(), "value1".into());
        claims.insert("key2".into(), "value2".into());

        let attester = AutoAttester::new();
        let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims.clone())
            .build(AsymmetricAlgo::P256)?;
        let cert = cert_bundle.cert_to_der()?;

        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Contains(claims.clone())).verify_der(&cert)?,
            VerifyPolicyOutput::Passed
        );

        let mut claims_mismatch = claims.clone();
        claims_mismatch.insert("key1".into(), "test-mismatch-value".into());
        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Contains(claims_mismatch)).verify_der(&cert)?,
            VerifyPolicyOutput::Failed
        );

        let mut claims_missing = claims.clone();
        claims_missing.insert("key3".into(), "test-missing-value".into());
        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Contains(claims_missing)).verify_der(&cert)?,
            VerifyPolicyOutput::Failed
        );

        Ok(())
    }

    #[test]
    fn test_verify_attestation_certificate_with_claims_overriding() -> Result<()> {
        if TeeType::detect_env() == None {
            /* skip */
            return Ok(());
        }

        /* Test verifiy cert with claims overriding */
        let mut claims = Claims::new();
        claims.insert(
            BUILT_IN_CLAIM_COMMON_TEE_TYPE.into(),
            "test-tee-type".into(),
        ); /* Try to overriding the "common_quote_type" claim */

        let attester = AutoAttester::new();
        let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims.clone())
            .build(AsymmetricAlgo::P256)?;
        let cert = cert_bundle.cert_to_der()?;

        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Contains(claims.clone())).verify_der(&cert)?,
            VerifyPolicyOutput::Failed
        );

        Ok(())
    }
}
