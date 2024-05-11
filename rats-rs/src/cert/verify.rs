use super::dice::cbor::{
    parse_claims_buffer, parse_evidence_buffer_with_tag, parse_pubkey_hash_value_buffer,
};
use super::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::auto::{AutoEvidence, AutoVerifier, LocalEvidence};
use crate::tee::coco::converter::CocoConverter;
use crate::tee::coco::evidence::CocoEvidence;
use crate::tee::coco::verifier::CocoVerifier;
use crate::tee::GenericConverter;
use crate::tee::{claims::Claims, GenericEvidence, GenericVerifier};

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
    /// Verify with Local Attester
    Local(ClaimsCheck),
    /// Verify with CoCo policies. Should be used only when peer is using CoCo Attester
    Coco {
        /// The Grpc address of CoCo Attestation Service
        as_addr: String,
        /// The policy ids needed to check
        policy_ids: Vec<String>,
        /// The path of all trusted certs to be used for checking CoCo AS token 
        trusted_certs_paths: Option<Vec<String>>,
        /// Additional strategy for checking cliams (both builtin claims and custom claims) 
        claims_check: ClaimsCheck,
    },
}

pub enum ClaimsCheck {
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
        let cert = Certificate::from_pem(cert)
            .kind(ErrorKind::ParseCertError)
            .context("failed to parse certificate from pem")?;
        let claims = self.verify_cert(&cert)?;
        self.check_claims(&claims)
    }

    pub fn verify_der(&self, cert: &[u8]) -> Result<VerifyPolicyOutput> {
        let cert = Certificate::from_der(cert)
            .kind(ErrorKind::ParseCertError)
            .context("failed to parse certificate from der")?;
        let claims = self.verify_cert(&cert)?;
        self.check_claims(&claims)
    }

    fn verify_cert(&self, cert: &Certificate) -> Result<Claims> {
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
        // TODO: endorsements extension

        let (cbor_tag, raw_evidence, claims_buffer) =
            parse_evidence_buffer_with_tag(evidence_buffer)?;
        /* Note: the hash algo is hardcoded to sha256, as defined in the Interoperable RA-TLS */
        let claims_buffer_hash = DefaultCrypto::hash(HashAlgo::Sha256, &claims_buffer);

        /* Parse evidence, verify evidence and get builtin claims */
        let builtin_claims =
            match &self.policy {
                VerifiyPolicy::Local(_) => {
                    let evidence = Into::<Result<_>>::into(
                        AutoEvidence::create_evidence_from_dice(cbor_tag, &raw_evidence),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to parse evidence: cbor_tag: {:#x?}, raw_evidence: {:02x?}",
                            cbor_tag, raw_evidence
                        )
                    })?;
                    let tee_type = evidence.get_tee_type();
                    debug!("TEE type of this cert is {:?}", tee_type);
                    let verifier = AutoVerifier::new();
                    verifier.verify_evidence(&evidence, &claims_buffer_hash)?;
                    evidence.get_claims()?
                }
                VerifiyPolicy::Coco {
                    as_addr,
                    policy_ids,
                    trusted_certs_paths,
                    ..
                } => {
                    let evidence = Into::<Result<_>>::into(
                        CocoEvidence::create_evidence_from_dice(cbor_tag, &raw_evidence),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to parse evidence: cbor_tag: {:#x?}, raw_evidence: {:02x?}",
                            cbor_tag, raw_evidence
                        )
                    })?;
                    let converter = CocoConverter::new(&as_addr, &policy_ids)?;
                    let token = converter.convert(&evidence)?;
                    let verifier = CocoVerifier::new(&trusted_certs_paths, &policy_ids)?;
                    verifier.verify_evidence(&token, &claims_buffer_hash)?;
                    token.get_claims()?
                }
            };

        /* Parse custom claims from the claims_buffer as addition to the built-in claims. */
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
            VerifiyPolicy::Local(claims_check) | VerifiyPolicy::Coco { claims_check, .. } => {
                /* For CoCo, the checking of policy_ids have done in the CocoVerifier, so there is no need to check here. */
                match claims_check {
                    ClaimsCheck::Contains(expected_claims) => {
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
                    ClaimsCheck::Custom(func) => Ok(func(claims)),
                }
            }
        }
    }
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
        crypto::{AsymmetricAlgo, HashAlgo},
        errors::*,
        tee::{
            auto::AutoAttester,
            claims::{Claims, BUILT_IN_CLAIM_COMMON_TEE_TYPE},
            TeeType,
        },
    };

    #[allow(unused_imports)]
    use super::*;

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
            CertVerifier::new(VerifiyPolicy::Local(ClaimsCheck::Contains(claims.clone())))
                .verify_der(&cert)?,
            VerifyPolicyOutput::Passed
        );

        let mut claims_mismatch = claims.clone();
        claims_mismatch.insert("key1".into(), "test-mismatch-value".into());
        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Local(ClaimsCheck::Contains(claims_mismatch)))
                .verify_der(&cert)?,
            VerifyPolicyOutput::Failed
        );

        let mut claims_missing = claims.clone();
        claims_missing.insert("key3".into(), "test-missing-value".into());
        assert_eq!(
            CertVerifier::new(VerifiyPolicy::Local(ClaimsCheck::Contains(claims_missing)))
                .verify_der(&cert)?,
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
            CertVerifier::new(VerifiyPolicy::Local(ClaimsCheck::Contains(claims.clone())))
                .verify_der(&cert)?,
            VerifyPolicyOutput::Failed
        );

        Ok(())
    }
}
