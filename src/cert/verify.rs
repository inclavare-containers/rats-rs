use super::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use super::dice::fields::{
    parse_claims_buffer, parse_evidence_buffer_with_tag, parse_pubkey_hash_value_buffer,
};
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::attester::GenericEvidence;

use crate::claims::Claims;
use crate::crypto::DefaultCrypto;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::verifier::GenericVerifier;

use const_oid::ObjectIdentifier;
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::{Decode, Encode};
use pkcs8::spki::AlgorithmIdentifierOwned;
use signature::Verifier;
use x509_cert::Certificate;

pub fn verify_cert_der<Verifier: GenericVerifier>(
    cert: &[u8],
    verifier: &Verifier,
) -> Result<Claims> {
    let cert = Certificate::from_der(cert)
        .kind(ErrorKind::ParseCertError)
        .context("failed to parse certificate from der")?;

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

    let (_tag, raw_evidence, claims_buffer) = parse_evidence_buffer_with_tag(evidence_buffer)?;
    // TODO: match verifier by tag

    let evidence = Verifier::Evidence::from_raw_evidence(&raw_evidence);
    /* Note: the hash algo is hardcoded to sha256, as defined in the Interoperable RA-TLS */
    let claims_buffer_hash = DefaultCrypto::hash(HashAlgo::Sha256, &claims_buffer);
    let builtin_claims = verifier.verify_evidence(&evidence, &claims_buffer_hash)?;
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
    let mut claims = custom_claims;
    builtin_claims.into_iter().for_each(|(k, v)| {
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

        const_oid::db::rfc5912::ID_RSASSA_PSS => {
            let params = algo
                .parameters
                .as_ref()
                .ok_or("empty PSS parameters")?
                .decode_as::<rsa::pkcs1::RsaPssParams>()?;

            match params.hash.oid {
                const_oid::db::rfc5912::ID_SHA_256 => {
                    rsa::pss::VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::try_from(spki)?)
                        .verify(signed_data, &signature.try_into()?)?
                }
                const_oid::db::rfc5912::ID_SHA_384 => {
                    rsa::pss::VerifyingKey::<sha2::Sha384>::new(rsa::RsaPublicKey::try_from(spki)?)
                        .verify(signed_data, &signature.try_into()?)?
                }
                const_oid::db::rfc5912::ID_SHA_512 => {
                    rsa::pss::VerifyingKey::<sha2::Sha512>::new(rsa::RsaPublicKey::try_from(spki)?)
                        .verify(signed_data, &signature.try_into()?)?
                }
                _ => return Err(format!("unsupported PSS hash algo {}", params.hash.oid).into()),
            }
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
