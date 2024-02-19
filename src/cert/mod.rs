pub mod dice;

use crate::attester::GenericEvidence;
use crate::cert::dice::fields::{generate_claims_buffer, generate_evidence_buffer_with_tag};
use crate::cert::dice::gen_cert;
use crate::claims::Claims;
use crate::crypto::{AsymmetricAlgo, AsymmetricPrivateKey, DefaultCrypto};
use crate::errors::*;
use crate::verifier::GenericVerifier;
use crate::{attester::GenericAttester, crypto::HashAlgo};
use const_oid::ObjectIdentifier;
use pkcs8::der::referenced::OwnedToRef;
use pkcs8::der::{Decode, Encode, EncodePem};
use pkcs8::spki::AlgorithmIdentifierOwned;
use pkcs8::LineEnding;
use signature::Verifier;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use self::dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE};
use self::dice::fields::{
    generate_pubkey_hash_value_buffer, parse_claims_buffer, parse_evidence_buffer_with_tag,
    parse_pubkey_hash_value_buffer,
};

const CLAIM_NAME_PUBLIC_KEY_HASH: &'static str = "pubkey-hash";
const CLAIM_NAME_NONCE: &'static str = "nonce";

pub struct CertBuilder<A: GenericAttester> {
    attester: A,
    claims: Option<Claims>,
    subject: String,
    hash_algo: HashAlgo,
}

impl<A: GenericAttester> CertBuilder<A> {
    pub fn new(attester: A, hash_algo: HashAlgo) -> Self {
        Self {
            attester: attester,
            claims: None,
            subject: "CN=rats-rs,O=Inclavare Containers".into(),
            hash_algo: hash_algo,
        }
    }

    pub fn with_claims(mut self, claims: Claims) -> Self {
        self.claims = Some(claims);
        self
    }

    pub fn with_subject(mut self, subject: impl AsRef<str>) -> Self {
        self.subject = subject.as_ref().into();
        self
    }

    /* align to librats */
    pub fn build_pem(
        &self,
        private_key_algo: AsymmetricAlgo,
    ) -> Result<(String, Zeroizing<String>)> {
        let key = DefaultCrypto::gen_private_key(private_key_algo)?;

        Ok((self.build_pem_with_private_key(&key)?, key.to_pkcs8_pem()?))
    }

    /* align to librats */
    pub fn build_pem_with_pkcs8_private_key(&self, private_key: &str) -> Result<String> {
        let key = AsymmetricPrivateKey::from_pkcs8_pem(private_key)?;

        self.build_pem_with_private_key(&key)
    }

    fn build_pem_with_private_key(&self, key: &AsymmetricPrivateKey) -> Result<String> {
        self.build_with_private_key_inner(key)?
            .to_pem(LineEnding::LF)
            .kind(ErrorKind::GenCertError)
            .context("failed to encode certificate as pem")
    }

    /* for spdm */
    pub(crate) fn build_der_with_private_key(&self, key: &AsymmetricPrivateKey) -> Result<Vec<u8>> {
        self.build_with_private_key_inner(&key)?
            .to_der()
            .kind(ErrorKind::GenCertError)
            .context("failed to encode certificate as der")
    }

    fn build_with_private_key_inner(&self, key: &AsymmetricPrivateKey) -> Result<Certificate> {
        /* Prepare custom claim `pubkey-hash` and add to claims map */
        let pubkey_hash = DefaultCrypto::hash_of_private_key(self.hash_algo, key)?;
        let pubkey_hash_value_buffer =
            generate_pubkey_hash_value_buffer(self.hash_algo, &pubkey_hash)?;

        let mut claims = match &self.claims {
            Some(claims) => claims.clone(),
            None => Claims::new(),
        };
        claims.insert(CLAIM_NAME_PUBLIC_KEY_HASH.into(), pubkey_hash_value_buffer);

        /* Serialize claims to claims_buffer */
        let claims_buffer = generate_claims_buffer(&claims)?;
        /* Note: the hash algo is hardcoded to sha256, as defined in the Interoperable RA-TLS */
        let claims_buffer_hash = DefaultCrypto::hash(HashAlgo::Sha256, &claims_buffer);

        /* Generate evidence buffer */
        let evidence = self.attester.get_evidence(&claims_buffer_hash)?;
        let evidence_buffer = generate_evidence_buffer_with_tag(
            A::Evidence::DICE_OCBR_TAG,
            evidence.get_raw_evidence_dice(),
            &claims_buffer,
        )?;

        gen_cert(
            &self.subject,
            self.hash_algo,
            &key,
            &evidence_buffer,
            Some(&[]),
        )
    }
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
    let endorsements_buffer = extract_ext_with_oid(&cert, &OID_TCG_DICE_ENDORSEMENT_MANIFEST);

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

pub fn verify_signature(
    cert: &Certificate,
    signed_data: &[u8],
    signature: &[u8],
    algo: &AlgorithmIdentifierOwned,
) -> Result<()> {
    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

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
                cert.tbs_certificate.signature.oid
            )
            .into())
        }
    }

    Ok(())
}

pub fn verify_cert_signature(cert: &Certificate, signed: &Certificate) -> Result<()> {
    if cert.tbs_certificate.subject != signed.tbs_certificate.issuer {
        return Err("certificate issuer does not match".into());
    }

    let signed_data = signed.tbs_certificate.to_der()?;
    let signature = signed
        .signature
        .as_bytes()
        .ok_or("could not get cert signature")?;

    verify_signature(cert, &signed_data, signature, &signed.signature_algorithm)
}
