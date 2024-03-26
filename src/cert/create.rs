use super::dice::fields::{
    generate_claims_buffer, generate_evidence_buffer_with_tag, generate_pubkey_hash_value_buffer,
};
use super::dice::generate_and_sign_dice_cert;
use super::CLAIM_NAME_PUBLIC_KEY_HASH;
use crate::attester::GenericEvidence;
use crate::crypto::AsymmetricPrivateKey;
use crate::errors::*;
use crate::{
    attester::GenericAttester,
    claims::Claims,
    crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
};

use pkcs8::der::{Encode, EncodePem};
use pkcs8::LineEnding;
use x509_cert::Certificate;
use zeroize::Zeroizing;

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
    #[allow(dead_code)]
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

        generate_and_sign_dice_cert(
            &self.subject,
            self.hash_algo,
            &key,
            &evidence_buffer,
            Some(&[]),
        )
    }
}
