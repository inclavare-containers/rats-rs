pub mod dice;

use self::dice::element::Claims;
use crate::cert::dice::element::{generate_claims_buffer, generate_evidence_buffer_with_tag};
use crate::cert::dice::gen_cert_pem;
use crate::crypto::{AsymmetricAlgo, AsymmetricPrivateKey, DefaultCrypto};
use crate::errors::*;
use crate::{attester::GenericAttester, crypto::HashAlgo};

use zeroize::Zeroizing;

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

    pub fn build_pem(
        &self,
        private_key_algo: AsymmetricAlgo,
    ) -> Result<(String, Zeroizing<String>)> {
        let key = DefaultCrypto::gen_private_key(private_key_algo)?;

        Ok((self.build_pem_with_private_key(&key)?, key.to_pkcs8_pem()?))
    }

    pub fn build_pem_with_pkcs8_private_key(&self, private_key: &str) -> Result<String> {
        let key = AsymmetricPrivateKey::from_pkcs8_pem(private_key)?;

        self.build_pem_with_private_key(&key)
    }

    fn build_pem_with_private_key(&self, key: &AsymmetricPrivateKey) -> Result<String> {
        /* Prepare custom claim `pubkey-hash` and add to claims map */
        let pubkey_hash = DefaultCrypto::hash_of_private_key(self.hash_algo, key)?;
        let mut claims = match &self.claims {
            Some(claims) => claims.clone(),
            None => Claims::new(),
        };
        claims.insert(CLAIM_NAME_PUBLIC_KEY_HASH.into(), pubkey_hash);

        /* Serialize claims to claims_buffer */
        let claims_buffer = generate_claims_buffer(&claims)?;
        let claims_buffer_hash = DefaultCrypto::hash(self.hash_algo, &claims_buffer);

        /* Generate evidence buffer */
        let evidence = self.attester.get_evidence(&claims_buffer_hash)?;
        let evidence_buffer = generate_evidence_buffer_with_tag(&evidence, &claims_buffer)?;

        let cert = gen_cert_pem(&self.subject, self.hash_algo, &key, &evidence_buffer, &[])?;
        Ok(cert)
    }
}
