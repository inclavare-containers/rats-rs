use std::fmt::format;

use crate::errors::*;

use pkcs8::{
    der::DecodePem, DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding,
    PrivateKeyInfo, SecretDocument,
};
use sha2::Digest as _;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}

// impl HashAlgo {
//     fn hash() -> Vec<> {}
// }

#[derive(Debug, Clone, Copy)]
pub enum AsymmetricAlgo {
    Rsa3072,
    Ecc256,
}

// TODO: try refactor AsymmetricPrivateKey to AsymmetricAlgo + trait object
#[derive(Debug)]
pub enum AsymmetricPrivateKey {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::SecretKey),
}

impl AsymmetricPrivateKey {
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        Ok(match self {
            AsymmetricPrivateKey::Rsa(key) => key.to_pkcs8_pem(LineEnding::LF)?,
            AsymmetricPrivateKey::P256(key) => key.to_pkcs8_pem(LineEnding::LF)?,
        })
    }

    pub fn from_pkcs8_pem(private_key_pkcs8: &str) -> Result<Self> {
        // let (label, doc) = SecretDocument::from_pem(private_key_pkcs8)?;
        // PrivateKeyInfo::from_pem(label)?;

        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(&private_key_pkcs8) {
            return Ok(AsymmetricPrivateKey::Rsa(key));
        } else {
            match p256::SecretKey::from_pkcs8_pem(&private_key_pkcs8) {
                Ok(key) => return Ok(AsymmetricPrivateKey::P256(key)),
                Err(e) => {
                    return Err(e).kind(ErrorKind::ParsePrivateKey).context(format!(
                        "failed to parse private key from pkcs8 pem format. content: '{}'",
                        private_key_pkcs8,
                    ))
                }
            }
        }
    }
}

pub struct DefaultCrypto {}

impl DefaultCrypto {
    pub fn gen_private_key(algo: AsymmetricAlgo) -> Result<AsymmetricPrivateKey> {
        let mut rng = rand::rngs::OsRng;
        match algo {
            AsymmetricAlgo::Rsa3072 => Ok(AsymmetricPrivateKey::Rsa(rsa::RsaPrivateKey::new(
                &mut rng, 3072,
            )?)),
            AsymmetricAlgo::Ecc256 => Ok(AsymmetricPrivateKey::P256(p256::SecretKey::random(
                &mut rng,
            ))),
        }
    }

    /// Calculate hash of SubjectPublicKeyInfo(SPKI) object
    pub fn hash_of_private_key(
        hash_algo: HashAlgo,
        private_key: &AsymmetricPrivateKey,
    ) -> Result<Vec<u8>> {
        let spki_doc = match private_key {
            AsymmetricPrivateKey::Rsa(key) => key.to_public_key().to_public_key_der(),
            AsymmetricPrivateKey::P256(key) => key.public_key().to_public_key_der(),
        }?;
        let bytes = spki_doc.as_bytes();

        Ok(Self::hash(hash_algo, bytes))
    }

    pub fn hash(hash_algo: HashAlgo, bytes: &[u8]) -> Vec<u8> {
        let result = match hash_algo {
            HashAlgo::Sha256 => sha2::Sha256::new().chain_update(bytes).finalize().to_vec(),
            HashAlgo::Sha384 => sha2::Sha384::new().chain_update(bytes).finalize().to_vec(),
            HashAlgo::Sha512 => sha2::Sha512::new().chain_update(bytes).finalize().to_vec(),
        };
        result
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn test_gen_cert() -> Result<()> {
        for algo in [AsymmetricAlgo::Ecc256, AsymmetricAlgo::Rsa3072] {
            let key = DefaultCrypto::gen_private_key(algo)?.to_pkcs8_pem()?;
            println!("generated {:?} key:\n{}", algo, key.as_str());
        }
        Ok(())
    }
}
