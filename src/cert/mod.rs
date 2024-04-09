mod create;
pub mod dice;
mod verify;

#[allow(dead_code)]
const CLAIM_NAME_PUBLIC_KEY_HASH: &'static str = "pubkey-hash";
#[allow(dead_code)]
const CLAIM_NAME_NONCE: &'static str = "nonce";

pub use create::CertBuilder;
pub use verify::verify_cert_der;

#[cfg(test)]
pub mod tests {

    use crate::{
        cert::CertBuilder,
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        errors::*,
        tee::{claims::Claims, AutoAttester, TeeType},
    };

    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_get_attestation_certificate() -> Result<()> {
        if TeeType::detect_env() == None {
            /* skip */
            return Ok(());
        }

        let mut claims = Claims::new();
        claims.insert("key1".into(), "value1".into());
        claims.insert("key2".into(), "value2".into());

        /* Test without provideing key */
        let attester = AutoAttester::new();
        let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims.clone())
            .build(AsymmetricAlgo::P256)?;

        println!("generated cert:\n{}", cert_bundle.cert_to_pem()?);
        println!(
            "generated private_key:\n{}",
            cert_bundle.private_key().to_pkcs8_pem()?.as_str()
        );

        /* Test with specific key */
        let attester = AutoAttester::new();
        let key = DefaultCrypto::gen_private_key(AsymmetricAlgo::P256)?;
        let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims)
            .build_with_private_key(&key)?;

        println!("generated cert:\n{}", cert_bundle.cert_to_pem()?);
        println!(
            "generated private_key:\n{}",
            cert_bundle.private_key().to_pkcs8_pem()?.as_str()
        );

        Ok(())
    }
}
