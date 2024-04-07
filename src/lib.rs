#![feature(specialization)]
#![allow(incomplete_features)]

mod cert;
mod crypto;
mod errors;
pub mod tee;
pub mod transport;

pub use crate::cert::{verify_cert_der, CertBuilder};

#[cfg(all(feature = "is_sync", feature = "async-tokio"))]
compile_error!("features `is_sync` and `async-tokio` are mutually exclusive");

#[cfg(test)]
pub mod tests {

    use self::{
        crypto::{AsymmetricAlgo, HashAlgo},
        tee::claims::Claims,
        tee::sgx_dcap::attester::SgxDcapAttester,
    };
    use crate::{cert::CertBuilder, errors::*};

    use super::*;

    #[test]
    fn test_get_attestation_certificate() -> Result<()> {
        let mut claims = Claims::new();
        claims.insert("key1".into(), "value1".into());
        claims.insert("key2".into(), "value2".into());

        let attester = SgxDcapAttester::new();

        let (cert, private_key) = CertBuilder::new(attester, HashAlgo::Sha256)
            .with_claims(claims)
            .build_pem(AsymmetricAlgo::P256)?;

        println!("generated cert:\n{}", cert);
        println!("generated private_key:\n{}", private_key.as_str());

        Ok(())
    }
}
