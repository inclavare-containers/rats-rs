#![feature(specialization)]

mod attester;
mod cert;
mod claims;
mod crypto;
mod errors;
mod transport;
mod verifier;

#[cfg(not(any(
    feature = "build-mode-host",
    feature = "build-mode-occlum",
    feature = "build-mode-sgx"
)))]
compile_error!("At least one `build-mode-*` feature should be enabled");

#[cfg(any(
    all(
        feature = "build-mode-host",
        any(feature = "build-mode-occlum", feature = "build-mode-sgx")
    ),
    all(
        feature = "build-mode-occlum",
        any(feature = "build-mode-host", feature = "build-mode-sgx")
    ),
    all(
        feature = "build-mode-sgx",
        any(feature = "build-mode-host", feature = "build-mode-occlum")
    ),
))]
compile_error!("more than one `build-mode-*` features cannot be enabled at the same time");

#[cfg(all(feature = "is_sync", feature = "async-tokio"))]
compile_error!("features `is_sync` and `async-tokio` are mutually exclusive");

#[cfg(test)]
pub mod tests {

    use self::{
        attester::{sgx_dcap::SgxDcapAttester, GenericAttester},
        cert::dice::{
            fields::{generate_claims_buffer, generate_evidence_buffer_with_tag},
            gen_cert,
        },
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
    };
    use crate::{cert::CertBuilder, claims::Claims, errors::*};

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
