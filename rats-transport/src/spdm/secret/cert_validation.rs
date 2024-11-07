use log::error;
use spdmlib::{
    crypto::cert_operation::CertValidationStrategy, error::SPDM_STATUS_INVALID_CERT,
    protocol::SpdmCertChainData,
};

use crate::{
    cert::verify::{CertVerifier, ClaimsCheck, VerifyPolicy, VerifyPolicyOutput},
    tee::claims::Claims,
};

pub trait ValidationContext {
    fn get_peer_root_cert(&self) -> Option<SpdmCertChainData>;
}

pub struct EmptyValidationContext {}

impl ValidationContext for EmptyValidationContext {
    fn get_peer_root_cert(&self) -> Option<SpdmCertChainData> {
        None
    }
}

pub struct RatsCertValidationStrategy {}

impl CertValidationStrategy for RatsCertValidationStrategy {
    fn verify_cert_chain(&self, cert_chain: &[u8]) -> spdmlib::error::SpdmResult {
        let expected_claims = Claims::default(); // TODO: user provided

        let verifier =
            CertVerifier::new(VerifyPolicy::Local(ClaimsCheck::Contains(expected_claims)));
        match verifier.verify_der(cert_chain) {
            Ok(VerifyPolicyOutput::Passed) => Ok(()),
            Ok(VerifyPolicyOutput::Failed) => {
                error!("CertVerifier verify finished with failed output");
                Err(SPDM_STATUS_INVALID_CERT)
            }
            Err(e) => {
                error!("CertVerifier failed during verifing DER cert: {:?}", e);
                Err(SPDM_STATUS_INVALID_CERT)
            }
        }
    }

    fn need_check_leaf_certificate(&self) -> bool {
        false
    }

    fn need_check_cert_chain_provisioned(&self) -> bool {
        false
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct DummyValidationContext {
        use_ecdsa: bool,
    }

    impl DummyValidationContext {
        pub fn new(use_ecdsa: bool) -> Self {
            Self { use_ecdsa }
        }
    }

    impl ValidationContext for DummyValidationContext {
        fn get_peer_root_cert(&self) -> Option<SpdmCertChainData> {
            let mut peer_root_cert_data = SpdmCertChainData {
                ..Default::default()
            };

            let ca_cert = if self.use_ecdsa {
                &include_bytes!("../../../../deps/spdm-rs/test_key/ecp384/ca.cert.der")[..]
            } else {
                &include_bytes!("../../../../deps/spdm-rs/test_key/rsa3072/ca.cert.der")[..]
            };
            let ca_len = ca_cert.len();
            peer_root_cert_data.data_size = (ca_len) as u16;
            peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

            Some(peer_root_cert_data)
        }
    }
}
