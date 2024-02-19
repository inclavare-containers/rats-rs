use crate::{errors::*, verifier::sgx_dcap::SgxDcapVerifier};
use spdmlib::{
    crypto::cert_operation::CertValidationStrategy, error::SPDM_STATUS_INVALID_CERT,
    protocol::SpdmCertChainData,
};

pub trait CertProvider {
    fn get_full_cert_chain(&self) -> Option<SpdmCertChainData>;
}

pub struct RatsCertProvider {
    cert_der: Vec<u8>,
}

impl RatsCertProvider {
    pub fn new(cert_der: Vec<u8>) -> Self {
        Self { cert_der }
    }
}

impl CertProvider for RatsCertProvider {
    fn get_full_cert_chain(&self) -> Option<SpdmCertChainData> {
        let mut my_cert_chain_data = SpdmCertChainData {
            ..Default::default()
        };

        my_cert_chain_data.data_size = self.cert_der.len() as u16;
        my_cert_chain_data.data[0..self.cert_der.len()].copy_from_slice(&self.cert_der);
        Some(my_cert_chain_data)
    }
}

pub struct EmptyCertProvider {}

impl CertProvider for EmptyCertProvider {
    fn get_full_cert_chain(&self) -> Option<SpdmCertChainData> {
        None
    }
}

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
        // TODO: check evidence type and choose Verifier
        match crate::cert::verify_cert_der(cert_chain, &SgxDcapVerifier::new()) {
            Ok(claims) => {
                // TODO: check BUILT_IN_CLAIM_SGX_MR_ENCLAVE etc.
                log::info!(
                    "{}:\t{}",
                    crate::verifier::sgx_dcap::claims::BUILT_IN_CLAIM_SGX_MR_ENCLAVE,
                    hex::encode(
                        &claims[crate::verifier::sgx_dcap::claims::BUILT_IN_CLAIM_SGX_MR_ENCLAVE]
                    ),
                );
                log::info!(
                    "{}:\t{}",
                    crate::verifier::sgx_dcap::claims::BUILT_IN_CLAIM_SGX_MR_SIGNER,
                    hex::encode(
                        &claims[crate::verifier::sgx_dcap::claims::BUILT_IN_CLAIM_SGX_MR_SIGNER]
                    ),
                );
                Ok(())
            }
            Err(e) => {
                log::error!(
                    "RatsCertValidationStrategy::verify_cert_chain() failed: {:?}",
                    e
                );
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
    pub struct DummyCertProvider {
        use_ecdsa: bool,
        is_requester: bool,
    }

    impl DummyCertProvider {
        pub fn new(use_ecdsa: bool, is_requester: bool) -> Self {
            Self {
                use_ecdsa,
                is_requester,
            }
        }
    }

    impl CertProvider for DummyCertProvider {
        fn get_full_cert_chain(&self) -> Option<SpdmCertChainData> {
            let mut my_cert_chain_data = SpdmCertChainData {
                ..Default::default()
            };

            let ca_file_path = if self.use_ecdsa {
                "../spdm-rs/test_key/ecp384/ca.cert.der"
            } else {
                "../spdm-rs/test_key/rsa3072/ca.cert.der"
            };
            let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
            let inter_file_path = if self.use_ecdsa {
                "../spdm-rs/test_key/ecp384/inter.cert.der"
            } else {
                "../spdm-rs/test_key/rsa3072/inter.cert.der"
            };
            let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
            let leaf_file_path = match self.is_requester {
                true => match self.use_ecdsa {
                    true => "../spdm-rs/test_key/ecp384/end_requester.cert.der",
                    false => "../spdm-rs/test_key/rsa3072/end_requester.cert.der",
                },
                false => match self.use_ecdsa {
                    true => "../spdm-rs/test_key/ecp384/end_responder.cert.der",
                    false => "../spdm-rs/test_key/rsa3072/end_responder.cert.der",
                },
            };

            let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

            let ca_len = ca_cert.len();
            let inter_len = inter_cert.len();
            let leaf_len = leaf_cert.len();
            println!(
                "total cert size - {:?} = {:?} + {:?} + {:?}",
                ca_len + inter_len + leaf_len,
                ca_len,
                inter_len,
                leaf_len
            );
            my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
            my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
            my_cert_chain_data.data[ca_len..(ca_len + inter_len)]
                .copy_from_slice(inter_cert.as_ref());
            my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
                .copy_from_slice(leaf_cert.as_ref());
            Some(my_cert_chain_data)
        }
    }

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

            let ca_file_path = if self.use_ecdsa {
                "../spdm-rs/test_key/ecp384/ca.cert.der"
            } else {
                "../spdm-rs/test_key/rsa3072/ca.cert.der"
            };
            let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
            let ca_len = ca_cert.len();
            peer_root_cert_data.data_size = (ca_len) as u16;
            peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

            Some(peer_root_cert_data)
        }
    }
}
