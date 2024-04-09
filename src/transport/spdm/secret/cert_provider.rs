use spdmlib::protocol::SpdmCertChainData;

pub trait CertProvider {
    fn get_full_cert_chain(&self) -> Option<SpdmCertChainData>;
}

pub struct RatsCertProvider {
    cert_der: Vec<u8>,
}

impl RatsCertProvider {
    pub fn new_der(cert_der: Vec<u8>) -> Self {
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
}
