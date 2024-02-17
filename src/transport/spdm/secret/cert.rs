use crate::errors::*;
use spdmlib::protocol::SpdmCertChainData;

pub trait SpdmCertProvider {
    fn get_full_cert_chain(&self) -> Result<SpdmCertChainData>;
    fn get_peer_root_cert(&self) -> Result<SpdmCertChainData>;
}

pub struct FileBasedCertProvider {
    use_ecdsa: bool,
    is_requester: bool,
}

impl FileBasedCertProvider {
    pub fn new(use_ecdsa: bool, is_requester: bool) -> Self {
        Self {
            use_ecdsa,
            is_requester,
        }
    }
}

impl SpdmCertProvider for FileBasedCertProvider {
    fn get_full_cert_chain(&self) -> Result<SpdmCertChainData> {
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
        my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
        my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
            .copy_from_slice(leaf_cert.as_ref());
        Ok(my_cert_chain_data)
    }

    fn get_peer_root_cert(&self) -> Result<SpdmCertChainData> {
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

        Ok(peer_root_cert_data)
    }
}
