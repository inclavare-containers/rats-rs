// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

use crate::transport::spdm::secret::cert_provider::FileBasedCertProvider;
use crate::transport::spdm::secret::cert_provider::SpdmCertProvider;
use crate::transport::GenericSecureTransPort;

use super::crypto_callback::SECRET_ASYM_IMPL_INSTANCE;
use super::io::FramedStream;
use super::secret_impl_sample::DummyMeasurementProvider;
use super::transport::SimpleTransportEncap;
use common::SpdmTransportEncap;
use core::convert::TryFrom;
use maybe_async::maybe_async;
use spdmlib::common;
use spdmlib::common::SecuredMessageVersion;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::config;
use spdmlib::config::MAX_ROOT_CERT_SUPPORT;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester;
use spin::Mutex;
use std::io::Read;
use std::io::Write;
extern crate alloc;
use crate::errors::*;
use alloc::sync::Arc;

struct SpdmRequester {
    context: requester::RequesterContext,
    session_id: Option<u32>,
}
impl SpdmRequester {
    pub fn new<S>(
        stream: S,
        base_asym_algo: SpdmBaseAsymAlgo,
        req_asym_algo: SpdmReqAsymAlgo,
    ) -> Self
    where
        S: Read + Write + Send + Sync + 'static,
    {
        let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::CHAL_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP
            | SpdmRequestCapabilityFlags::HBEAT_CAP
            | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
        let req_capabilities = if cfg!(feature = "mut-auth") {
            req_capabilities | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        } else {
            req_capabilities
        };

        let config_info = common::SpdmConfigInfo {
            spdm_version: [
                Some(SpdmVersion::SpdmVersion10),
                Some(SpdmVersion::SpdmVersion11),
                Some(SpdmVersion::SpdmVersion12),
            ],
            req_capabilities,
            req_ct_exponent: 0,
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            base_asym_algo: base_asym_algo,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            dhe_algo: SpdmDheAlgo::SECP_384_R1,
            aead_algo: SpdmAeadAlgo::AES_256_GCM,
            req_asym_algo: req_asym_algo,
            key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
            data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
            max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
            secure_spdm_version: [
                Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
                Some(SecuredMessageVersion::try_from(0x11u8).unwrap()),
            ],
            ..Default::default()
        };

        let cert_provider = FileBasedCertProvider::new(true, true);
        let peer_root_cert_data = cert_provider.gen_root_cert().unwrap();

        let mut peer_root_cert_data_list = gen_array_clone(None, MAX_ROOT_CERT_SUPPORT);
        peer_root_cert_data_list[0] = Some(peer_root_cert_data);

        let provision_info = if cfg!(feature = "mut-auth") {
            spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
            let my_cert_chain_data = cert_provider.gen_full_cert_chain().unwrap();

            common::SpdmProvisionInfo {
                my_cert_chain_data: [
                    Some(my_cert_chain_data),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
                my_cert_chain: [None, None, None, None, None, None, None, None],
                peer_root_cert_data: peer_root_cert_data_list,
            }
        } else {
            common::SpdmProvisionInfo {
                my_cert_chain_data: [None, None, None, None, None, None, None, None],
                my_cert_chain: [None, None, None, None, None, None, None, None],
                peer_root_cert_data: peer_root_cert_data_list,
            }
        };

        let device_io = Arc::new(Mutex::new(FramedStream::new(stream)));
        let transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
            Arc::new(Mutex::new(SimpleTransportEncap {}));

        let context = requester::RequesterContext::new(
            device_io,
            transport_encap,
            Box::new(DummyMeasurementProvider {}),
            config_info,
            provision_info,
        );

        Self {
            context,
            session_id: None,
        }
    }
}

#[maybe_async]
impl GenericSecureTransPort for SpdmRequester {
    async fn negotiate(&mut self) -> Result<()> {
        let mut transcript_vca = None;
        if self
            .context
            .init_connection(&mut transcript_vca)
            .await
            .is_err()
        {
            panic!("init_connection failed!");
        }

        if self.context.send_receive_spdm_digest(None).await.is_err() {
            panic!("send_receive_spdm_digest failed!");
        }

        if self
            .context
            .send_receive_spdm_certificate(None, 0)
            .await
            .is_err()
        {
            panic!("send_receive_spdm_certificate failed!");
        }

        if self
            .context
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .is_err()
        {
            panic!("send_receive_spdm_challenge failed!");
        }

        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        if self
            .context
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .is_err()
        {
            panic!("send_receive_spdm_measurement failed!");
        }

        if transcript_meas.is_none() {
            panic!("get message_m from send_receive_spdm_measurement failed!");
        }

        let result = self
            .context
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await;
        match result {
            Ok(session_id) => {
                self.session_id = Some(session_id);
                Ok(())
            }
            Err(e) => Err(e)
                .kind(ErrorKind::SpdmNegotiate)
                .context("failed to setup session"),
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        // TODO: split message to blocks with negotiate_info.rsp_data_transfer_size_sel
        /* disable message send after shutdown() called */
        match self.session_id {
            Some(session_id) => self
                .context
                .send_message(Some(session_id), &bytes, true)
                .await
                .kind(ErrorKind::SpdmSend)
                .context("failed to send message"),
            None => Err(Error::kind_with_msg(
                ErrorKind::SpdmSessionNotReady,
                "session not ready, unknown session_id",
            )),
        }
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        // TODO: fix buf length too short
        // TODO: check is_app_message
        // let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        match self.session_id {
            Some(session_id) => self
                .context
                .receive_message(Some(session_id), &mut buf[..], true)
                .await
                .kind(ErrorKind::SpdmReceive)
                .context("failed to receive message"),
            None => Err(Error::kind_with_msg(
                ErrorKind::SpdmSessionNotReady,
                "session not ready, unknown session_id",
            )),
        }
    }

    // async fn shutdown(&mut self) -> Result<()> {
    //     if !self.shutdown_trigged {
    //         self.shutdown_trigged = true;
    //         self.context
    //             .end_session(self.session_id.unwrap())
    //             .await
    //             .kind(ErrorKind::SpdmShutdown)
    //             .context("failed to end session")
    //     } else {
    //         Err(Error::kind(ErrorKind::SpdmSessionShutdownTriggered))
    //     }
    // }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use std::net::TcpStream;

    #[maybe_async::maybe_async]
    async fn run_requester(
        stream: TcpStream,
        base_asym_algo: SpdmBaseAsymAlgo,
        req_asym_algo: SpdmReqAsymAlgo,
    ) -> Result<()> {
        let mut requester = SpdmRequester::new(stream, base_asym_algo, req_asym_algo);
        requester.negotiate().await?;

        for i in 0..1024u32 {
            requester.send(&i.to_be_bytes()).await?;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        for i in 1024..2048u32 {
            let expected = i.to_be_bytes();
            let expected_len = expected.len();
            let len = requester
                .receive(&mut receive_buffer[..expected_len])
                .await?;
            assert_eq!(expected_len, len);
            assert_eq!(expected, receive_buffer[..expected_len]);
        }

        // requester.shutdown().await?;
        Ok(())
    }

    #[test]
    fn test_spdm_over_tcp() -> Result<()> {
        let stream =
            TcpStream::connect("127.0.0.1:2323").expect("Couldn't connect to the server...");

        let base_asymalgo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384; // SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        let req_asym_algo = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384; // SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072

        #[cfg(not(feature = "is_sync"))]
        {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(Box::pin(run_requester(
                stream,
                base_asymalgo,
                req_asym_algo,
            )))
            .unwrap();
        }

        #[cfg(feature = "is_sync")]
        {
            run_requester(stream, base_asymalgo, req_asym_algo).unwrap();
        }
        Ok(())
    }
}
