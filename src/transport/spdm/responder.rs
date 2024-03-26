// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use super::secret::cert::{CertProvider, ValidationContext};
use super::secret::measurement::DummyMeasurementProvider;
use super::watchdog_impl_sample::init_watchdog;
use codec::Codec;
use common::SpdmTransportEncap;
use core::convert::TryFrom;
use maybe_async::maybe_async;
use spdmlib::common::session::SpdmSessionState;
use spdmlib::common::{SecuredMessageVersion, SpdmOpaqueSupport};
use spdmlib::crypto::cert_operation::CertValidationStrategy;
use spdmlib::secret::asym_sign::SecretAsymSigner;
use std::io::{Read, Write};
// TODO: secret_impl_sample for measurements
// use spdm_emu::{secret_impl_sample::*, EMU_STACK_SIZE};
use spdmlib::{
    common, config,
    protocol::*,
    responder::{self, ProcessMessageResult},
};
use spin::Mutex;
extern crate alloc;
use crate::errors::*;
use crate::transport::spdm::io::FramedStream;
use crate::transport::spdm::transport::SimpleTransportEncap;
use crate::transport::GenericSecureTransPort;
use alloc::sync::Arc;

pub struct SpdmResonder {
    context: responder::ResponderContext,
    session_id: Option<u32>,
}

impl SpdmResonder {
    pub fn new<S>(
        stream: S,
        cert_provider: Box<dyn CertProvider>,
        validation_context: Box<dyn ValidationContext>,
        asym_signer: Box<dyn SecretAsymSigner + Send + Sync>,
        cert_validation_strategy: Box<dyn CertValidationStrategy + Send + Sync>,
    ) -> Self
    where
        S: Read + Write + Send + Sync + 'static,
    {
        let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::ENCAP_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        let rsp_capabilities = if cfg!(feature = "mut-auth") {
            rsp_capabilities | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        } else {
            rsp_capabilities
        };

        let config_info = common::SpdmConfigInfo {
            spdm_version: [
                Some(SpdmVersion::SpdmVersion10),
                Some(SpdmVersion::SpdmVersion11),
                Some(SpdmVersion::SpdmVersion12),
            ],
            rsp_capabilities,
            rsp_ct_exponent: 0,
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
            base_asym_algo: asym_signer.supported_algo().1,
            base_hash_algo: asym_signer.supported_algo().0,
            dhe_algo: SpdmDheAlgo::SECP_384_R1,
            aead_algo: SpdmAeadAlgo::AES_256_GCM,
            req_asym_algo: SpdmReqAsymAlgo::all(),
            key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
            data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
            max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
            heartbeat_period: config::HEARTBEAT_PERIOD,
            secure_spdm_version: [
                Some(SecuredMessageVersion::try_from(0x10u8).unwrap()),
                Some(SecuredMessageVersion::try_from(0x11u8).unwrap()),
            ],
            ..Default::default()
        };

        let mut provision_info = common::SpdmProvisionInfo::default();
        provision_info.my_cert_chain_data[0] = cert_provider.get_full_cert_chain();
        provision_info.peer_root_cert_data[0] = validation_context.get_peer_root_cert();

        init_watchdog();

        let device_io = Arc::new(Mutex::new(FramedStream::new(stream)));
        let transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
            Arc::new(Mutex::new(SimpleTransportEncap {}));

        let context = responder::ResponderContext::new(
            device_io,
            transport_encap,
            Box::new(DummyMeasurementProvider {}),
            asym_signer,
            cert_validation_strategy,
            config_info,
            provision_info,
        );

        Self {
            context,
            session_id: None,
        }
    }

    pub fn ensure_session_established(&self, session_id: u32) -> Result<()> {
        /* check spdm session state */
        let spdm_session = match self.context.common.get_immutable_session_via_id(session_id) {
            Some(v) => v,
            None => {
                return Err(Error::kind_with_msg(
                    ErrorKind::SpdmBrokenSession,
                    format!("failed to get session of session_id: {}", session_id),
                ));
            }
        };

        if spdm_session.get_session_state() != SpdmSessionState::SpdmSessionEstablished {
            return Err(Error::kind_with_msg(
                ErrorKind::SpdmSessionNotReady,
                format!("the session is not ready, session_id: {}", session_id),
            ));
        }
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPort for SpdmResonder {
    async fn negotiate(&mut self) -> Result<()> {
        let mut raw_packet = [0u8; config::RECEIVER_BUFFER_SIZE];
        let mut spdm_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        loop {
            let res = self
                .context
                .process_message(false, &mut raw_packet, &mut spdm_buffer)
                .await;
            match res {
                ProcessMessageResult::Success { used }
                | ProcessMessageResult::SuccessSecured {
                    used,
                    decode_size: _,
                    is_app_message: _,
                } => {
                    let mut read = codec::Reader::init(&raw_packet[0..used]);
                    let session_id = match u32::read(&mut read) {
                        Some(v) => v,
                        None => {
                            break Err(Error::kind_with_msg(
                                ErrorKind::SpdmNegotiate,
                                "failed to get session_id",
                            ));
                        }
                    };
                    match self.context.common.get_immutable_session_via_id(session_id) {
                        Some(spdm_session) => {
                            /* Waiting until state is SpdmSessionState::SpdmSessionEstablished */
                            if spdm_session.get_session_state()
                                == SpdmSessionState::SpdmSessionEstablished
                            {
                                self.session_id = Some(session_id);
                                break Ok(());
                            }
                        }
                        None => {
                            /* The spdm_session object setup is done at KEY_EXCHANGE/KEY_EXCHANGE_RSP. And the spdm_session is None before it. */
                            continue;
                        }
                    };
                }
                ProcessMessageResult::SpdmHandleError(spdm_status) => {
                    return Err(spdm_status)
                        .kind(ErrorKind::SpdmNegotiate)
                        .context("process_message failed while handling SPDM message")
                }
                ProcessMessageResult::DecodeError(_used) => {
                    return Err(Error::kind_with_msg(
                        ErrorKind::SpdmNegotiate,
                        "failed while parsing transport data",
                    ));
                }
            }
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        // TODO: may conflict with response expected by requester (bidirectional communication problem)

        // TODO: split message to blocks with negotiate_info.rsp_data_transfer_size_sel
        match self.session_id {
            Some(session_id) => {
                self.ensure_session_established(session_id)?;
                self.context
                    .send_message(Some(session_id), &bytes, true)
                    .await
                    .kind(ErrorKind::SpdmSend)
                    .context("failed to send message")
            }
            None => Err(Error::kind_with_msg(
                ErrorKind::SpdmSessionNotReady,
                "session not ready, unknown session_id",
            )),
        }
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.session_id.is_none() {
            return Err(Error::kind_with_msg(
                ErrorKind::SpdmSessionNotReady,
                "session not ready, unknown session_id",
            ));
        };

        let mut raw_packet = [0u8; config::RECEIVER_BUFFER_SIZE];
        let mut spdm_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        loop {
            let res = self
                .context
                .process_message(false, &mut raw_packet, &mut spdm_buffer)
                .await;
            match res {
                ProcessMessageResult::Success { used: _ } => continue,
                ProcessMessageResult::SuccessSecured {
                    used,
                    decode_size,
                    is_app_message,
                } => {
                    let mut read = codec::Reader::init(&raw_packet[0..used]);
                    let session_id = match u32::read(&mut read) {
                        Some(v) => v,
                        None => {
                            break Err(Error::kind_with_msg(
                                ErrorKind::SpdmReceive,
                                "failed to get session_id",
                            ));
                        }
                    };
                    if session_id != self.session_id.unwrap() {
                        break Err(Error::kind_with_msg(
                            ErrorKind::SpdmReceive,
                            format!(
                                "session_id mismatch, expected {}, got {}",
                                self.session_id.unwrap(),
                                session_id,
                            ),
                        ));
                    }

                    if is_app_message {
                        /* copy received data to user provided buffer */
                        // TODO: store remain messages
                        let data_len_to_copy = std::cmp::min(buf.len(), decode_size);
                        buf[..data_len_to_copy].copy_from_slice(&spdm_buffer[..data_len_to_copy]);
                        return Ok(data_len_to_copy);
                    } else {
                        self.ensure_session_established(session_id)?;
                    }
                }
                ProcessMessageResult::SpdmHandleError(spdm_status) => {
                    return Err(spdm_status)
                        .kind(ErrorKind::SpdmReceive)
                        .context("process_message failed while handling SPDM message")
                }
                ProcessMessageResult::DecodeError(_used) => {
                    return Err(Error::kind_with_msg(
                        ErrorKind::SpdmReceive,
                        "failed while parsing transport data",
                    ));
                }
            }
        }
    }

    // async fn shutdown(&mut self) -> Result<()> {
    //     // TODO:
    //     Ok(())
    // }
}

#[cfg(test)]
pub mod tests {

    use spdmlib::crypto::cert_operation::DefaultCertValidationStrategy;

    use crate::{
        attester::sgx_dcap::SgxDcapAttester,
        cert::CertBuilder,
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        transport::spdm::secret::{
            asym_crypto::{tests::DummySecretAsymSigner, RatsSecretAsymSigner},
            cert::{
                tests::{DummyCertProvider, DummyValidationContext},
                EmptyValidationContext, RatsCertProvider, RatsCertValidationStrategy,
            },
        },
    };

    use super::super::requester::tests::run_requester;
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[maybe_async::maybe_async]
    pub async fn run_responder(test_dummy: bool, stream: TcpStream) -> Result<()> {
        let (cert_provider, asym_signer, cert_validation_strategy) = if test_dummy {
            (
                Box::new(DummyCertProvider::new(true, false)) as Box<dyn CertProvider>,
                Box::new(DummySecretAsymSigner {}) as Box<dyn SecretAsymSigner + Send + Sync>,
                Box::new(DefaultCertValidationStrategy {})
                    as Box<dyn CertValidationStrategy + Send + Sync>,
            )
        } else {
            let attester = SgxDcapAttester::new();
            let key = DefaultCrypto::gen_private_key(AsymmetricAlgo::P256)?;
            let cert =
                CertBuilder::new(attester, HashAlgo::Sha256).build_der_with_private_key(&key)?;
            (
                Box::new(RatsCertProvider::new(cert)) as Box<dyn CertProvider>,
                Box::new(RatsSecretAsymSigner::new(key)) as Box<dyn SecretAsymSigner + Send + Sync>,
                Box::new(RatsCertValidationStrategy {})
                    as Box<dyn CertValidationStrategy + Send + Sync>,
            )
        };

        let validation_context = if cfg!(feature = "mut-auth") && test_dummy {
            Box::new(DummyValidationContext::new(true)) as Box<dyn ValidationContext>
        } else {
            Box::new(EmptyValidationContext {}) as Box<dyn ValidationContext>
        };

        let mut responder = SpdmResonder::new(
            stream,
            cert_provider,
            validation_context,
            asym_signer,
            cert_validation_strategy,
        );
        responder.negotiate().await?;

        for i in 1024..2048u32 {
            responder.send(&i.to_be_bytes()).await?;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        for i in 0..1024u32 {
            let expected = i.to_be_bytes();
            let expected_len = expected.len();
            let len = responder
                .receive(&mut receive_buffer[..expected_len])
                .await?;
            assert_eq!(expected_len, len);
            assert_eq!(expected, receive_buffer[..expected_len]);
        }

        // responder.shutdown().await?;

        Ok(())
    }

    #[test]
    fn test_spdm_over_tcp() -> Result<()> {
        let test_dummy = true; /* set this to `false` for testing with dice cert */

        let t1 = std::thread::spawn(move || {
            let listener =
                TcpListener::bind("127.0.0.1:2323").expect("Couldn't bind to the server");
            println!("server start!");

            println!("waiting for next connection!");
            let (stream, _) = listener.accept().expect("Read stream error!");
            println!("new connection!");

            #[cfg(not(feature = "is_sync"))]
            {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(run_responder(test_dummy, stream)).unwrap();
            }

            #[cfg(feature = "is_sync")]
            {
                run_responder(test_dummy, stream).unwrap();
            }
        });

        let t2 = std::thread::spawn(move || {
            let stream =
                TcpStream::connect("127.0.0.1:2323").expect("Couldn't connect to the server...");

            #[cfg(not(feature = "is_sync"))]
            {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(Box::pin(run_requester(test_dummy, stream)))
                    .unwrap();
            }

            #[cfg(feature = "is_sync")]
            {
                run_requester(test_dummy, stream).unwrap();
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();
        Ok(())
    }
}
