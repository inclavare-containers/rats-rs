// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#![forbid(unsafe_code)]

use super::io::FramedStream;
use super::secret::asym_crypto::RatsSecretAsymSigner;
use super::secret::cert_provider::CertProvider;
use super::secret::cert_provider::EmptyCertProvider;
use super::secret::cert_provider::RatsCertProvider;
use super::secret::cert_validation::EmptyValidationContext;
use super::secret::cert_validation::RatsCertValidationStrategy;
use super::secret::cert_validation::ValidationContext;
use super::secret::measurement::EmptyMeasurementProvider;
use super::secret::measurement::RatsMeasurementProvider;
use super::transport::SimpleTransportEncap;
use super::VerifyMode;
use crate::crypto::AsymmetricAlgo;
use crate::crypto::HashAlgo;
use crate::errors::*;
use crate::tee::AutoAttester;
use crate::transport::GenericSecureTransPort;
use crate::CertBuilder;
use codec::{Codec, Reader};
use common::SpdmTransportEncap;
use core::convert::TryFrom;
use log::debug;
use maybe_async::maybe_async;
use spdmlib::common;
use spdmlib::common::SecuredMessageVersion;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::config;
use spdmlib::crypto::cert_operation::CertValidationStrategy;
use spdmlib::crypto::cert_operation::DefaultCertValidationStrategy;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::requester;
use spdmlib::secret::asym_sign::DefaultSecretAsymSigner;
use spdmlib::secret::asym_sign::SecretAsymSigner;
use spdmlib::secret::measurement::MeasurementProvider;
use spin::Mutex;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;

pub struct SpdmRequesterBuilder {
    verify_mode: VerifyMode,
    attest_self: bool,
}

impl SpdmRequesterBuilder {
    /// Creates a new `SpdmRequesterBuilder` instance with default settings.
    pub fn new() -> Self {
        Self {
            verify_mode: VerifyMode::VERIFY_PEER,
            attest_self: false,
        }
    }

    /// Sets the verification mode. If not specified, defaults to `VerifyMode:VERIFY_PEER`
    pub fn with_verify_mode(mut self, verify_mode: VerifyMode) -> Self {
        self.verify_mode = verify_mode;
        self
    }

    /// Sets whether to attest self to the peer. If not specified, defaults to `false`.
    pub fn with_attest_self(mut self, attest_self: bool) -> Self {
        self.attest_self = attest_self;
        self
    }

    pub fn build_with_stream<S>(&self, stream: S) -> Result<SpdmRequester>
    where
        S: Read + Write + Send + Sync + 'static,
    {
        let (cert_provider, asym_signer, measurement_provider) = if cfg!(feature = "mut-auth")
            && self.attest_self
        {
            let attester = AutoAttester::new();
            let cert_bundle =
                CertBuilder::new(attester, HashAlgo::Sha256).build(AsymmetricAlgo::P256)?;
            (
                Box::new(RatsCertProvider::new_der(cert_bundle.cert_to_der()?))
                    as Box<dyn CertProvider>,
                Box::new(RatsSecretAsymSigner::new(cert_bundle.private_key().clone()))
                    as Box<dyn SecretAsymSigner + Send + Sync>,
                Box::new(RatsMeasurementProvider::new_from_evidence(
                    cert_bundle.evidence(),
                )?) as Box<dyn MeasurementProvider + Send + Sync>,
            )
        } else {
            (
                Box::new(EmptyCertProvider {}) as Box<dyn CertProvider>,
                Box::new(DefaultSecretAsymSigner {})
                    as Box<dyn SecretAsymSigner + Send + Sync + 'static>,
                Box::new(EmptyMeasurementProvider {}) as Box<dyn MeasurementProvider + Send + Sync>,
            )
        };

        // TODO: merge validation_context into cert_validation_strategy and delete SpdmProvisionInfo::peer_root_cert_data of spdm-rs.
        let (validation_context, cert_validation_strategy) =
            if self.verify_mode.contains(VerifyMode::VERIFY_PEER) {
                (
                    Box::new(EmptyValidationContext {}) as Box<dyn ValidationContext>,
                    Box::new(RatsCertValidationStrategy {})
                        as Box<dyn CertValidationStrategy + Send + Sync>,
                )
            } else {
                (
                    Box::new(EmptyValidationContext {}) as Box<dyn ValidationContext>, // TODO: use a default rats-rs CA cert or change code of spdm-rs.
                    Box::new(DefaultCertValidationStrategy {})
                        as Box<dyn CertValidationStrategy + Send + Sync>,
                )
            };

        Ok(SpdmRequester::new(
            stream,
            cert_provider,
            validation_context,
            asym_signer,
            cert_validation_strategy,
            measurement_provider,
        ))
    }
}

pub struct SpdmRequester {
    context: requester::RequesterContext,
    session_id: Option<u32>,
}

impl SpdmRequester {
    pub fn new<S>(
        stream: S,
        cert_provider: Box<dyn CertProvider>,
        validation_context: Box<dyn ValidationContext>,
        asym_signer: Box<dyn SecretAsymSigner + Send + Sync>,
        cert_validation_strategy: Box<dyn CertValidationStrategy + Send + Sync>,
        measurement_provider: Box<dyn MeasurementProvider + Send + Sync>,
    ) -> Self
    where
        S: Read + Write + Send + Sync + 'static,
    {
        let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::CHAL_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP;
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
            base_asym_algo: SpdmBaseAsymAlgo::all(),
            base_hash_algo: asym_signer.supported_algo().0,
            dhe_algo: SpdmDheAlgo::SECP_384_R1,
            aead_algo: SpdmAeadAlgo::AES_256_GCM,
            req_asym_algo: SpdmReqAsymAlgo::from_bits_truncate(
                asym_signer.supported_algo().1.bits() as u16,
            ), /* cast here */
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

        let mut provision_info = common::SpdmProvisionInfo::default();
        provision_info.my_cert_chain_data[0] = cert_provider.get_full_cert_chain();
        provision_info.peer_root_cert_data[0] = validation_context.get_peer_root_cert();

        let device_io = Arc::new(Mutex::new(FramedStream::new(stream)));
        let transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
            Arc::new(Mutex::new(SimpleTransportEncap {}));

        let context = requester::RequesterContext::new(
            device_io,
            transport_encap,
            measurement_provider,
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
}

#[maybe_async]
impl GenericSecureTransPort for SpdmRequester {
    async fn negotiate(&mut self) -> Result<()> {
        let mut transcript_vca = None;
        self.context
            .init_connection(&mut transcript_vca)
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("init_connection failed")?;

        self.context
            .send_receive_spdm_digest(None)
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("send_receive_spdm_digest failed")?;

        self.context
            .send_receive_spdm_certificate(None, 0)
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("send_receive_spdm_certificate failed")?;

        self.context
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("send_receive_spdm_challenge failed")?;

        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let mut content_changed = None;
        let mut transcript_meas = None;

        self.context
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED
                    | SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED, /* Request raw bit stream so we can check measurement content provided by peer. */
                SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                &mut content_changed,
                &mut total_number,
                &mut spdm_measurement_record_structure,
                &mut transcript_meas,
            )
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("send_receive_spdm_measurement failed")?;

        if transcript_meas.is_none() {
            Err(Error::kind_with_msg(
                ErrorKind::SpdmNegotiate,
                "get message_m from send_receive_spdm_measurement failed",
            ))?;
        }

        {
            /* Print measurements info for debuging */
            let measurement_record_data = &spdm_measurement_record_structure
                .measurement_record_data[..spdm_measurement_record_structure
                .measurement_record_length
                .get() as usize];
            let mut reader = Reader::init(&measurement_record_data);
            let mut blocks = vec![];
            loop {
                if let Some(block) = SpdmMeasurementBlockStructure::read(&mut reader) {
                    blocks.push(block);
                } else {
                    break;
                }
            }

            let iter = blocks.iter().map(|block| {
                format!(
                    "index: {}, type: {:?}, representation: {:?}, value: {}",
                    block.index,
                    block.measurement.r#type,
                    block.measurement.representation,
                    hex::encode(&block.measurement.value[..block.measurement.value_size as usize])
                )
            });
            let block_str: String = itertools::Itertools::intersperse(iter, "\n".into()).collect();

            debug!("Result of GET_MEASUREMENTS: number_of_blocks: {}, content_changed: {content_changed:?}, blocks:\n{}", spdm_measurement_record_structure.number_of_blocks, block_str);
        }

        let session_id = self
            .context
            .start_session(
                false,
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .await
            .kind(ErrorKind::SpdmNegotiate)
            .context("failed to setup session")?;

        self.session_id = Some(session_id);
        Ok(())
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

    use spdmlib::{
        crypto::cert_operation::DefaultCertValidationStrategy,
        secret::asym_sign::DefaultSecretAsymSigner,
    };

    use crate::{
        cert::CertBuilder,
        crypto::{AsymmetricAlgo, HashAlgo},
        transport::spdm::secret::{
            asym_crypto::{tests::DummySecretAsymSigner, RatsSecretAsymSigner},
            cert_provider::{tests::DummyCertProvider, EmptyCertProvider, RatsCertProvider},
            cert_validation::{
                tests::DummyValidationContext, EmptyValidationContext, RatsCertValidationStrategy,
            },
        },
    };

    use super::*;
    use std::net::TcpStream;

    #[maybe_async::maybe_async]
    pub async fn run_requester(test_dummy: bool, stream: TcpStream) -> Result<()> {
        let (cert_provider, asym_signer, measurement_provider, cert_validation_strategy) =
            if cfg!(feature = "mut-auth") {
                if test_dummy {
                    (
                        Box::new(DummyCertProvider::new(true, true)) as Box<dyn CertProvider>,
                        Box::new(DummySecretAsymSigner {})
                            as Box<dyn SecretAsymSigner + Send + Sync + 'static>,
                        Box::new(EmptyMeasurementProvider {})
                            as Box<dyn MeasurementProvider + Send + Sync>,
                        Box::new(DefaultCertValidationStrategy {})
                            as Box<dyn CertValidationStrategy + Send + Sync>,
                    )
                } else {
                    let attester = AutoAttester::new();
                    let cert_bundle =
                        CertBuilder::new(attester, HashAlgo::Sha256).build(AsymmetricAlgo::P256)?;
                    (
                        Box::new(RatsCertProvider::new_der(cert_bundle.cert_to_der()?))
                            as Box<dyn CertProvider>,
                        Box::new(RatsSecretAsymSigner::new(cert_bundle.private_key().clone()))
                            as Box<dyn SecretAsymSigner + Send + Sync>,
                        Box::new(RatsMeasurementProvider::new_from_evidence(
                            cert_bundle.evidence(),
                        )?) as Box<dyn MeasurementProvider + Send + Sync>,
                        Box::new(RatsCertValidationStrategy {})
                            as Box<dyn CertValidationStrategy + Send + Sync>,
                    )
                }
            } else {
                (
                    Box::new(EmptyCertProvider {}) as Box<dyn CertProvider>,
                    Box::new(DefaultSecretAsymSigner {})
                        as Box<dyn SecretAsymSigner + Send + Sync + 'static>,
                    Box::new(EmptyMeasurementProvider {})
                        as Box<dyn MeasurementProvider + Send + Sync>,
                    if test_dummy {
                        Box::new(DefaultCertValidationStrategy {})
                            as Box<dyn CertValidationStrategy + Send + Sync>
                    } else {
                        Box::new(RatsCertValidationStrategy {})
                            as Box<dyn CertValidationStrategy + Send + Sync>
                    },
                )
            };

        let validation_context = if test_dummy {
            Box::new(DummyValidationContext::new(true)) as Box<dyn ValidationContext>
        } else {
            Box::new(EmptyValidationContext {}) as Box<dyn ValidationContext>
        };

        let mut requester = SpdmRequester::new(
            stream,
            cert_provider,
            validation_context,
            asym_signer,
            cert_validation_strategy,
            measurement_provider,
        );
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
}
