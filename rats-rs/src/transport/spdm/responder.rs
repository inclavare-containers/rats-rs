use super::half::{ReadHalf, WriteHalf};
use super::secret::asym_crypto::RatsSecretAsymSigner;
use super::secret::cert_provider::{CertProvider, EmptyCertProvider, RatsCertProvider};
use super::secret::cert_validation::{
    EmptyValidationContext, RatsCertValidationStrategy, ValidationContext,
};
use super::secret::measurement::{EmptyMeasurementProvider, RatsMeasurementProvider};
use super::VerifyMode;
use codec::Codec;
use common::SpdmTransportEncap;
use log::{debug, warn};
use maybe_async::maybe_async;
use spdmlib::common::session::SpdmSessionState;
use spdmlib::common::{SecuredMessageVersion, SpdmOpaqueSupport};
use spdmlib::crypto::cert_operation::{CertValidationStrategy, DefaultCertValidationStrategy};
use spdmlib::secret::asym_sign::{DefaultSecretAsymSigner, SecretAsymSigner};
use spdmlib::secret::measurement::MeasurementProvider;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::DerefMut;
// TODO: secret_impl_sample for measurements
// use spdm_emu::{secret_impl_sample::*, EMU_STACK_SIZE};
use spdmlib::{
    common, config,
    protocol::*,
    responder::{self, ProcessMessageResult},
};
use spin::Mutex;
extern crate alloc;
use crate::cert::create::CertBuilder;
use crate::crypto::{AsymmetricAlgo, HashAlgo};
use crate::errors::*;
use crate::tee::AutoAttester;
use crate::transport::spdm::io::FramedStream;
use crate::transport::spdm::transport::SimpleTransportEncap;
use crate::transport::GenericSecureTransPort;
use alloc::sync::Arc;
use spdmlib::common::SpdmDeviceIo;

pub struct SpdmResponderBuilder {
    verify_mode: VerifyMode,
    attest_self: bool,
}

impl SpdmResponderBuilder {
    /// Creates a new `SpdmResponderBuilder` instance with default settings.
    pub fn new() -> Self {
        Self {
            verify_mode: VerifyMode::VERIFY_NONE,
            attest_self: true,
        }
    }

    /// Sets the verification mode. If not specified, defaults to `VerifyMode:VERIFY_NONE`
    pub fn with_verify_mode(mut self, verify_mode: VerifyMode) -> Self {
        self.verify_mode = verify_mode;
        self
    }

    /// Sets whether to attest self to the peer. If not specified, defaults to `true`.
    pub fn with_attest_self(mut self, attest_self: bool) -> Self {
        self.attest_self = attest_self;
        self
    }

    #[maybe_async::maybe_async]
    pub async fn build_with_tcp_stream(&self, stream: TcpStream) -> Result<SpdmResponder> {
        let (cert_provider, asym_signer, measurement_provider) = if self.attest_self {
            // TODO: generate cert and key for each handshake and check nonce from user
            let attester = AutoAttester::new();
            let cert_bundle = CertBuilder::new(attester, HashAlgo::Sha256)
                .build(AsymmetricAlgo::P256)
                .await?;
            (
                Box::new(RatsCertProvider::new_der(cert_bundle.cert_to_der()?))
                    as Box<dyn CertProvider>,
                Box::new(RatsSecretAsymSigner::new(
                    cert_bundle.private_key().clone(),
                    HashAlgo::Sha256,
                )) as Box<dyn SecretAsymSigner + Send + Sync>,
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

        Ok(SpdmResponder::new(
            stream,
            cert_provider,
            validation_context,
            asym_signer,
            cert_validation_strategy,
            measurement_provider,
        ))
    }
}

pub struct SpdmResponder {
    stream: TcpStream,
    context: responder::ResponderContext,
    session_id: Option<u32>,
}

impl SpdmResponder {
    pub fn new(
        stream: TcpStream,
        cert_provider: Box<dyn CertProvider>,
        validation_context: Box<dyn ValidationContext>,
        asym_signer: Box<dyn SecretAsymSigner + Send + Sync>,
        cert_validation_strategy: Box<dyn CertValidationStrategy + Send + Sync>,
        measurement_provider: Box<dyn MeasurementProvider + Send + Sync>,
    ) -> Self {
        let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::ENCAP_CAP;
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

        let device_io = Arc::new(Mutex::new(FramedStream::new(stream.try_clone().unwrap())));
        let transport_encap: Arc<Mutex<(dyn SpdmTransportEncap + Send + Sync)>> =
            Arc::new(Mutex::new(SimpleTransportEncap {}));

        let context = responder::ResponderContext::new(
            device_io,
            transport_encap,
            measurement_provider,
            asym_signer,
            cert_validation_strategy,
            config_info,
            provision_info,
        );

        Self {
            stream,
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

    pub fn into_split(self) -> Result<(ReadHalf, WriteHalf)> {
        let session_id = self.session_id.ok_or(Error::kind_with_msg(
            ErrorKind::SpdmSessionNotReady,
            "session not ready, unknown session_id",
        ))?;

        /* We reuse self.context.common.device_io here, since FramedStream::read_buffer may not be empty. */
        let device_io_read_half = self.context.common.device_io.clone();
        let common = Arc::new(Mutex::new(self.context.common));

        Ok((
            ReadHalf {
                is_requester: false,
                session_id,
                common: common.clone(),
                device_io: device_io_read_half,
            },
            WriteHalf {
                is_requester: false,
                session_id,
                common,
                /* Create a new device_io here, to avoid deadlocks when reading and writing device_io at the same time. This is caused by the design limitation of SpdmDeviceIo */
                device_io: Arc::new(Mutex::new(FramedStream::new(self.stream))),
            },
        ))
    }
}

#[maybe_async]
impl GenericSecureTransPort for SpdmResponder {
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
}

#[cfg(test)]
pub mod tests {

    use itertools::iproduct;
    use log::LevelFilter;
    use spdmlib::crypto::cert_operation::DefaultCertValidationStrategy;

    use crate::{
        cert::create::CertBuilder,
        crypto::{AsymmetricAlgo, HashAlgo},
        tee::{AutoAttester, TeeType},
        transport::{
            spdm::secret::{
                asym_crypto::{tests::DummySecretAsymSigner, RatsSecretAsymSigner},
                cert_provider::{tests::DummyCertProvider, RatsCertProvider},
                cert_validation::{
                    tests::DummyValidationContext, EmptyValidationContext,
                    RatsCertValidationStrategy,
                },
                measurement::EmptyMeasurementProvider,
            },
            GenericSecureTransPortRead, GenericSecureTransPortWrite,
        },
    };

    use super::super::requester::tests::run_requester;
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[maybe_async::maybe_async]
    pub async fn run_responder(
        test_dummy: bool,
        stream: TcpStream,
        hash_algo: HashAlgo,
        asym_algo: AsymmetricAlgo,
    ) -> Result<()> {
        let (cert_provider, asym_signer, measurement_provider, cert_validation_strategy) =
            if test_dummy {
                (
                    Box::new(DummyCertProvider::new(true, false)) as Box<dyn CertProvider>,
                    Box::new(DummySecretAsymSigner {}) as Box<dyn SecretAsymSigner + Send + Sync>,
                    Box::new(EmptyMeasurementProvider {})
                        as Box<dyn MeasurementProvider + Send + Sync>,
                    Box::new(DefaultCertValidationStrategy {})
                        as Box<dyn CertValidationStrategy + Send + Sync>,
                )
            } else {
                let attester = AutoAttester::new();
                let cert_bundle = CertBuilder::new(attester, hash_algo)
                    .build(asym_algo)
                    .await?;
                (
                    Box::new(RatsCertProvider::new_der(cert_bundle.cert_to_der()?))
                        as Box<dyn CertProvider>,
                    Box::new(RatsSecretAsymSigner::new(
                        cert_bundle.private_key().clone(),
                        hash_algo,
                    )) as Box<dyn SecretAsymSigner + Send + Sync>,
                    Box::new(RatsMeasurementProvider::new_from_evidence(
                        cert_bundle.evidence(),
                    )?) as Box<dyn MeasurementProvider + Send + Sync>,
                    Box::new(RatsCertValidationStrategy {})
                        as Box<dyn CertValidationStrategy + Send + Sync>,
                )
            };

        let validation_context = if cfg!(feature = "mut-auth") && test_dummy {
            Box::new(DummyValidationContext::new(true)) as Box<dyn ValidationContext>
        } else {
            Box::new(EmptyValidationContext {}) as Box<dyn ValidationContext>
        };

        let mut responder = SpdmResponder::new(
            stream,
            cert_provider,
            validation_context,
            asym_signer,
            cert_validation_strategy,
            measurement_provider,
        );
        responder.negotiate().await?;

        let (mut read_half, mut write_half) = responder.into_split()?;

        for i in 1024..2048u32 {
            write_half.send(&i.to_be_bytes()).await?;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        for i in 0..1024u32 {
            let expected = i.to_be_bytes();
            let expected_len = expected.len();
            let len = read_half
                .receive(&mut receive_buffer[..expected_len])
                .await?;
            assert_eq!(expected_len, len);
            assert_eq!(expected, receive_buffer[..expected_len]);
        }

        write_half.shutdown().await?;

        Ok(())
    }

    const THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;

    #[maybe_async::maybe_async]
    #[cfg_attr(feature = "is-sync", test)]
    #[cfg_attr(not(feature = "is-sync"), tokio::test)]
    async fn test_spdm_over_tcp() -> Result<()> {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .try_init();

        let test_dummy = match TeeType::detect_env() {
            Some(_) => false, /* Testing with dice cert */
            None => true,
        };

        for (requested_measurement_summary_hash_type, hash_algo, asym_algo) in [
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
                HashAlgo::Sha256,
                AsymmetricAlgo::Rsa2048,
            ),
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
                HashAlgo::Sha384,
                AsymmetricAlgo::Rsa3072,
            ),
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
                HashAlgo::Sha512,
                AsymmetricAlgo::Rsa4096,
            ),
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
                HashAlgo::Sha256,
                AsymmetricAlgo::P256,
            ),
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
                HashAlgo::Sha256,
                AsymmetricAlgo::P256,
            ),
            (
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                HashAlgo::Sha256,
                AsymmetricAlgo::P256,
            ),
        ] {
            // for (hash_algo, asym_algo) in [(HashAlgo::Sha256, AsymmetricAlgo::Rsa3072)] {
            println!("test hash_algo({hash_algo:?}) + asym_algo({asym_algo:?})");
            let requester_func = move || {
                let stream = TcpStream::connect("127.0.0.1:2323")
                    .expect("Couldn't connect to the server...");

                #[cfg(not(feature = "is-sync"))]
                {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(Box::pin(run_requester(
                        test_dummy,
                        stream,
                        hash_algo,
                        asym_algo,
                        requested_measurement_summary_hash_type,
                    )))
                    .unwrap();
                }

                #[cfg(feature = "is-sync")]
                {
                    run_requester(
                        test_dummy,
                        stream,
                        hash_algo,
                        asym_algo,
                        requested_measurement_summary_hash_type,
                    )
                    .unwrap();
                }
            };

            let responder_func = move || {
                let listener =
                    TcpListener::bind("127.0.0.1:2323").expect("Couldn't bind to the server");
                println!("server start!");

                let builder = std::thread::Builder::new().stack_size(THREAD_STACK_SIZE);
                let t2 = builder.spawn(requester_func).unwrap();

                println!("waiting for next connection!");
                let (stream, _) = listener.accept().expect("Read stream error!");
                println!("new connection!");

                #[cfg(not(feature = "is-sync"))]
                {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(run_responder(test_dummy, stream, hash_algo, asym_algo))
                        .unwrap();
                }

                #[cfg(feature = "is-sync")]
                {
                    run_responder(test_dummy, stream, hash_algo, asym_algo).unwrap();
                }

                t2.join().unwrap();
            };

            let builder = std::thread::Builder::new().stack_size(THREAD_STACK_SIZE);
            let t1 = builder.spawn(responder_func).unwrap();

            t1.join().unwrap();
        }

        Ok(())
    }
}
