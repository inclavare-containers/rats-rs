//! A Transport Message is a packet consisting of a header and body. Its design shares similarities with MCTP.
//! For reference of MCTP, see: https://www.dmtf.org/sites/default/files/standards/documents/DSP0245_1.2.0.pdf

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmTransportEncap;
use spdmlib::error::{
    SpdmResult, SPDM_STATUS_DECAP_APP_FAIL, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_APP_FAIL,
    SPDM_STATUS_ENCAP_FAIL,
};
extern crate alloc;
use alloc::sync::Arc;
use core::ops::Deref;
use core::ops::DerefMut;
use spin::Mutex;

enum_builder! {
    /// Enumeration of message types for the Transport Message.
    @U8
    EnumName: SimpleTransportMessageType;
    EnumVal{
        /// Message type for SPDM messages.
        Spdm => 0x00,
        /// Message type for Secured messages. The plaintext is either an SDPM message or an APP message.
        Secured => 0x01,
        /// Message type for APP messages.
        App => 0x02
    }
}

impl Default for SimpleTransportMessageType {
    fn default() -> SimpleTransportMessageType {
        SimpleTransportMessageType::Spdm
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SimpleTransportMessageHeader {
    pub r#type: SimpleTransportMessageType,
}

impl Codec for SimpleTransportMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.r#type.encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SimpleTransportMessageHeader> {
        let r#type = SimpleTransportMessageType::read(r)?;
        Some(SimpleTransportMessageHeader { r#type })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SimpleTransportEncap {}

#[maybe_async::maybe_async]
impl SpdmTransportEncap for SimpleTransportEncap {
    async fn encap(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        transport_buffer: Arc<Mutex<&mut [u8]>>,
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut transport_buffer = transport_buffer.lock();
        let transport_buffer = transport_buffer.deref_mut();
        let mut writer = Writer::init(transport_buffer);
        let mctp_header = SimpleTransportMessageHeader {
            r#type: if secured_message {
                SimpleTransportMessageType::Secured
            } else {
                SimpleTransportMessageType::Spdm
            },
        };
        mctp_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_FAIL)?;
        let header_size = writer.used();
        if transport_buffer.len() < header_size + payload_len {
            return Err(SPDM_STATUS_ENCAP_FAIL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(&spdm_buffer);
        Ok(header_size + payload_len)
    }

    /// Decapsulates a packet as a Transport Message.
    ///
    /// Returns `Err` if it's neither Spdm message nor Secured message, or if the SPDM buffer cannot accommodate.
    async fn decap(
        &mut self,
        transport_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let transport_buffer: &[u8] = transport_buffer.deref();
        let mut reader = Reader::init(transport_buffer);
        let secured_message;
        match SimpleTransportMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                SimpleTransportMessageType::Spdm => {
                    secured_message = false;
                }
                SimpleTransportMessageType::Secured => {
                    secured_message = true;
                }
                v => {
                    println!(
                        "decap err: Spdm message and Secured message expected, but got message type: {:x?}",
                        v
                    );
                    return Err(SPDM_STATUS_DECAP_FAIL);
                }
            },
            None => return Err(SPDM_STATUS_DECAP_FAIL),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    async fn encap_app(
        &mut self,
        spdm_buffer: Arc<&[u8]>,
        app_buffer: Arc<Mutex<&mut [u8]>>,
        is_app_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut app_buffer = app_buffer.lock();
        let app_buffer = app_buffer.deref_mut();
        let mut writer = Writer::init(app_buffer);
        let mctp_header = if is_app_message {
            SimpleTransportMessageHeader {
                r#type: SimpleTransportMessageType::App,
            }
        } else {
            SimpleTransportMessageHeader {
                r#type: SimpleTransportMessageType::Spdm,
            }
        };
        mctp_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_APP_FAIL)?;
        let header_size = writer.used();
        if app_buffer.len() < header_size + payload_len {
            return Err(SPDM_STATUS_ENCAP_APP_FAIL);
        }
        app_buffer[header_size..(header_size + payload_len)].copy_from_slice(&spdm_buffer);
        Ok(header_size + payload_len)
    }

    /// Decapsulates a packet as a Transport Message.
    ///
    /// Returns `Err` if it's neither Secured message nor App message, or if the SPDM buffer cannot accommodate.
    async fn decap_app(
        &mut self,
        app_buffer: Arc<&[u8]>,
        spdm_buffer: Arc<Mutex<&mut [u8]>>,
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&app_buffer);
        let mut is_app_mesaage = false;
        match SimpleTransportMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                SimpleTransportMessageType::Spdm => {}
                SimpleTransportMessageType::App => {
                    is_app_mesaage = true;
                }
                v => {
                    println!("decap_app err: Spdm message and App message expected, but got message type: {:x?}", v);
                    return Err(SPDM_STATUS_DECAP_APP_FAIL);
                }
            },
            None => return Err(SPDM_STATUS_DECAP_APP_FAIL),
        }
        let header_size = reader.used();
        let payload_size = app_buffer.len() - header_size;
        let mut spdm_buffer = spdm_buffer.lock();
        let spdm_buffer = spdm_buffer.deref_mut();
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_APP_FAIL);
        }
        let payload = &app_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, is_app_mesaage))
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        2 /* @imlk: do we need this? */
    }
    fn get_max_random_count(&mut self) -> u16 {
        32
    }
}
