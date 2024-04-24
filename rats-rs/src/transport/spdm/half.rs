use super::io::FramedStream;
use crate::errors::*;
use crate::transport::GenericSecureTransPortRead;
use crate::transport::GenericSecureTransPortWrite;
use log::debug;
use log::warn;
use maybe_async::maybe_async;
use spdmlib::common::SpdmContext;
use spdmlib::common::SpdmDeviceIo;
use spdmlib::config;
use spin::Mutex;
use std::net::TcpStream;
use std::sync::Arc;

pub struct ReadHalf {
    pub(crate) is_requester: bool,
    pub(crate) session_id: u32,
    pub(crate) common: Arc<Mutex<SpdmContext>>,
    // TODO: Should use Box<dyn SpdmDeviceIo + Send + Sync> here, but is limited by the design of spdm-rs.
    pub(crate) device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>, /* Should only call it's `send()` function */
}

pub struct WriteHalf {
    pub(crate) is_requester: bool,
    pub(crate) session_id: u32,
    pub(crate) common: Arc<Mutex<SpdmContext>>,
    // TODO: Should use Box<dyn SpdmDeviceIo + Send + Sync> here, but is limited by the design of spdm-rs.
    pub(crate) device_io: Arc<Mutex<dyn SpdmDeviceIo + Send + Sync>>, /* Should only call it's `receive()` and `flush()` functions */
}

#[maybe_async]
impl GenericSecureTransPortWrite for WriteHalf {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        // TODO: When using in responder side, this may conflict with response expected by requester (bidirectional communication problem)
        // TODO: split message to blocks with negotiate_info.rsp_data_transfer_size_sel
        // TODO: disable message send after shutdown() called

        debug!("session({}) send() {} bytes", self.session_id, bytes.len());

        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used;
        {
            let mut common = self.common.lock();
            if common.negotiate_info.rsp_data_transfer_size_sel != 0
                && bytes.len() > common.negotiate_info.rsp_data_transfer_size_sel as usize
            {
                return Err(Error::kind_with_msg(
                    ErrorKind::SpdmSend,
                    format!(
                        "The buffer cannot be longer than {}",
                        common.negotiate_info.rsp_data_transfer_size_sel
                    ),
                ));
            }

            used = common
                .encode_secured_message(
                    self.session_id,
                    bytes,
                    &mut transport_buffer,
                    self.is_requester,
                    true,
                )
                .await
                .kind(ErrorKind::SpdmSend)
                .context("Failed to encode as secured message")?;
        }

        /* Note here we use our local device_io instead of self.common.device_io */
        let mut device_io = self.device_io.lock();
        device_io
            .send(Arc::new(&transport_buffer[..used]))
            .await
            .kind(ErrorKind::SpdmSend)
            .context("Failed to send message to device_io")?;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // TODO: rewrite this to make it transport layer independent
        let mut device_io = self.device_io.lock();
        let any = device_io.as_any();
        if let Some(framed_stream) = any.downcast_mut::<FramedStream<TcpStream>>() {
            framed_stream
                .stream
                .shutdown(std::net::Shutdown::Write)
                .kind(ErrorKind::SpdmShutdown)
                .context("Failed to end session")?
        } else {
            warn!("The shutdown() is not supported by the underling stream type");
        }
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for ReadHalf {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        // TODO: fix buf length too short

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let timeout = {
            let common = self.common.lock();
            2 << common.negotiate_info.rsp_ct_exponent_sel
        };

        let used = {
            let mut device_io = self.device_io.lock();
            device_io
                .receive(Arc::new(Mutex::new(&mut transport_buffer)), timeout)
                .await
                .kind(ErrorKind::SpdmReceive)
                .context("Failed to receive message from device_io")?
        };

        let (used, is_app_message) = {
            let mut common = self.common.lock();
            common
                .decode_secured_message(
                    self.session_id,
                    &transport_buffer[..used],
                    buf,
                    !self.is_requester,
                )
                .await
                .kind(ErrorKind::SpdmReceive)
                .context("Failed to decode as secured message")?
        };
        if !is_app_message {
            Err(Error::kind_with_msg(
                ErrorKind::SpdmReceive,
                "App message is expected",
            ))?
        }

        debug!("session({}) receive() {used} bytes", self.session_id);
        Ok(used)
    }
}
