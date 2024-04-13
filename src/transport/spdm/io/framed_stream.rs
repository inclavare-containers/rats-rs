extern crate alloc;

use codec::{Codec, Reader, Writer};
use log::{error, trace, warn};
use spdmlib::common::SpdmDeviceIo;
use spdmlib::config;
use spdmlib::error::{SpdmResult, SPDM_STATUS_SEND_FAIL};
use spin::Mutex;

use alloc::sync::Arc;
use core::ops::DerefMut;
use std::any::Any;
use std::io::{Read, Write};

const FRAME_HEADER_SIZE: usize = core::mem::size_of::<FrameHeader>();

#[derive(Debug, Copy, Clone, Default)]
struct FrameHeader {
    pub payload_size: u32,
}

impl Codec for FrameHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.payload_size.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<FrameHeader> {
        let payload_size = u32::read(r)?;
        Some(FrameHeader { payload_size })
    }
}

/// `FramedStream` is a generic framing module that segments a stream of `u8` data (`S`)
/// into multiple packets. It maintains an internal state to manage reading from the stream
/// and buffers data until complete packets are formed.
pub struct FramedStream<S: Read + Write + Send + 'static> {
    pub(crate) stream: S,
    read_buffer: Vec<u8>,
    read_remain: usize,
}

impl<S> FramedStream<S>
where
    S: Read + Write + Send + 'static,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: stream,
            read_buffer: vec![0; FRAME_HEADER_SIZE + config::RECEIVER_BUFFER_SIZE],
            read_remain: 0,
        }
    }
}

#[maybe_async::maybe_async]
impl<S> SpdmDeviceIo for FramedStream<S>
where
    S: Read + Write + Send + 'static,
{
    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> Result<usize, usize> {
        let mut buffer_size = self.read_remain;
        let mut expected_size: usize = 0;
        let enough = loop {
            /* First, check if existing buffer is ok to return */
            if (expected_size == 0) && (buffer_size >= FRAME_HEADER_SIZE) {
                let mut reader = Reader::init(&self.read_buffer[..FRAME_HEADER_SIZE]);
                let socket_header = FrameHeader::read(&mut reader).unwrap(); /* should always be ok since buffer_size >= FRAME_HEADER_SIZE */

                expected_size = socket_header.payload_size.to_be() as usize + FRAME_HEADER_SIZE;
            }
            if (expected_size != 0) && (buffer_size >= expected_size) {
                /* got enough bytes */
                break true;
            }

            if buffer_size >= self.read_buffer.len() {
                /* not enough but the buffer is full */
                warn!("broken packet: buffer is too small ({} bytes) and should be at least {expected_size} bytes", self.read_buffer.len());
                break false;
            }

            /* waiting for enough bytes */
            // TODO: support real async
            let s = match self.stream.read(&mut self.read_buffer[buffer_size..]) {
                Ok(s) => s,
                Err(e) => {
                    error!("broken packet: {e}");
                    break false;
                } /* stream read error! */
            };
            buffer_size += s;

            if s == 0 {
                /* the stream is closed, and we have not got more bytes at this try, so let's give up. */
                if buffer_size != 0 {
                    /* however, if we have already got some bytes of current packet, which means we have a incomplete packet, let's print an error msg. */
                    // TODO: return Error at here.
                    error!("broken packet: unexpected EOF");
                }
                break false;
            }
        };

        let read_size = std::cmp::min(buffer_size, expected_size);
        trace!(
            "read framed:\t{:02x?}{:02x?}",
            &self.read_buffer[..std::cmp::min(read_size, FRAME_HEADER_SIZE)],
            &self.read_buffer[std::cmp::min(read_size, FRAME_HEADER_SIZE)..read_size]
        );

        if enough {
            let used = expected_size - FRAME_HEADER_SIZE;
            /* copy payload to read_buffer */
            let mut read_buffer = read_buffer.lock();
            let read_buffer = read_buffer.deref_mut();
            read_buffer[..used]
                .copy_from_slice(&self.read_buffer[FRAME_HEADER_SIZE..expected_size]);

            /* backup remain bytes */
            self.read_buffer.copy_within(expected_size..buffer_size, 0);
            self.read_remain = buffer_size - expected_size;
            return Ok(used);
        } else {
            self.read_remain = buffer_size;
            return Err(0);
        }
    }

    async fn send(&mut self, payload: Arc<&[u8]>) -> SpdmResult {
        let mut buffer = [0u8; FRAME_HEADER_SIZE + config::SENDER_BUFFER_SIZE];

        let mut writer = Writer::init(&mut buffer);
        let payload_size = payload.len();
        let header = FrameHeader {
            payload_size: (payload_size as u32).to_be(),
        };
        assert!(header.encode(&mut writer).is_ok());
        let used = writer.used();
        assert_eq!(used, FRAME_HEADER_SIZE);

        self.stream
            .write_all(&buffer[..used])
            .map_err(|_| SPDM_STATUS_SEND_FAIL)?;
        self.stream
            .write_all(&payload)
            .map_err(|_| SPDM_STATUS_SEND_FAIL)?;
        self.stream.flush().map_err(|_| SPDM_STATUS_SEND_FAIL)?;

        trace!("write framed:\t{:02x?}{:02x?}", &buffer[..used], payload);
        Ok(())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        self.stream.flush().map_err(|_| SPDM_STATUS_SEND_FAIL)
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
