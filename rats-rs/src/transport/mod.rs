#[cfg(feature = "transport-spdm")]
pub mod spdm;

#[cfg(feature = "transport-tls")]
pub mod tls;

use crate::errors::*;
use maybe_async::maybe_async;

#[maybe_async]
pub trait GenericSecureTransPort {
    async fn negotiate(&mut self) -> Result<()>;
}

#[maybe_async]
pub trait GenericSecureTransPortWrite {
    async fn send(&mut self, bytes: &[u8]) -> Result<()>;

    /* Given the current version of spdm-rs implementation, there is no graceful way
       to implement "Remotely-Initiated Shutdown" like what SSL_shutdown() provided.
       The root case is that spdm-rs not support responder-side END_SESSION sending.
       So we don't provide shutdown() for now. As a workaround, user can shutdown a
       SPDM session by shutdown the transport layer of SPDM.

       SSL_shutdown(): https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html
    */
    async fn shutdown(&mut self) -> Result<()>;
}

#[maybe_async]
pub trait GenericSecureTransPortRead {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize>;
}
