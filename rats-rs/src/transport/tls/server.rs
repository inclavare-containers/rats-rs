use super::{
    as_raw, as_raw_mut, ossl_init, verify_certificate_default, EpvPkey, GetFd, GetFdDumpImpl,
    SslMode, TcpWrapper, OPENSSL_EX_DATA_IDX,
};
use crate::{
    cert::{create::CertBuilder, dice::cbor::parse_evidence_buffer_with_tag},
    crypto::{AsymmetricPrivateKey, DefaultCrypto, HashAlgo},
    errors::*,
    tee::{sgx_dcap::evidence, AutoAttester, GenericVerifier},
    transport::{GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite},
};
use lazy_static::lazy_static;
use log::{debug, error};
use maybe_async::maybe_async;
use openssl_sys::*;
use pkcs8::EncodePrivateKey;
use std::{
    cell::Cell,
    ffi::c_int,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    ptr,
    sync::{Arc, Mutex},
};

//TODO: use typestate only impl `VerifyCertExtension` if needed
pub struct Server {
    ctx: Option<*mut SSL_CTX>,
    ssl_session: Option<*mut SSL>,
    verify_callback: SSL_verify_cb,
    stream: Box<dyn GetFd>,
}

// TODO: use typestate design pattern?
pub struct TlsServerBuilder {
    verify: SSL_verify_cb,
    stream: Box<dyn GetFd>,
    verify_peer: bool,
}

impl TlsServerBuilder {
    pub fn build(self) -> Result<Server> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify_callback: if self.verify_peer {
                if self.verify.is_some() {
                    self.verify
                } else {
                    Some(verify_certificate_default)
                }
            } else {
                None
            },
            stream: self.stream,
        };
        s.init()?;
        Ok(s)
    }
    pub fn new() -> Self {
        Self {
            verify: None,
            stream: Box::new(GetFdDumpImpl),
            verify_peer: false,
        }
    }
    pub fn with_verify(mut self, verify: SSL_verify_cb) -> Self {
        self.verify = verify;
        self
    }
    pub fn with_verify_peer(mut self, verify_peer: bool) -> Self {
        self.verify_peer = verify_peer;
        self
    }
    pub fn with_tcp_stream(mut self, stream: TcpStream) -> Self {
        self.stream = Box::new(TcpWrapper(stream));
        self
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for Server {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if self.ctx.is_none() || self.ssl_session.is_none() {
            return Err(Error::kind(ErrorKind::OsslCtxOrSessionUninitialized));
        }
        let res = unsafe {
            SSL_write(
                self.ssl_session.unwrap(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as i32,
            )
        };
        if res < 0 {
            return Err(Error::kind(ErrorKind::OsslSendFail));
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        if let Some(ssl_session) = self.ssl_session {
            unsafe {
                SSL_shutdown(ssl_session);
                SSL_free(ssl_session);
            }
        }
        if let Some(ctx) = self.ctx {
            unsafe {
                SSL_CTX_free(ctx);
            }
        }
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for Server {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.ctx.is_none() || self.ssl_session.is_none() {
            return Err(Error::kind(ErrorKind::OsslCtxOrSessionUninitialized));
        }
        let res = unsafe {
            SSL_read(
                self.ssl_session.unwrap(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as i32,
            )
        };
        if res < 0 {
            return Err(Error::kind(ErrorKind::OsslReceiveFail));
        }
        Ok(res as usize)
    }
}

#[maybe_async]
impl GenericSecureTransPort for Server {
    async fn negotiate(&mut self) -> Result<()> {
        let ctx = self
            .ctx
            .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?;
        if self.verify_callback.is_some() {
            let mut mode = SslMode::SSL_VERIFY_NONE;
            mode |= SslMode::SSL_VERIFY_PEER | SslMode::SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            unsafe {
                SSL_CTX_set_verify(ctx, mode.bits(), self.verify_callback);
            }
        }
        let session = unsafe { SSL_new(ctx) };
        if session.is_null() {
            return Err(Error::kind(ErrorKind::OsslNoMem));
        }
        unsafe {
            X509_STORE_set_ex_data(
                SSL_CTX_get_cert_store(ctx),
                OPENSSL_EX_DATA_IDX.lock().unwrap().get(),
                as_raw_mut(self),
            );
        }
        let res = unsafe { SSL_set_fd(session, self.stream.get_fd()) };
        if res != 1 {
            return Err(Error::kind(ErrorKind::OsslSetFdFail));
        }
        unsafe {
            ERR_clear_error();
        }
        let err = unsafe { SSL_accept(session) };
        if err != 1 {
            error!("failed to negotiate {}, SSL_get_error(): {}", err, unsafe {
                SSL_get_error(session, err)
            });
            return Err(Error::kind(ErrorKind::OsslServerNegotiationFail));
        }
        self.ssl_session = Some(session);
        Ok(())
    }
}

impl Server {
    pub fn init(&mut self) -> Result<()> {
        ossl_init()?;
        let ctx = unsafe { SSL_CTX_new(TLS_server_method()) };
        if ctx.is_null() {
            return Err(Error::kind(ErrorKind::OsslCtxInitializeFail));
        }
        self.ctx = Some(ctx);
        let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
        self.use_privkey(&privkey)?;
        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
            .build_with_private_key(&privkey)?
            .cert_to_der()?;
        self.use_cert(&cert)?;
        Ok(())
    }

    pub fn use_privkey(&mut self, privkey: &AsymmetricPrivateKey) -> Result<()> {
        let pkey;
        let epkey: ::libc::c_int;
        match privkey {
            AsymmetricPrivateKey::Rsa2048(key)
            | AsymmetricPrivateKey::Rsa3072(key)
            | AsymmetricPrivateKey::Rsa4096(key) => {
                pkey = key.to_pkcs8_der()?;
                epkey = EpvPkey::RSA.bits();
            }
            AsymmetricPrivateKey::P256(key) => {
                pkey = key.to_pkcs8_der()?;
                epkey = EpvPkey::EC.bits();
            }
        }
        let ctx = self
            .ctx
            .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?;
        let pkey_len = pkey.as_bytes().len() as ::libc::c_long;
        let pkey_buffer = as_raw(&pkey.as_bytes()[0]);
        unsafe {
            let res = SSL_CTX_use_PrivateKey_ASN1(epkey, ctx, pkey_buffer, pkey_len);
            if res != 1 {
                return Err(Error::kind(ErrorKind::OsslUsePrivKeyfail));
            }
        }
        Ok(())
    }

    pub fn use_cert(&mut self, cert: &Vec<u8>) -> Result<()> {
        let ctx = self
            .ctx
            .ok_or(Error::kind(ErrorKind::OsslCtxUninitialize))?;
        let ptr = cert.as_ptr();
        let len = cert.len();
        let res = unsafe {
            SSL_CTX_use_certificate_ASN1(
                ctx,
                len as ::libc::c_int,
                ptr as usize as *const ::libc::c_uchar,
            )
        };
        if res != 1 {
            return Err(Error::kind(ErrorKind::OsslUseCertfail));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use crate::{
        cert::create::{CertBuilder, CertBundle},
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        errors::*,
        tee::AutoAttester,
        transport::{
            tls::{as_raw_mut, ossl_init, GetFdDumpImpl},
            GenericSecureTransPortWrite,
        },
    };
    use core::slice;
    use openssl_sys::*;
    use std::ptr;

    #[test]
    fn test_server_init() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify_callback: None,
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        s.shutdown()?;
        Ok(())
    }
    #[test]
    fn test_server_shutdown() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify_callback: None,
            stream: Box::new(GetFdDumpImpl),
        };
        s.init()?;
        s.shutdown()?;
        Ok(())
    }

    fn ossl_get_privkey(s: &mut Server) -> Vec<u8> {
        let ssl_session = unsafe { SSL_new(s.ctx.unwrap()) };
        let pkey = unsafe { SSL_get_privatekey(ssl_session) };
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        let res = unsafe {
            PEM_write_bio_PrivateKey(
                bio,
                pkey,
                ptr::null(),
                ptr::null_mut(),
                0,
                None,
                ptr::null_mut(),
            )
        };
        assert_ne!(res, 0);
        let mut pem_data = ptr::null_mut::<i8>();
        let pem_size = unsafe { BIO_get_mem_data(bio, as_raw_mut(&mut pem_data)) };
        let now =
            unsafe { slice::from_raw_parts(pem_data as *const u8, pem_size as usize).to_vec() };
        unsafe {
            SSL_shutdown(ssl_session);
            SSL_free(ssl_session);
        }
        now
    }

    #[test]
    fn test_server_use_key() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify_callback: None,
            stream: Box::new(GetFdDumpImpl),
        };
        ossl_init()?;
        let ctx = unsafe { SSL_CTX_new(TLS_server_method()) };
        if ctx.is_null() {
            return Err(Error::kind(ErrorKind::OsslCtxInitializeFail));
        }
        s.ctx = Some(ctx);
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let binding = privkey.to_pkcs8_pem()?;
        let privpem = binding.as_bytes();
        s.use_privkey(&privkey)?;
        let now = ossl_get_privkey(&mut s);
        assert_eq!(privpem, now.as_slice());
        s.shutdown()?;
        Ok(())
    }

    #[test]
    fn test_server_use_cert() -> Result<()> {
        let mut s = Server {
            ctx: None,
            ssl_session: None,
            verify_callback: None,
            stream: Box::new(GetFdDumpImpl),
        };
        ossl_init()?;
        let ctx = unsafe { SSL_CTX_new(TLS_server_method()) };
        if ctx.is_null() {
            return Err(Error::kind(ErrorKind::OsslCtxInitializeFail));
        }
        s.ctx = Some(ctx);
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let bundle = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
            .build_with_private_key(&privkey)?;
        let cert = bundle.cert_to_der()?;
        println!("cert.pem: {}", bundle.cert_to_pem()?);
        s.use_cert(&cert)?;
        let raw_cert = unsafe { SSL_CTX_get0_certificate(s.ctx.unwrap()) };
        let mut raw_ptr = ptr::null_mut::<u8>();
        let len = unsafe { i2d_X509(raw_cert, &mut raw_ptr as *mut *mut u8) };
        let now = unsafe { slice::from_raw_parts(raw_ptr as *const u8, len as usize).to_vec() };
        assert_eq!(cert, now);
        s.shutdown()?;
        Ok(())
    }
}
