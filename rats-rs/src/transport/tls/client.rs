use super::{
    as_raw, as_raw_mut, ossl_init, verify_certificate_default, EpvPkey, GetFd, SslMode, TcpWrapper,
    OPENSSL_EX_DATA_IDX,
};
use crate::{
    cert::{
        create::CertBuilder,
        dice::cbor::{parse_evidence_buffer_with_tag, OCBR_TAG_EVIDENCE_INTEL_TEE_QUOTE},
    },
    crypto::{AsymmetricPrivateKey, DefaultCrypto, HashAlgo},
    errors::*,
    tee::{
        sgx_dcap::evidence, AutoAttester, AutoEvidence, AutoVerifier, GenericEvidence,
        GenericVerifier,
    },
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
    net::{TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    ptr::{self, null_mut},
    sync::{Arc, Mutex},
};

pub struct Client {
    ctx: *mut SSL_CTX,
    ssl_session: Option<*mut SSL>,
    verify_callback: SSL_verify_cb,
    stream: Box<dyn GetFd>,
    attest_self: bool,
}

// `Client` is not 'Send' because it contains raw pointer which doesn't impl `Send`
// async methods capturing `&mut Client` need `Send` trait for `Client`, so we impl here.
#[cfg(feature = "async-tokio")]
unsafe impl Send for Client {}

pub struct TlsClientBuilder {
    verify: SSL_verify_cb,
    stream: Option<Box<dyn GetFd>>,
    attest_self: bool,
}

impl TlsClientBuilder {
    #[maybe_async]
    pub async fn build(self) -> Result<Client> {
        ossl_init()?;
        let ctx = unsafe { SSL_CTX_new(TLS_client_method()) };
        if ctx.is_null() {
            return Err(Error::kind(ErrorKind::OsslCtxInitializeFail));
        }
        let mut c = Client {
            ctx: ctx,
            ssl_session: None,
            verify_callback: Some(self.verify.unwrap_or(verify_certificate_default)),
            stream: self
                .stream
                .ok_or(Error::kind(ErrorKind::OsslTlsBuilderStreamUnset))?,
            attest_self: self.attest_self,
        };
        if c.attest_self {
            let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
            c.use_privkey(&privkey)?;
            let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
                .build_with_private_key(&privkey)
                .await?
                .cert_to_der()?;
            c.use_cert(&cert)?;
        }
        Ok(c)
    }
    pub fn with_verify(mut self, verify: SSL_verify_cb) -> Self {
        self.verify = verify;
        self
    }
    pub fn with_tcp_stream(mut self, stream: TcpStream) -> Self {
        self.stream = Some(Box::new(TcpWrapper(stream)));
        self
    }
    pub fn with_attest_self(mut self, attest_self: bool) -> Self {
        self.attest_self = attest_self;
        self
    }
    pub fn new() -> Self {
        Self {
            verify: None,
            stream: None,
            attest_self: false,
        }
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for Client {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if self.ssl_session.is_none() {
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
            }
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(ssl_session) = self.ssl_session {
            unsafe {
                SSL_free(ssl_session);
            }
        }
        unsafe {
            SSL_CTX_free(self.ctx);
        }
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for Client {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.ssl_session.is_none() {
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
impl GenericSecureTransPort for Client {
    async fn negotiate(&mut self) -> Result<()> {
        let ctx = self.ctx;
        if self.verify_callback.is_some() {
            let mode = SslMode::SSL_VERIFY_PEER;
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
                *OPENSSL_EX_DATA_IDX,
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
        let err = unsafe { SSL_connect(session) };
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

impl Client {
    pub fn use_privkey(&mut self, privkey: &AsymmetricPrivateKey) -> Result<()> {
        let pkey;
        let epkey: ::libc::c_int;
        match privkey {
            AsymmetricPrivateKey::Rsa2048(key)
            | AsymmetricPrivateKey::Rsa3072(key)
            | AsymmetricPrivateKey::Rsa4096(key) => {
                pkey = key.to_pkcs8_der().map_err(|_e| Error::unknown())?;
                epkey = EpvPkey::RSA.bits();
            }
            AsymmetricPrivateKey::P256(key) => {
                pkey = key.to_pkcs8_der()?;
                epkey = EpvPkey::EC.bits();
            }
        }
        let ctx = self.ctx;
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
        let ctx = self.ctx;
        let res = unsafe {
            SSL_CTX_use_certificate_ASN1(
                ctx,
                cert.len() as ::libc::c_int,
                cert.as_ptr() as usize as *const ::libc::c_uchar,
            )
        };
        if res != 1 {
            return Err(Error::kind(ErrorKind::OsslUseCertfail));
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::{Client, TlsClientBuilder};
    use crate::{
        cert::create::CertBuilder,
        crypto::{AsymmetricAlgo, DefaultCrypto, HashAlgo},
        errors::*,
        tee::{AutoAttester, AutoVerifier},
        transport::{
            tls::{as_raw, as_raw_mut, ossl_init, GetFd},
            GenericSecureTransPortWrite,
        },
    };
    use maybe_async::maybe_async;
    use openssl_sys::*;
    use std::{
        net::TcpStream,
        ptr::{self, null_mut},
        slice,
    };

    struct GetFdDumpImpl;
    impl GetFd for GetFdDumpImpl {
        fn get_fd(&self) -> i32 {
            0
        }
    }

    #[maybe_async]
    #[cfg_attr(feature = "is-sync", test)]
    #[cfg_attr(not(feature = "is-sync"), tokio::test)]
    async fn test_client_shutdown() -> Result<()> {
        let mut builder = TlsClientBuilder::new();
        builder.stream = Some(Box::new(GetFdDumpImpl));
        let mut c = builder.build().await?;
        c.shutdown().await?;
        Ok(())
    }

    fn ossl_get_privkey(c: &mut Client) -> Vec<u8> {
        let ssl_session = unsafe { SSL_new(c.ctx) };
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

    #[maybe_async]
    #[cfg_attr(feature = "is-sync", test)]
    #[cfg_attr(not(feature = "is-sync"), tokio::test)]
    async fn test_client_use_key() -> Result<()> {
        let mut builder = TlsClientBuilder::new();
        builder.stream = Some(Box::new(GetFdDumpImpl));
        let mut c = builder.build().await?;
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let binding = privkey.to_pkcs8_pem()?;
        let privpem = binding.as_bytes();
        c.use_privkey(&privkey)?;
        let now = ossl_get_privkey(&mut c);
        assert_eq!(privpem, now);
        c.shutdown().await?;
        Ok(())
    }

    #[maybe_async]
    #[cfg_attr(feature = "is-sync", test)]
    #[cfg_attr(not(feature = "is-sync"), tokio::test)]
    async fn test_client_use_cert() -> Result<()> {
        let mut builder = TlsClientBuilder::new();
        builder.stream = Some(Box::new(GetFdDumpImpl));
        let mut c = builder.build().await?;
        let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
            .build_with_private_key(&privkey)
            .await?
            .cert_to_der()?;
        c.use_cert(&cert)?;
        let raw_cert = unsafe { SSL_CTX_get0_certificate(c.ctx) };
        let mut raw_ptr = ptr::null_mut::<u8>();
        let len = unsafe { i2d_X509(raw_cert, &mut raw_ptr as *mut *mut u8) };
        let now = unsafe { slice::from_raw_parts(raw_ptr as *const u8, len as usize).to_vec() };
        assert_eq!(cert, now);
        c.shutdown().await?;
        Ok(())
    }
}
