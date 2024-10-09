use super::RatsClientVerifier;
use crate::cert::create::CertBuilder;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::Result;
use crate::tee::AutoAttester;
use crate::transport::{
    GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite,
};
use maybe_async::maybe_async;
use std::mem;
use std::sync::Arc;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

struct NegotiateInner {
    reader: ReadHalf<TlsStream<TcpStream>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

pub struct RustlsServer {
    acceptor: TlsAcceptor,
    stream: Option<TcpStream>,
    inner: Option<NegotiateInner>,
}

impl RustlsServer {
    #[maybe_async]
    pub async fn new(stream: TcpStream, mutal: bool) -> Result<Self> {
        let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
            .build_with_private_key(&privkey)
            .await?
            .cert_to_der()?;
        let tmp: PrivatePkcs8KeyDer = privkey.to_pkcs8_der()?.as_bytes().to_vec().into();
        let config_builder = rustls::ServerConfig::builder();
        let config;
        if mutal {
            config = config_builder
                .with_client_cert_verifier(Arc::new(RatsClientVerifier {
                    default_client_verifier: WebPkiClientVerifier::builder(Arc::new({
                        //XXX: only to bypass empty test of WebPkiClientVerifier
                        let mut root = rustls::RootCertStore::empty();
                        let privkey =
                            DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
                        let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
                            .build_with_private_key(&privkey)
                            .await?
                            .cert_to_der()?;
                        root.add(cert.into())?;
                        root
                    }))
                    .build()?,
                }))
                .with_single_cert(vec![cert.into()], tmp.into())?;
        } else {
            config = config_builder
                .with_no_client_auth()
                .with_single_cert(vec![cert.into()], tmp.into())?;
        }
        Ok(RustlsServer {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            stream: Some(stream),
            inner: None,
        })
    }
}

#[maybe_async]
impl GenericSecureTransPort for RustlsServer {
    async fn negotiate(&mut self) -> Result<()> {
        let acceptor = self.acceptor.clone();
        let stream = std::mem::replace(&mut self.stream, None).unwrap();
        let tls_stream = acceptor.accept(stream).await?;
        let (reader, writer) = split(tls_stream);
        self.inner = Some(NegotiateInner {
            reader: reader,
            writer: writer,
        });
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for RustlsServer {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner.as_mut().unwrap().writer.write(bytes).await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<()> {
        self.inner.as_mut().unwrap().writer.shutdown().await?;
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for RustlsServer {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = self.inner.as_mut().unwrap().reader.read(buf).await?;
        Ok(len)
    }
}
