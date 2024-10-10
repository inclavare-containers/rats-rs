use super::RatsServerVerifier;
use crate::cert::create::CertBuilder;
use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::Result;
use crate::tee::AutoAttester;
use crate::transport::{
    GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite,
};
use maybe_async::maybe_async;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{self, pki_types, ClientConfig};
use tokio_rustls::TlsConnector;

#[allow(unused)]
pub struct RustlsClient {
    connector: TlsConnector,
    addr: String,
    reader: Option<ReadHalf<TlsStream<TcpStream>>>,
    writer: Option<WriteHalf<TlsStream<TcpStream>>>,
}

impl RustlsClient {
    #[maybe_async]
    pub async fn new(addr: &str, mutal: bool) -> Result<Self> {
        let config_builder = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(rustls::RootCertStore::empty()));
        let mut config;
        if mutal {
            let privkey = DefaultCrypto::gen_private_key(crate::crypto::AsymmetricAlgo::Rsa2048)?;
            let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
                .build_with_private_key(&privkey)
                .await?
                .cert_to_der()?;
            let tmp: PrivatePkcs8KeyDer = privkey.to_pkcs8_der()?.as_bytes().to_vec().into();
            config = config_builder.with_client_auth_cert(vec![cert.into()], tmp.into())?;
        } else {
            config = config_builder.with_no_client_auth();
        }

        config
            .dangerous()
            .set_certificate_verifier(Arc::new(RatsServerVerifier {
                default_server_verifier: WebPkiServerVerifier::builder(Arc::new({
                    //XXX: only to bypass empty test of WebPkiServerVerifier
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
            }));
        Ok(RustlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            addr: addr.to_string(),
            reader: None,
            writer: None,
        })
    }
}

#[maybe_async]
impl GenericSecureTransPort for RustlsClient {
    async fn negotiate(&mut self) -> Result<()> {
        let addr = self.addr.parse::<SocketAddr>()?.ip();
        let stream = TcpStream::connect(&self.addr).await?;
        let domain = pki_types::ServerName::try_from(addr)?;
        let tls_stream = self.connector.connect(domain, stream).await?;
        let (reader, writer) = split(tls_stream);
        self.reader = Some(reader);
        self.writer = Some(writer);
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortWrite for RustlsClient {
    async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.as_mut().unwrap().write(bytes).await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<()> {
        self.writer.as_mut().unwrap().shutdown().await?;
        Ok(())
    }
}

#[maybe_async]
impl GenericSecureTransPortRead for RustlsClient {
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = self.reader.as_mut().unwrap().read(buf).await?;
        Ok(len)
    }
}
