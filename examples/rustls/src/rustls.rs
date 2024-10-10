use std::future::Future;

use crate::{CommonClientOptions, CommonServerOptions};
use anyhow::{bail, Result};
use log::info;
use rats_rs::transport::rustls::{RustlsClient, RustlsServer};
use rats_rs::transport::{
    GenericSecureTransPort, GenericSecureTransPortRead, GenericSecureTransPortWrite,
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

pub async fn with_tls_tcp_client<T>(
    opts: CommonClientOptions,
    func: impl FnOnce(RustlsClient) -> T,
) -> Result<()>
where
    T: Future<Output = Result<()>>,
{
    let mut rustls_client = RustlsClient::new(&opts.connect_to_tcp, opts.attest_self).await?;

    info!("Connected to server: {}", opts.connect_to_tcp);

    rustls_client.negotiate().await?;

    info!(
        "The tls session on connection {} (responder) is ready.",
        opts.connect_to_tcp,
    );

    func(rustls_client).await?;

    info!("Everything is fine, exit now.");
    Ok(())
}

pub async fn with_tls_tcp_server<T>(
    opts: CommonServerOptions,
    func: impl Fn(RustlsServer) -> T,
) -> Result<()>
where
    T: Future<Output = Result<()>>,
{
    let listener = TcpListener::bind(&opts.listen_on_tcp)
        .await
        .expect("Failed to bind to address");

    info!("Server started, listening on {}", &opts.listen_on_tcp);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("New connection: {}", peer_addr);
        let mut server = RustlsServer::new(stream, opts.verify_peer).await?;
        server.negotiate().await?;

        info!(
            "The tls session on connection {} (requester) is ready.",
            peer_addr
        );

        func(server).await?;

        info!(
            "The connection {} is shutdown, waiting for another now.",
            peer_addr
        );
    }
}
