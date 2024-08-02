use crate::{CommonClientOptions, CommonServerOptions};
use anyhow::{bail, Result};
use log::info;
use rats_rs::transport::{
    tls::{Client, Server, TlsClientBuilder, TlsServerBuilder},
    GenericSecureTransPort,
};
use std::net::{SocketAddr, TcpListener, TcpStream};

pub fn with_tls_tcp_client(
    opts: CommonClientOptions,
    func: impl FnOnce(Client) -> Result<()>,
) -> Result<()> {
    let server_addr: SocketAddr = opts.connect_to_tcp.parse().expect("Invalid address");

    // Connect to TCP server
    let stream = TcpStream::connect(server_addr).expect("Failed to connect to server");

    info!("Connected to server: {}", server_addr);

    let mut client = TlsClientBuilder::new()
        .with_attest_self(opts.attest_self)
        .with_tcp_stream(stream)
        .build()?;

    client.negotiate()?;

    info!(
        "The tls session on connection {} (responder) is ready.",
        server_addr
    );

    func(client)?;

    info!("Everything is fine, exit now.");
    Ok(())
}

pub fn with_tls_tcp_server(
    opts: CommonServerOptions,
    func: impl Fn(Server) -> Result<()>,
) -> Result<()> {
    let listen_addr: SocketAddr = opts.listen_on_tcp.parse().expect("Invalid address");

    let listener = TcpListener::bind(listen_addr).expect("Failed to bind to address");

    info!("Server started, listening on {}", listen_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer_addr = stream.peer_addr().unwrap();
                info!("New connection: {}", peer_addr);
                let mut server = TlsServerBuilder::new()
                    .with_verify_peer(opts.verify_peer)
                    .with_tcp_stream(stream)
                    .build()?;
                server.negotiate()?;

                info!(
                    "The tls session on connection {} (requester) is ready.",
                    peer_addr
                );

                func(server)?;

                info!(
                    "The connection {} is shutdown, waiting for another now.",
                    peer_addr
                );
            }
            Err(e) => {
                bail!("Error accepting connection: {}", e);
            }
        }
    }
    Ok(())
}
