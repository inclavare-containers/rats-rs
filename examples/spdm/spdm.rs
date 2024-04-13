use anyhow::{bail, Result};
use log::info;
use rats_rs::transport::{
    spdm::{
        requester::{SpdmRequester, SpdmRequesterBuilder},
        responder::{SpdmResponder, SpdmResponderBuilder},
        VerifyMode,
    },
    GenericSecureTransPort,
};
use std::net::{SocketAddr, TcpListener, TcpStream};

use crate::{CommonClientOptions, CommonServerOptions};

pub fn with_spdm_tcp_server(
    opts: &CommonServerOptions,
    func: impl Fn(SpdmResponder) -> Result<()>,
) -> Result<()> {
    let listen_addr: SocketAddr = opts.listen_on_tcp.parse().expect("Invalid address");

    // Start TCP server
    let listener = TcpListener::bind(listen_addr).expect("Failed to bind to address");

    info!("Server started, listening on {}", listen_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer_addr = stream.peer_addr().unwrap();
                info!("New connection: {}", peer_addr);

                let mut responder = SpdmResponderBuilder::new()
                    .with_attest_self(opts.attest_self)
                    .with_verify_mode(if opts.verify_peer {
                        VerifyMode::VERIFY_PEER
                    } else {
                        VerifyMode::VERIFY_NONE
                    })
                    .build_with_tcp_stream(stream)?;

                responder.negotiate()?;

                info!(
                    "The spdm session on connection {} (requester) is ready.",
                    peer_addr
                );

                func(responder)?;

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

pub fn with_spdm_tcp_client(
    opts: &CommonClientOptions,
    func: impl FnOnce(SpdmRequester) -> Result<()>,
) -> Result<()> {
    let server_addr: SocketAddr = opts.connect_to_tcp.parse().expect("Invalid address");

    // Connect to TCP server
    let stream = TcpStream::connect(server_addr).expect("Failed to connect to server");

    info!("Connected to server: {}", server_addr);

    let mut requester = SpdmRequesterBuilder::new()
        .with_attest_self(opts.attest_self)
        .with_verify_mode(if opts.verify_peer {
            VerifyMode::VERIFY_PEER
        } else {
            VerifyMode::VERIFY_NONE
        })
        .build_with_tcp_stream(stream)?;

    requester.negotiate()?;

    info!(
        "The spdm session on connection {} (responder) is ready.",
        server_addr
    );

    func(requester)?;

    info!("Everything is fine, exit now.");
    Ok(())
}
