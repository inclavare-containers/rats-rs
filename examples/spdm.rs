use anyhow::{bail, Result};
use clap::{arg, ArgAction, Parser};
use rats_rs::transport::{
    spdm::{requester::SpdmRequesterBuilder, responder::SpdmResponderBuilder, VerifyMode},
    GenericSecureTransPort,
};
use std::net::{SocketAddr, TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum SpdmCommand {
    #[command(name = "server")]
    Server(ServerOptions),
    #[command(name = "client")]
    Client(ClientOptions),
}

#[derive(Parser, Debug)]
struct ServerOptions {
    /// Whether to attest self to peer. Defaults to `true`.
    #[arg(
        long,
        default_missing_value("true"),
        default_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    attest_self: bool,

    /// Whether to verify peer. Defaults to `false`.
    #[arg(
        long,
        default_missing_value("true"),
        default_value("false"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    verify_peer: bool,

    /// Address to listen on for TCP connections.
    #[arg(long)]
    listen_on_tcp: String,
}

#[derive(Parser, Debug)]
struct ClientOptions {
    /// Whether to attest self to peer. Defaults to `false`.
    #[arg(
        long,
        default_missing_value("true"),
        default_value("false"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    attest_self: bool,

    /// Whether to verify peer. Defaults to `true`.
    #[arg(
        long,
        default_missing_value("true"),
        default_value("true"),
        num_args(0..=1),
        require_equals(true),
        action = ArgAction::Set,
    )]
    verify_peer: bool,

    /// Address to connect to for TCP connection.
    #[arg(long)]
    connect_to_tcp: String,
}

fn main() -> Result<()> {
    let env = env_logger::Env::default()
        .filter_or("RATS_RS_LOG_LEVEL", "debug")
        .write_style_or("RATS_RS_LOG_STYLE", "always"); // enable color
    env_logger::Builder::from_env(env)
        // .format_indent(None) // No indent for each line
        .init();

    let cmd = SpdmCommand::parse();
    println!("Welcome to rats-rs spdm example!: \n\tcmd: {cmd:?}");

    match cmd {
        SpdmCommand::Server(opts) => {
            let listen_addr: SocketAddr = opts.listen_on_tcp.parse().expect("Invalid address");

            // Start TCP server
            let listener = TcpListener::bind(listen_addr).expect("Failed to bind to address");

            println!("Server started, listening on {}", listen_addr);

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let peer_addr = stream.peer_addr().unwrap();
                        println!("New connection: {}", peer_addr);

                        let mut responder = SpdmResponderBuilder::new()
                            .with_attest_self(opts.attest_self)
                            .with_verify_mode(if opts.verify_peer {
                                VerifyMode::VERIFY_PEER
                            } else {
                                VerifyMode::VERIFY_NONE
                            })
                            .build_with_stream(stream)?;

                        responder.negotiate()?;

                        for i in 1024..2048u32 {
                            responder.send(&i.to_be_bytes())?;
                        }

                        let mut receive_buffer = [0u8; rats_rs::transport::spdm::MAX_SPDM_MSG_SIZE];

                        for i in 0..1024u32 {
                            let expected = i.to_be_bytes();
                            let expected_len = expected.len();
                            let len = responder.receive(&mut receive_buffer[..expected_len])?;
                            assert_eq!(expected_len, len);
                            assert_eq!(expected, receive_buffer[..expected_len]);
                        }

                        println!(
                            "The connection {} is shutdown, waiting for another now.",
                            peer_addr
                        );
                    }
                    Err(e) => {
                        bail!("Error accepting connection: {}", e);
                    }
                }
            }
        }
        SpdmCommand::Client(opts) => {
            let server_addr: SocketAddr = opts.connect_to_tcp.parse().expect("Invalid address");

            // Connect to TCP server
            let stream = TcpStream::connect(server_addr).expect("Failed to connect to server");

            println!("Connected to server: {}", server_addr);

            let mut requester = SpdmRequesterBuilder::new()
                .with_attest_self(opts.attest_self)
                .with_verify_mode(if opts.verify_peer {
                    VerifyMode::VERIFY_PEER
                } else {
                    VerifyMode::VERIFY_NONE
                })
                .build_with_stream(stream)?;

            requester.negotiate()?;

            for i in 0..1024u32 {
                requester.send(&i.to_be_bytes())?;
            }

            let mut receive_buffer = [0u8; rats_rs::transport::spdm::MAX_SPDM_MSG_SIZE];

            for i in 1024..2048u32 {
                let expected = i.to_be_bytes();
                let expected_len = expected.len();
                let len = requester.receive(&mut receive_buffer[..expected_len])?;
                assert_eq!(expected_len, len);
                assert_eq!(expected, receive_buffer[..expected_len]);
            }

            println!("Everything is fine, exit now.");
        }
    }

    Ok(())
}
