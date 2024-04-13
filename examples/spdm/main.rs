mod echo;
mod spdm;
mod tunnel;

use anyhow::Result;
use clap::{arg, ArgAction, Parser};
use log::info;

use crate::{
    echo::{echo_client, echo_server},
    tunnel::{tunnel_client, tunnel_server},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum SpdmCommand {
    #[command(name = "echo-server")]
    EchoServer(CommonServerOptions),
    #[command(name = "echo-client")]
    EchoClient(CommonClientOptions),
    #[command(name = "tunnel-server")]
    TunnelServer {
        #[command(flatten)]
        common: CommonServerOptions,
        #[command(flatten)]
        opts: TunnelServerOptions,
    },
    #[command(name = "tunnel-client")]
    TunnelClient {
        #[command(flatten)]
        common: CommonClientOptions,
        #[command(flatten)]
        opts: TunnelClientOptions,
    },
}

#[derive(Parser, Debug)]
struct TunnelServerOptions {
    /// The upstream ip:port to forward ingress TCP connections to.
    #[arg(long)]
    upstream: String,
}

#[derive(Parser, Debug)]
struct TunnelClientOptions {
    /// The ingress TCP ip:port to listen on.
    #[arg(long)]
    ingress: String,
}

#[derive(Parser, Debug)]
struct CommonServerOptions {
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

    /// The ip:port to listen on for TCP connections.
    #[arg(long)]
    listen_on_tcp: String,
}

#[derive(Parser, Debug, Clone)]
struct CommonClientOptions {
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

    /// The ip:port to connect to for TCP connection.
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
    info!("Welcome to rats-rs spdm example!: \n\tcmd: {cmd:?}");

    match cmd {
        SpdmCommand::EchoServer(opts) => echo_server(opts)?,
        SpdmCommand::EchoClient(opts) => echo_client(opts)?,
        SpdmCommand::TunnelServer { common, opts } => tunnel_server(common, opts)?,
        SpdmCommand::TunnelClient { common, opts } => tunnel_client(common, opts)?,
    }

    Ok(())
}
