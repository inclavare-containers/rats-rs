mod echo;
mod tls;

use anyhow::Result;
use clap::{arg, ArgAction, Parser};
use echo::{echo_client, echo_server};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
enum TlsCommand {
    #[command(name = "echo-client")]
    EchoClient(CommonClientOptions),
    #[command(name = "echo-server")]
    EchoServer(CommonServerOptions),
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
        .write_style_or("RATS_RS_LOG_STYLE", "always");
    env_logger::Builder::from_env(env).init();
    let command = TlsCommand::parse();
    match command {
        TlsCommand::EchoClient(opts) => echo_client(opts)?,
        TlsCommand::EchoServer(opts) => echo_server(opts)?,
    }
    Ok(())
}
