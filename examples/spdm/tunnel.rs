use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

use crate::{
    spdm::{with_spdm_tcp_client, with_spdm_tcp_server},
    CommonClientOptions, CommonServerOptions, TunnelClientOptions, TunnelServerOptions,
};
use anyhow::{anyhow, Context, Result};
use log::{error, info};
use rats_rs::transport::GenericSecureTransPort;

const THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;

pub fn tunnel_client(common: CommonClientOptions, opts: TunnelClientOptions) -> Result<()> {
    let listener = TcpListener::bind(&opts.ingress).expect("Invalid ingress address");
    info!("tunnel-client listening on {}", opts.ingress);

    for stream in listener.incoming() {
        match stream {
            Ok(mut client_stream) => {
                with_spdm_tcp_client(&common, |requester| {
                    let requester = Arc::new(Mutex::new(requester));

                    {
                        let requester = requester.clone();
                        let mut client_stream = client_stream.try_clone()?;
                        let builder = thread::Builder::new().stack_size(THREAD_STACK_SIZE);
                        let _ = builder.spawn(move || -> Result<()> {
                            // Forward data from ingress to tunnel-server
                            let mut buf = [0; 1024];
                            loop {
                                let recv_len = client_stream
                                    .read(&mut buf)
                                    .with_context(|| format!("Failed to read from ingress"))?;
                                let mut requester = requester
                                    .lock()
                                    .map_err(|e| anyhow!("requester.lock() failed: {e}"))?;
                                if recv_len == 0 {
                                    info!("Connection closed by ingress");
                                    requester.shutdown()?;
                                    break;
                                }
                                requester.send(&buf[..recv_len])?;
                            }
                            Ok(())
                        })?;
                    }

                    {
                        let builder = thread::Builder::new().stack_size(THREAD_STACK_SIZE);
                        let _ = builder.spawn(move || -> Result<()> {
                            // Forward data from tunnel-server to ingress
                            let mut buf = [0; 1024];
                            loop {
                                let mut requester = requester
                                    .lock()
                                    .map_err(|e| anyhow!("requester.lock() failed: {e}"))?;
                                let recv_len = requester.receive(&mut buf)?;

                                if recv_len == 0 {
                                    info!("Connection closed by tunnel-server");
                                    client_stream.shutdown(Shutdown::Write)?;
                                    break;
                                }
                                client_stream.write_all(&buf[..recv_len])?;
                            }
                            Ok(())
                        })?;
                    }

                    Ok(())
                })?
            }
            Err(e) => {
                error!("Failed to accept client connection: {}", e);
            }
        }
    }

    Ok(())
}

pub fn tunnel_server(common: CommonServerOptions, opts: TunnelServerOptions) -> Result<()> {
    with_spdm_tcp_server(&common, |responder| {
        let mut server_stream = TcpStream::connect(&opts.upstream)
            .with_context(|| format!("Failed to connect to upstream {}", opts.upstream))?;
        let responder = Arc::new(Mutex::new(responder));

        {
            let responder = responder.clone();
            let mut server_stream = server_stream.try_clone()?;
            let builder = thread::Builder::new().stack_size(THREAD_STACK_SIZE);
            let _ = builder.spawn(move || -> Result<()> {
                // Forward data from tunnel-client to upstream
                let mut buf = [0; 1024];
                loop {
                    let mut responder = responder
                        .lock()
                        .map_err(|e| anyhow!("responder.lock() failed: {e}"))?;
                    let recv_len = responder.receive(&mut buf)?;

                    if recv_len == 0 {
                        info!("Connection closed by tunnel-client");
                        server_stream.shutdown(Shutdown::Write)?;
                        break;
                    }
                    server_stream.write_all(&buf[..recv_len])?;
                }
                Ok(())
            })?;
        }

        {
            let responder = responder.clone();
            let builder = thread::Builder::new().stack_size(THREAD_STACK_SIZE);
            let _ = builder.spawn(move || -> Result<()> {
                // Forward data from upstream to tunnel-client
                let mut buf = [0; 1024];
                loop {
                    let recv_len = server_stream
                        .read(&mut buf)
                        .with_context(|| format!("Failed to read from upstream"))?;

                    let mut responder = responder
                        .lock()
                        .map_err(|e| anyhow!("responder.lock() failed: {e}"))?;
                    if recv_len == 0 {
                        info!("Connection closed by upstream");
                        responder.shutdown()?;
                        break;
                    }
                    responder.send(&buf[..recv_len])?;
                }
                Ok(())
            })?;
        }

        Ok(())
    })
}
