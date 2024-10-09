use crate::{
    rustls::{with_tls_tcp_client, with_tls_tcp_server},
    CommonClientOptions, CommonServerOptions,
};
use anyhow::Result;
use log::info;
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use rats_rs::transport::{
    rustls::{RustlsClient, RustlsServer},
    GenericSecureTransPortRead, GenericSecureTransPortWrite,
};

pub async fn echo_client(opts: CommonClientOptions) -> Result<()> {
    with_tls_tcp_client(opts, async |mut c: RustlsClient| {
        let mut rng = SmallRng::from_entropy();
        for _i in 0..128 {
            let mut expected = [0u8; 8];
            let expected_len = expected.len();

            rng.fill_bytes(&mut expected);
            c.send(&expected).await?;

            let mut buffer = [0u8; 1024];
            let recv_len = c.receive(&mut buffer[..expected_len]).await?;

            assert_eq!(expected_len, recv_len);
            assert_eq!(expected, buffer[..expected_len]);
            info!("{}/128: passed", _i + 1);
        }
        c.shutdown().await?;
        Ok(())
    })
    .await?;
    Ok(())
}

pub async fn echo_server(opts: CommonServerOptions) -> Result<()> {
    with_tls_tcp_server(opts, async |mut s: RustlsServer| {
        let mut buffer = [0u8; 1024];
        let buffer_len = buffer.len();
        for _i in 0..128 {
            let recv_len = s.receive(&mut buffer[..buffer_len]).await?;
            s.send(&mut buffer[..recv_len]).await?;
        }
        s.shutdown().await?;
        Ok(())
    })
    .await?;
    Ok(())
}
