use crate::{
    tls::{with_tls_tcp_client, with_tls_tcp_server},
    CommonClientOptions, CommonServerOptions,
};
use anyhow::Result;
use log::info;
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use rats_rs::transport::{GenericSecureTransPortRead, GenericSecureTransPortWrite};

pub fn echo_client(opts: CommonClientOptions) -> Result<()> {
    with_tls_tcp_client(opts, |mut c| {
        let mut rng = SmallRng::from_entropy();
        for _i in 0..128 {
            let mut expected = [0u8; 8];
            let expected_len = expected.len();

            rng.fill_bytes(&mut expected);
            c.send(&expected)?;

            let mut buffer = [0u8; 1024];
            let recv_len = c.receive(&mut buffer[..expected_len])?;

            assert_eq!(expected_len, recv_len);
            assert_eq!(expected, buffer[..expected_len]);
            info!("{}/128: passed", _i + 1);
        }
        c.shutdown()?;
        Ok(())
    })?;
    Ok(())
}

pub fn echo_server(opts: CommonServerOptions) -> Result<()> {
    with_tls_tcp_server(opts, |mut s| {
        let mut buffer = [0u8; 1024];
        let buffer_len = buffer.len();
        for _i in 0..128 {
            let recv_len = s.receive(&mut buffer[..buffer_len])?;
            s.send(&mut buffer[..recv_len])?;
        }
        s.shutdown()?;
        Ok(())
    })?;
    Ok(())
}
