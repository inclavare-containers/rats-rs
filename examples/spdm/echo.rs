use crate::{
    spdm::{with_spdm_tcp_client, with_spdm_tcp_server},
    CommonClientOptions, CommonServerOptions,
};
use anyhow::Result;
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use rats_rs::transport::GenericSecureTransPort;

pub fn echo_client(opts: CommonClientOptions) -> Result<()> {
    with_spdm_tcp_client(&opts, |mut requester| {
        let mut rng = SmallRng::from_entropy();
        for _i in 0..128 {
            let mut expected = [0u8; 8];
            let expected_len = expected.len();

            rng.fill_bytes(&mut expected);
            requester.send(&expected)?;

            let mut buffer = [0u8; rats_rs::transport::spdm::MAX_SPDM_MSG_SIZE];
            let recv_len = requester.receive(&mut buffer[..expected_len])?;

            assert_eq!(expected_len, recv_len);
            assert_eq!(expected, buffer[..expected_len]);
        }
        Ok(())
    })?;

    Ok(())
}

pub fn echo_server(opts: CommonServerOptions) -> Result<()> {
    with_spdm_tcp_server(&opts, |mut responder| {
        let mut buffer = [0u8; rats_rs::transport::spdm::MAX_SPDM_MSG_SIZE];
        let buffer_len = buffer.len();
        for _i in 0..128 {
            let recv_len = responder.receive(&mut buffer[..buffer_len])?;
            responder.send(&mut buffer[..recv_len])?;
        }
        Ok(())
    })?;

    Ok(())
}
