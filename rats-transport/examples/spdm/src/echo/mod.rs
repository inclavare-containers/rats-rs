use crate::{
    spdm::{with_spdm_tcp_client, with_spdm_tcp_server},
    CommonClientOptions, CommonServerOptions,
};
use anyhow::Result;
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use rats_transport::{GenericSecureTransPortRead, GenericSecureTransPortWrite};

pub fn echo_client(opts: CommonClientOptions) -> Result<()> {
    with_spdm_tcp_client(&opts, |requester| {
        let (mut read_half, mut write_half) = requester.into_split()?;

        let mut rng = SmallRng::from_entropy();
        for _i in 0..128 {
            let mut expected = [0u8; 8];
            let expected_len = expected.len();

            rng.fill_bytes(&mut expected);
            write_half.send(&expected)?;

            let mut buffer = [0u8; rats_transport::spdm::MAX_SPDM_MSG_SIZE];
            let recv_len = read_half.receive(&mut buffer[..expected_len])?;

            assert_eq!(expected_len, recv_len);
            assert_eq!(expected, buffer[..expected_len]);
        }
        write_half.shutdown()?;
        Ok(())
    })?;

    Ok(())
}

pub fn echo_server(opts: CommonServerOptions) -> Result<()> {
    with_spdm_tcp_server(&opts, |responder| {
        let (mut read_half, mut write_half) = responder.into_split()?;

        let mut buffer = [0u8; rats_transport::spdm::MAX_SPDM_MSG_SIZE];
        let buffer_len = buffer.len();
        for _i in 0..128 {
            let recv_len = read_half.receive(&mut buffer[..buffer_len])?;
            write_half.send(&mut buffer[..recv_len])?;
        }

        write_half.shutdown()?;
        Ok(())
    })?;

    Ok(())
}
