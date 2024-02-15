mod spdm_emu;
mod spdm_requester_emu;
mod spdm_responder_emu;


use super::GenericTransPort;

struct SpdmTransPort {}

impl GenericTransPort for SpdmTransPort {
    fn negotiate(&self) -> super::Result<()> {
        todo!()
    }

    fn send(&self, bytes: &[u8]) -> super::Result<()> {
        todo!()
    }

    fn receive(&self) -> super::Result<()> {
        todo!()
    }
}
