// mod spdm_emu;
// mod spdm_requester_emu;
// mod spdm_responder_emu;
pub mod half;
mod io;
pub mod requester;
pub mod responder;
mod secret;
mod transport;

use bitflags::bitflags;
pub use spdmlib::config::MAX_SPDM_MSG_SIZE;

bitflags! {
    pub struct VerifyMode: u32 {
        const VERIFY_NONE = 0b00000000;
        const VERIFY_PEER = 0b00000001;
        const B = 0b00000010;
        const C = 0b00000100;
    }
}
