#[cfg(feature = "transport-spdm")]
mod spdm;

use crate::errors::*;

pub trait GenericTransPort {
    fn negotiate(&self) -> Result<()>;

    fn send(&self, bytes: &[u8]) -> Result<()>;

    fn receive(&self) -> Result<()>;
}
