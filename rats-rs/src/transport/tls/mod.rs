mod client;
mod server;

use super::{Error, ErrorKind, Result};
use crate::{
    cert::{
        dice::extensions::{OID_TCG_DICE_ENDORSEMENT_MANIFEST, OID_TCG_DICE_TAGGED_EVIDENCE},
        verify::{
            verify_cert_der, CertVerifier, VerifiyPolicy, VerifiyPolicy::Contains,
            VerifyPolicyOutput,
        },
    },
    tee::claims::Claims,
};
use bitflags::bitflags;
pub use client::{Client, TlsClientBuilder};
use lazy_static::lazy_static;
use libc::c_int;
use log::{debug, error};
use openssl_sys::*;
use pkcs8::ObjectIdentifier;
pub use server::{Server, TlsServerBuilder};
use std::{
    cell::Cell,
    net::TcpStream,
    os::fd::AsRawFd,
    ptr, slice,
    sync::{Arc, Mutex, Once},
};

lazy_static! {
    static ref OPENSSL_EX_DATA_IDX: Arc<Mutex<Cell<i32>>> = unsafe {
        Arc::new(Mutex::new(Cell::new(CRYPTO_get_ex_new_index(
            4,
            0,
            ptr::null_mut(),
            None,
            None,
            None,
        ))))
    };
}

static START: Once = Once::new();

trait GetFd {
    fn get_fd(&self) -> i32;
}

struct GetFdDumpImpl;

impl GetFd for GetFdDumpImpl {
    fn get_fd(&self) -> i32 {
        0
    }
}

struct TcpWrapper(TcpStream);

impl GetFd for TcpWrapper {
    fn get_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

#[inline]
pub fn as_raw_mut<F, T>(p: &mut F) -> *mut T {
    p as *mut F as usize as *mut T
}

#[inline]
pub fn as_raw<F, T>(p: &F) -> *const T {
    p as *const F as usize as *const T
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct SslMode : i32 {
        const SSL_VERIFY_NONE                 = 0x00;
        const SSL_VERIFY_PEER                 = 0x01;
        const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        const SSL_VERIFY_CLIENT_ONCE          = 0x04;
        const SSL_VERIFY_POST_HANDSHAKE       = 0x08;
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct SslInit : u64 {
        const LOAD_CRYPTO_STRINGS = 0x0000_0002;
        const ADD_ALL_CIPHERS = 0x0000_0004;
        const ADD_ALL_DIGESTS = 0x0000_0008;
        const LOAD_SSL_STRINGS = 0x0020_0000;
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct EpvPkey : i32 {
        const EC = 408;
        const RSA = 6;
    }
}

pub fn ossl_init() -> Result<()> {
    START.call_once(|| unsafe {
        OPENSSL_init_crypto(
            SslInit::ADD_ALL_DIGESTS.bits() | SslInit::ADD_ALL_DIGESTS.bits(),
            ptr::null(),
        );
        OPENSSL_init_ssl(
            SslInit::LOAD_SSL_STRINGS.bits() | SslInit::LOAD_CRYPTO_STRINGS.bits(),
            ptr::null(),
        );
        OPENSSL_init_crypto(SslInit::LOAD_CRYPTO_STRINGS.bits(), ptr::null());
        OPENSSL_init_crypto(SslInit::ADD_ALL_DIGESTS.bits(), ptr::null());
    });
    if unsafe { OPENSSL_init_ssl(0, ptr::null()) } < 0 {
        return Err(Error::kind(ErrorKind::OsslInitializeFail));
    }
    Ok(())
}

extern "C" fn verify_certificate_default(
    preverify_ok: libc::c_int,
    ctx: *mut X509_STORE_CTX,
) -> libc::c_int {
    if preverify_ok == 0 {
        debug!("preverify_ok is 0");
        let err = unsafe { X509_STORE_CTX_get_error(ctx) };
        if err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT {
            return 1;
        }
        error!("Failed on pre-verification due to {}\n", err);
        if err == X509_V_ERR_CERT_NOT_YET_VALID {
            error!(
                "Please ensure check the time-keeping is consistent between client and server\n"
            );
        }
        return 0;
    }
    let raw_cert = unsafe { X509_STORE_CTX_get_current_cert(ctx) };
    let mut raw_ptr = ptr::null_mut::<u8>();
    let len = unsafe { i2d_X509(raw_cert, &mut raw_ptr as *mut *mut u8) };
    let now = unsafe { slice::from_raw_parts(raw_ptr as *const u8, len as usize) };
    let res = CertVerifier::new(Contains(Claims::new())).verify(now);
    match res {
        Ok(VerifyPolicyOutput::Passed) => {
            return 1;
        }
        Ok(VerifyPolicyOutput::Failed) => {
            error!("Verify failed because of claims");
            return 0;
        }
        Err(err) => {
            error!("Verify failed with err: {:?}", err);
            return 0;
        }
    }
}

#[cfg(test)]
mod test {
    use super::ossl_init;
    use crate::errors::*;

    #[test]
    fn test_ossl_init() -> Result<()> {
        ossl_init()?;
        Ok(())
    }
}
