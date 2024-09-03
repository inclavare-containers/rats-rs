use anyhow::{Error, Result};
use ctor::{ctor, dtor};
use lazy_static::lazy_static;
use libc::*;
use log::{error, info};
use rats_rs::cert::create::CertBuilder;
use rats_rs::crypto::{AsymmetricAlgo, HashAlgo};
use rats_rs::transport::tls::*;
use rats_rs::{crypto::DefaultCrypto, tee::AutoAttester};
use std::ptr::null_mut;
use std::{ffi::CStr, mem::transmute_copy};

#[derive(Default)]
struct OsslCtx {
    ssl_ctx_set_verify: Option<
        unsafe extern "C" fn(ctx: *mut SSL_CTX, mode: ::libc::c_int, callback: SSL_verify_cb),
    >,
    ssl_set_verify:
        Option<unsafe extern "C" fn(s: *mut SSL, mode: ::libc::c_int, callback: SSL_verify_cb)>,
    ssl_accept: Option<unsafe extern "C" fn(ssl: *mut SSL) -> ::libc::c_int>,
    ssl_connect: Option<unsafe extern "C" fn(ssl: *mut SSL) -> ::libc::c_int>,
    ssl_use_certificate_asn1: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            d: *const ::libc::c_uchar,
            len: ::libc::c_int,
        ) -> ::libc::c_int,
    >,
    ssl_use_privatekey_asn1: Option<
        unsafe extern "C" fn(pk: c_int, ssl: *mut SSL, d: *const c_uchar, len: c_long) -> c_int,
    >,
    ssl_ctx_use_privatekey_asn1: Option<
        unsafe extern "C" fn(
            pk: ::libc::c_int,
            ctx: *mut SSL_CTX,
            d: *const ::libc::c_uchar,
            len: ::libc::c_long,
        ) -> ::libc::c_int,
    >,
    ssl_ctx_use_certificate_asn1: Option<
        unsafe extern "C" fn(
            ctx: *mut SSL_CTX,
            len: ::libc::c_int,
            d: *const ::libc::c_uchar,
        ) -> ::libc::c_int,
    >,
    ssl_ctx_set_cert_verify_callback: Option<
        unsafe extern "C" fn(
            ctx: *mut SSL_CTX,
            cb: ::std::option::Option<
                unsafe extern "C" fn(
                    arg1: *mut X509_STORE_CTX,
                    arg2: *mut ::libc::c_void,
                ) -> ::libc::c_int,
            >,
            arg: *mut ::libc::c_void,
        ),
    >,
}

// Only update once
unsafe impl Sync for OsslCtx {}

lazy_static! {
    static ref OSSL_CTX: OsslCtx = {
        let ctx = init_openssl_ctx();
        if let Err(e) = ctx {
            error!("Failed to fetch openssl symbol! Error: {:?}", e);
            return OsslCtx::default();
        }
        return ctx.unwrap();
    };
}

#[inline]
fn dlsym_load<T: Sized>(name_str: &CStr) -> Result<T> {
    unsafe {
        dlerror();
        let f = dlsym(RTLD_NEXT, name_str.as_ptr());
        let e = dlerror();
        if !e.is_null() {
            return Err(Error::msg(format!(
                "Failed to find symbol with dlsym {}: {}",
                name_str.to_str().unwrap(),
                CStr::from_ptr(e).to_str().unwrap(),
            )));
        }
        if f.is_null() {
            return Err(Error::msg(format!(
                "Symbol not resolved by dlsym {}",
                name_str.to_str().unwrap(),
            )));
        }
        Ok(transmute_copy(&f))
    }
}

fn init_openssl_ctx() -> Result<OsslCtx> {
    let mut ctx = OsslCtx::default();
    ctx.ssl_accept = Some(dlsym_load(c"SSL_accept")?);
    ctx.ssl_connect = Some(dlsym_load(c"SSL_connect")?);
    ctx.ssl_set_verify = Some(dlsym_load(c"SSL_set_verify")?);
    ctx.ssl_ctx_set_verify = Some(dlsym_load(c"SSL_CTX_set_verify")?);
    ctx.ssl_ctx_use_certificate_asn1 = Some(dlsym_load(c"SSL_CTX_use_certificate_ASN1")?);
    ctx.ssl_ctx_use_privatekey_asn1 = Some(dlsym_load(c"SSL_CTX_use_PrivateKey_ASN1")?);
    ctx.ssl_use_privatekey_asn1 = Some(dlsym_load(c"SSL_use_PrivateKey_ASN1")?);
    ctx.ssl_use_certificate_asn1 = Some(dlsym_load(c"SSL_use_certificate_ASN1")?);
    ctx.ssl_ctx_set_cert_verify_callback = Some(dlsym_load(c"SSL_CTX_set_cert_verify_callback")?);
    Ok(ctx)
}

fn setup_verifier_with_openssl_ssl_ctx_obj(ctx: *mut SSL_CTX) -> c_int {
    if let Err(e) = setup_ssl_verifier(OsslObject::SslCtx(ctx)) {
        error!("setup_verifier_with_openssl_ssl_ctx_obj failed: {:?}", e);
        return 0;
    }
    return 1;
}

fn setup_verifier_with_openssl_ssl_obj(ssl: *mut SSL) -> c_int {
    if let Err(e) = setup_ssl_verifier(OsslObject::Ssl(ssl)) {
        error!("setup_verifier_with_openssl_ssl_obj failed: {:?}", e);
        return 0;
    }
    return 1;
}

fn setup_attester_with_openssl_ssl_ctx_obj(ctx: *mut SSL_CTX) -> c_int {
    if let Err(e) = setup_ssl_attester(OsslObject::SslCtx(ctx)) {
        error!("setup_attester_with_openssl_ssl_ctx_obj failed: {:?}", e);
        return 0;
    }
    return 1;
}

fn setup_attester_with_openssl_ssl_obj(ssl: *mut SSL) -> c_int {
    if let Err(e) = setup_ssl_attester(OsslObject::Ssl(ssl)) {
        error!("setup_attester_with_openssl_ssl_obj failed: {:?}", e);
        return 0;
    }
    return 1;
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_set_verify(
    ctx: *mut SSL_CTX,
    mode: c_int,
    verify_callback: SSL_verify_cb,
) {
    info!("SSL_CTX_set_verify() called");
    unsafe { OSSL_CTX.ssl_ctx_set_verify.unwrap()(ctx, mode, verify_callback) };
    setup_verifier_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_set_verify(ssl: *mut SSL, mode: c_int, verify_callback: SSL_verify_cb) {
    info!("SSL_set_verify() called");
    unsafe { OSSL_CTX.ssl_set_verify.unwrap()(ssl, mode, verify_callback) };
    setup_verifier_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_accept(ssl: *mut SSL) -> c_int {
    info!("SSL_accept() called");
    setup_verifier_with_openssl_ssl_obj(ssl);
    return unsafe { OSSL_CTX.ssl_accept.unwrap()(ssl) };
}

#[allow(non_snake_case, unused)]
#[no_mangle]
extern "C" fn SSL_connect(ssl: *mut SSL) -> c_int {
    info!("SSL_connect() called");
    setup_verifier_with_openssl_ssl_obj(ssl);
    return unsafe { OSSL_CTX.ssl_accept.unwrap()(ssl) };
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int {
    info!("SSL_CTX_use_certificate called");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_certificate_ASN1(
    ctx: *mut SSL_CTX,
    len: c_int,
    d: *const c_uchar,
) -> c_int {
    info!("SSL_CTX_use_certificate_ASN1");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_certificate_file(
    ctx: *mut SSL_CTX,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_CTX_use_certificate_file");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_certificate(ssl: *mut SSL, x: *mut X509) -> c_int {
    info!("SSL_use_certificate");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_certificate_ASN1(ssl: *mut SSL, d: *const c_uchar, len: c_int) -> c_int {
    info!("SSL_use_certificate_ASN1");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_certificate_file(
    ssl: *mut SSL,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_use_certificate_file");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_certificate_chain_file(
    ctx: *mut SSL_CTX,
    file: *const c_char,
) -> c_int {
    info!("SSL_CTX_use_certificate_chain_file");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_certificate_chain_file(ssl: *mut SSL, file: *const c_char) -> c_int {
    info!("SSL_use_certificate_chain_file");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> c_int {
    info!("SSL_CTX_use_PrivateKey");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_PrivateKey_ASN1(
    pk: c_int,
    ctx: *mut SSL_CTX,
    d: *const c_uchar,
    len: c_long,
) -> c_int {
    info!("SSL_CTX_use_PrivateKey");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_PrivateKey_file(
    ctx: *mut SSL_CTX,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_CTX_use_PrivateKey_file");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_RSAPrivateKey(ctx: *mut SSL_CTX, rsa: *mut RSA) -> c_int {
    info!("SSL_CTX_use_RSAPrivateKey");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_RSAPrivateKey_ASN1(
    ctx: *mut SSL_CTX,
    d: *const c_uchar,
    len: c_long,
) -> c_int {
    info!("SSL_CTX_use_RSAPrivateKey_ASN1");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_RSAPrivateKey_file(
    ctx: *mut SSL_CTX,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_CTX_use_RSAPrivateKey_file");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_PrivateKey(ssl: *mut SSL, pkey: *mut EVP_PKEY) -> c_int {
    info!("SSL_use_PrivateKey");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_PrivateKey_ASN1(
    pk: c_int,
    ssl: *mut SSL,
    d: *const c_uchar,
    len: c_long,
) -> c_int {
    info!("SSL_use_PrivateKey_ASN1");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_PrivateKey_file(
    ssl: *mut SSL,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_use_PrivateKey_file");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_RSAPrivateKey(ssl: *mut SSL, rsa: *mut RSA) -> c_int {
    info!("SSL_use_RSAPrivateKey");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_RSAPrivateKey_ASN1(
    ssl: *mut SSL,
    d: *const c_uchar,
    len: c_long,
) -> c_int {
    info!("SSL_use_RSAPrivateKey_ASN1");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_RSAPrivateKey_file(
    ssl: *mut SSL,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    info!("SSL_use_RSAPrivateKey_file");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_use_cert_and_key(
    ctx: *mut SSL_CTX,
    x509: *mut X509,
    privatekey: *mut EVP_PKEY,
    chain: *mut stack_st_X509,
    override_: c_int,
) -> c_int {
    info!("SSL_CTX_use_cert_and_key");
    return setup_attester_with_openssl_ssl_ctx_obj(ctx);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_use_cert_and_key(
    ssl: *mut SSL,
    x509: *mut X509,
    privatekey: *mut EVP_PKEY,
    chain: *mut stack_st_X509,
    override_: c_int,
) -> c_int {
    info!("SSL_use_cert_and_key");
    return setup_attester_with_openssl_ssl_obj(ssl);
}

#[allow(non_snake_case, unused)]
#[no_mangle]
pub extern "C" fn SSL_CTX_set_cert_verify_callback(
    ctx: *mut SSL_CTX,
    cb: ::std::option::Option<
        unsafe extern "C" fn(arg1: *mut X509_STORE_CTX, arg2: *mut ::libc::c_void) -> ::libc::c_int,
    >,
    arg: *mut ::libc::c_void,
) -> c_int {
    info!("SSL_CTX_set_cert_verify_callback");
    return setup_verifier_with_openssl_ssl_ctx_obj(ctx);
}

// Only setting `SSL_set_verify` or `SSL_CTX_set_veriy` as rats-rs certificate verify hook is not enough, since some openssl lib users(like curl) will use
// `SSL_get_verify_result` to get certificate verify result, which is still produced by the default openssl cerfiticate verify function. we should provide
// a entire certificate verify callback.
// check https://docs.openssl.org/master/man3/SSL_CTX_set_cert_verify_callback/ for more information.
#[no_mangle]
pub extern "C" fn cert_verify_callback(ctx: *mut X509_STORE_CTX, _: *mut ::libc::c_void) -> c_int {
    let ssl = unsafe {
        X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()) as *mut SSL
    };
    let res = unsafe { X509_verify_cert(ctx) };
    let err = unsafe { X509_STORE_CTX_get_error(ctx) };
    // we tolerate self signed error
    if err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT {
        unsafe { X509_STORE_CTX_set_error(ctx, X509_V_OK) };
        unsafe { SSL_set_verify_result(ssl, 0) };
    }
    return res;
}

pub enum OsslObject {
    Ssl(*mut SSL),
    SslCtx(*mut SSL_CTX),
}

pub fn setup_ssl_attester(obj: OsslObject) -> Result<()> {
    let privkey = DefaultCrypto::gen_private_key(AsymmetricAlgo::Rsa2048)?;
    let cert = CertBuilder::new(AutoAttester::new(), HashAlgo::Sha256)
        .build_with_private_key(&privkey)?
        .cert_to_der()?;
    let epkey;
    match &privkey {
        rats_rs::crypto::AsymmetricPrivateKey::Rsa2048(_)
        | rats_rs::crypto::AsymmetricPrivateKey::Rsa3072(_)
        | rats_rs::crypto::AsymmetricPrivateKey::Rsa4096(_) => {
            epkey = EVP_PKEY_RSA;
        }
        rats_rs::crypto::AsymmetricPrivateKey::P256(_) => {
            epkey = EVP_PKEY_EC;
        }
    }
    let pkey = privkey.to_pkcs8_der()?;
    let pkey_len = pkey.as_bytes().len();
    let pkey_buffer = pkey.as_bytes().as_ptr();

    unsafe {
        ERR_clear_error();
    }
    match obj {
        OsslObject::Ssl(ssl) => {
            let mut res = unsafe {
                OSSL_CTX.ssl_use_certificate_asn1.unwrap()(ssl, cert.as_ptr(), cert.len() as c_int)
            };
            if res != 1 {
                return Err(Error::msg(format!(
                    "Failed to setup certificate: {}",
                    unsafe {
                        CStr::from_ptr(ERR_error_string(ERR_get_error(), null_mut())).to_str()?
                    }
                )));
            }
            res = unsafe {
                OSSL_CTX.ssl_use_privatekey_asn1.unwrap()(
                    epkey,
                    ssl,
                    pkey_buffer,
                    pkey_len as c_long,
                )
            };
            if res != 1 {
                return Err(Error::msg(format!(
                    "Failed to setup privatekey: {}",
                    unsafe {
                        CStr::from_ptr(ERR_error_string(ERR_get_error(), null_mut())).to_str()?
                    }
                )));
            }
        }
        OsslObject::SslCtx(ctx) => {
            let mut res = unsafe {
                OSSL_CTX.ssl_ctx_use_certificate_asn1.unwrap()(
                    ctx,
                    cert.len() as c_int,
                    cert.as_ptr(),
                )
            };
            if res != 1 {
                return Err(Error::msg(format!(
                    "Failed to setup certificate: {}",
                    unsafe {
                        CStr::from_ptr(ERR_error_string(ERR_get_error(), null_mut())).to_str()?
                    }
                )));
            }
            res = unsafe {
                OSSL_CTX.ssl_ctx_use_privatekey_asn1.unwrap()(
                    epkey,
                    ctx,
                    pkey_buffer,
                    pkey_len as c_long,
                )
            };
            if res != 1 {
                return Err(Error::msg(format!(
                    "Failed to setup privatekey: {}",
                    unsafe {
                        CStr::from_ptr(ERR_error_string(ERR_get_error(), null_mut())).to_str()?
                    }
                )));
            }
        }
    }
    Ok(())
}

pub fn setup_ssl_verifier(obj: OsslObject) -> Result<()> {
    match obj {
        OsslObject::Ssl(ssl) => {
            let old_cb = unsafe { SSL_get_verify_callback(ssl) };
            let ctx = unsafe { SSL_get_SSL_CTX(ssl) };
            let cert_store = unsafe { SSL_CTX_get_cert_store(ctx) };
            let verify_mode = unsafe { SSL_get_verify_mode(ssl) };
            if old_cb.is_some() && old_cb.unwrap() == verify_certificate_default {
                return Ok(());
            }
            unsafe {
                X509_STORE_set_ex_data(cert_store, *OPENSSL_EX_DATA_IDX, ctx as *mut c_void);
                OSSL_CTX.ssl_set_verify.unwrap()(
                    ssl,
                    verify_mode,
                    Some(verify_certificate_default),
                );
                OSSL_CTX.ssl_ctx_set_cert_verify_callback.unwrap()(
                    ctx,
                    Some(cert_verify_callback),
                    null_mut(),
                );
            }
        }
        OsslObject::SslCtx(ctx) => {
            let old_cb = unsafe { SSL_CTX_get_verify_callback(ctx) };
            let cert_store = unsafe { SSL_CTX_get_cert_store(ctx) };
            let verify_mode = unsafe { SSL_CTX_get_verify_mode(ctx) };
            if old_cb.is_some() && old_cb.unwrap() == verify_certificate_default {
                return Ok(());
            }
            unsafe {
                X509_STORE_set_ex_data(cert_store, *OPENSSL_EX_DATA_IDX, ctx as *mut c_void);
                OSSL_CTX.ssl_ctx_set_verify.unwrap()(
                    ctx,
                    verify_mode,
                    Some(verify_certificate_default),
                );
                OSSL_CTX.ssl_ctx_set_cert_verify_callback.unwrap()(
                    ctx,
                    Some(cert_verify_callback),
                    null_mut(),
                );
            }
        }
    }
    Ok(())
}

#[ctor]
fn init() {
    let env = env_logger::Env::default()
        .filter_or("RATS_RS_LOG_LEVEL", "debug")
        .write_style_or("RATS_RS_LOG_STYLE", "always");
    env_logger::Builder::from_env(env).init();
    if let Err(e) = ossl_init() {
        error!("openssl init error: {:?}", e);
    }
}

#[dtor]
fn fini() {
    info!("openssl-hook finish");
}
