use rats_rs::cert::verify::{
    CertVerifier, VerifiyPolicy as RatsRsVerifiyPolicy, VerifyPolicyOutput,
};
use rats_rs::crypto::{AsymmetricAlgo, AsymmetricPrivateKey, HashAlgo};
use rats_rs::errors::*;
use rats_rs::tee::claims::Claims;
use rats_rs::tee::sgx_dcap::attester::SgxDcapAttester;
use rats_rs::tee::tdx::attester::TdxAttester;
use rats_rs::{cert::create::CertBuilder, tee::AutoAttester};
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::{c_char, c_void};
use zeroize::Zeroizing;

use crate::errors::error_obj_t;
use crate::types::{asymmetric_algo_t, attester_type_t, hash_algo_t, AttesterType};

/// Generates RATS X.509 Certificates, as part of the `rats-rs` certificate APIs.
///
/// # Arguments
///
/// * `cert_subject` - A pointer to a null-terminated string specifying the subject name for the output certificate.
/// * `hash_algo` - The hashing algorithm to be used.
/// * `asymmetric_algo` - The asymmetric encryption algorithm specified for the certificate.
/// * `attester_type` - Specifies the type of the attester.
/// * `privkey_in` - A pointer to the input private key content (PEM format). If not `NULL`, the function uses this key to generate the certificate.
/// * `privkey_len_in` - The length of the input private key content.
/// * `privkey_out` - (Only used when `privkey_in` is `NULL`) A mutable pointer to a pointer where the function will place the generated private key content in bytes (PEM format). The caller must free this memory with `rats_rs_rust_free()`.
/// * `privkey_len_out` - (Only used when `privkey_in` is `NULL`) A mutable pointer to hold the length of the generated private key. Must be initialized to 0 by the caller.
/// * `certificate_out` - A mutable pointer to a pointer where the function will place the generated certificate in PEM format. The caller is responsible for freeing this memory with `rats_rs_rust_free()`.
/// * `certificate_len_out` - A mutable pointer to hold the content length of the generated certificate.
///
/// # Returns
///
/// A pointer to an `error_obj_t` struct indicating success (`NULL`) or containing error details if the operation fails.
///
/// # Safety
///
/// This function is FFI compatibility, and caller should ensure proper handling of pointers to prevent memory leaks and undefined behavior.
#[no_mangle]
pub extern "C" fn rats_rs_create_cert(
    cert_subject: *const c_char,
    hash_algo: hash_algo_t,
    asymmetric_algo: asymmetric_algo_t,
    attester_type: attester_type_t,
    privkey_in: *const u8,
    privkey_len_in: usize,
    privkey_out: *mut *mut u8,
    privkey_len_out: *mut usize,
    certificate_out: *mut *mut u8,
    certificate_len_out: *mut usize,
) -> *mut error_obj_t {
    let cert_subject = if !cert_subject.is_null() {
        Some(
            match unsafe { CStr::from_ptr(cert_subject) }
                .to_str()
                .kind(ErrorKind::InvalidParameter)
                .context("Invalid cert_subject")
            {
                Ok(v) => v,
                Err(e) => return Box::<Error>::into_raw(Box::new(e)),
            },
        )
    } else {
        None
    };

    let provided_privkey = if privkey_in.is_null() || privkey_len_in == 0 {
        /* Need to generate a pairs of key for caller */
        if privkey_out.is_null() || privkey_len_out.is_null() {
            return Box::<Error>::into_raw(Box::new(Error::kind_with_msg(
                ErrorKind::InvalidParameter,
                "When key pair generation is required, privkey_out and privkey_len_out should not be null",
            )));
        }
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(privkey_in, privkey_len_in) })
    };

    let (pem_cert, privkey) = match rats_rs_create_cert_internal(
        cert_subject,
        hash_algo,
        asymmetric_algo,
        attester_type,
        provided_privkey,
    ) {
        Ok(v) => v,
        Err(e) => return Box::<Error>::into_raw(Box::new(e)),
    };

    /* Set output */
    let mut buf = pem_cert.into_bytes().into_boxed_slice();
    unsafe {
        certificate_len_out.write(buf.len());
        certificate_out.write(buf.as_mut_ptr());
        std::mem::forget(buf);
    };

    if provided_privkey.is_none() {
        let mut buf = <String as Clone>::clone(&privkey)
            .into_bytes()
            .into_boxed_slice();
        unsafe {
            privkey_len_out.write(buf.len());
            privkey_out.write(buf.as_mut_ptr());
            std::mem::forget(buf);
        };
    }

    return std::ptr::null_mut();
}

fn rats_rs_create_cert_internal(
    cert_subject: Option<&str>,
    hash_algo: HashAlgo,
    asymmetric_algo: AsymmetricAlgo,
    attester_type: AttesterType,
    privkey: Option<&[u8]>,
) -> Result<(String, Zeroizing<String>)> {
    macro_rules! attester_dispatch {
        ($att_type:ty) => {{
            let attester = <$att_type>::new();

            let mut builder = CertBuilder::new(attester, hash_algo);
            if let Some(cert_subject) = cert_subject {
                builder = builder.with_subject(cert_subject);
            }
            let cert_bundle = match privkey {
                Some(privkey) => {
                    let pem = std::str::from_utf8(privkey)?;
                    let key = AsymmetricPrivateKey::from_pkcs8_pem(pem)?;
                    builder.build_with_private_key(&key)?
                }
                None => builder.build(asymmetric_algo)?,
            };
            let pem_cert = cert_bundle.cert_to_pem()?;
            let privkey = cert_bundle.private_key().to_pkcs8_pem()?;
            (pem_cert, privkey)
        }};
    }

    Ok(match attester_type {
        AttesterType::Auto => attester_dispatch!(AutoAttester),
        AttesterType::SgxDcap => attester_dispatch!(SgxDcapAttester),
        AttesterType::Tdx => attester_dispatch!(TdxAttester),
    })
}

#[allow(non_camel_case_types)]
pub type verify_policy_output_t = VerifyPolicyOutput;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CClaim {
    pub name: *const c_char,
    pub value: *const u8,
    pub value_len: usize,
}

impl Default for CClaim {
    fn default() -> Self {
        Self {
            name: std::ptr::null(),
            value: std::ptr::null(),
            value_len: 0,
        }
    }
}

#[allow(non_camel_case_types)]
pub type claim_t = CClaim;

/// Represents the different verification policies that can be applied to certificates.
#[repr(C)]
pub enum VerifiyPolicy {
    /// Verifies if the certificate contains a specific set of claims.
    Contains {
        /// A pointer to an array of `claim_t` structures representing the required claims.
        claims: *const claim_t,
        /// The number of claims in the `claims` array.
        claims_len: usize,
    },
    /// Enables the use of a custom verification function, providing flexibility for specialized validation logic.
    Custom {
        /// A function pointer to the custom verification function that will be invoked.
        func: custom_verifier_func,
        /// A pointer to arbitrary data that will be passed to the custom verification function.
        args: *mut c_void,
    },
}

#[allow(non_camel_case_types)]
pub type verifiy_policy_t = VerifiyPolicy;

/// Signature of a custom verification function provided by the user.
/// This function should implement the custom logic to verify certificate claims and return the result.
/// # Arguments
///
/// * `claims` - A pointer to an array of `claim_t` structures representing the claims to be verified. Those claims are parsed from X.509 certs and provided by rats-rs.
/// * `claims_len` - The number of claims in the `claims` array.
/// * `args` - A pointer to arbitrary data provided by the caller when setting up the custom verification. Can be used within the function to hold additional context or configuration.
#[allow(non_camel_case_types)]
pub type custom_verifier_func = extern "C" fn(
    claims: *const claim_t,
    claims_len: usize,
    args: *mut c_void,
) -> verify_policy_output_t;

impl TryFrom<VerifiyPolicy> for RatsRsVerifiyPolicy {
    type Error = Error;

    fn try_from(value: VerifiyPolicy) -> Result<Self> {
        Ok(match value {
            VerifiyPolicy::Contains {
                claims: c_claims_ptr,
                claims_len: c_claims_len,
            } => {
                let mut claims = Claims::default();
                if !c_claims_ptr.is_null() {
                    let c_claims =
                        unsafe { &*std::ptr::slice_from_raw_parts(c_claims_ptr, c_claims_len) };
                    for i in 0..c_claims_len {
                        let claim = c_claims[i];
                        if claim.name.is_null() || claim.value.is_null() {
                            return Err(Error::kind_with_msg(
                                ErrorKind::InvalidParameter,
                                "claim.name and claim.value should not be null",
                            ));
                        }
                        let name = unsafe { CStr::from_ptr(claim.name) }.to_str()?;
                        let value = unsafe {
                            &*std::ptr::slice_from_raw_parts(claim.value, claim.value_len)
                        };
                        claims.insert(name.into(), value.into());
                    }
                }
                RatsRsVerifiyPolicy::Contains(claims)
            }
            VerifiyPolicy::Custom { func, args } => {
                let f = move |claims: &Claims| {
                    let mut c_claims = vec![CClaim::default(); claims.len()];
                    let mut names = vec![]; // To make lifetime longer
                    for (i, (name, value)) in claims.iter().enumerate() {
                        let name = unsafe { CString::from_vec_unchecked(name.as_bytes().into()) };
                        c_claims[i].name = name.as_ptr();
                        names.push(name);

                        c_claims[i].value = value.as_ptr();
                        c_claims[i].value_len = value.len();
                    }

                    func(c_claims.as_ptr(), c_claims.len(), args)
                };
                RatsRsVerifiyPolicy::Custom(Box::new(f))
            }
        })
    }
}

/// Verifies RATS X.509 Certificates.
///
/// This function verifies the provided X.509 certificate in PEM format against a verification policy.
/// It supports both predefined policies and custom verification logic through a user-supplied callback.
///
/// # Arguments
///
/// * `certificate` - A pointer to the PEM-encoded certificate data to be verified.
/// * `certificate_len` - The size of the certificate data content in bytes.
/// * `verifiy_policy` - An enum specifying the verification policy. See `verifiy_policy_t` for details.
/// * `verify_policy_output_out` - A mutable pointer where the result of the verification will be stored. See `See `verify_policy_output_t` for details.`
///
/// # Returns
///
/// A pointer to an error object if an error occurs during verification, or `NULL` on success.
///
/// # Safety
///
/// This function is FFI compatibility, and caller should ensure proper handling of pointers to prevent memory leaks and undefined behavior.
///
/// The caller also must ensure that the pointers provided (`certificate`, `verify_policy_output_out`) are valid and that
/// any custom functions passed are correctly implemented and safe to call.
#[no_mangle]
pub extern "C" fn rats_rs_verify_cert(
    certificate: *const u8,
    certificate_len: usize,
    verifiy_policy: verifiy_policy_t,
    verify_policy_output_out: *mut verify_policy_output_t,
) -> *mut error_obj_t {
    if certificate.is_null() || verify_policy_output_out.is_null() {
        return Box::<Error>::into_raw(Box::new(Error::kind_with_msg(
            ErrorKind::InvalidParameter,
            "certificate and verify_policy_output_out should not be null",
        )));
    }
    let cert = unsafe { &*std::ptr::slice_from_raw_parts(certificate, certificate_len) };

    let verifiy_policy = match verifiy_policy
        .try_into()
        .context("The verifiy_policy parameter is invalid")
    {
        Ok(v) => v,
        Err(e) => return Box::<Error>::into_raw(Box::new(e)),
    };

    let output = match CertVerifier::new(verifiy_policy).verify_pem(cert) {
        Ok(v) => v,
        Err(e) => return Box::<Error>::into_raw(Box::new(e)),
    };

    /* Set output */
    unsafe { verify_policy_output_out.write(output) };

    return std::ptr::null_mut();
}
