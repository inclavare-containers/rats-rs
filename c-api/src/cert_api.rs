use rats_cert::cert::create::CertBuilder;
use rats_cert::cert::verify::{
    CertVerifier, ClaimsCheck as RatsRsClaimsCheck, CocoVerifyMode as RatsRsCocoVerifyMode,
    VerifyPolicy as RatsRsVerifyPolicy, VerifyPolicyOutput,
};
use rats_cert::crypto::{AsymmetricAlgo, AsymmetricPrivateKey, HashAlgo};
use rats_cert::errors::*;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::coco::attester::CocoAttester;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::AttesterPipeline;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::{c_char, c_void};
use std::vec;
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
        ($attester:expr) => {{
            let attester = $attester;

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
        #[cfg(feature = "local")]
        AttesterType::Local { r#type } => {
            use crate::types::LocalAttesterType;

            match r#type {
                LocalAttesterType::Auto => {
                    use rats_cert::tee::auto::AutoAttester;
                    attester_dispatch!(AutoAttester::new())
                }
                LocalAttesterType::SgxDcap => {
                    use rats_cert::tee::sgx_dcap::attester::SgxDcapAttester;
                    attester_dispatch!(SgxDcapAttester::new())
                }
                LocalAttesterType::Tdx => {
                    use rats_cert::tee::tdx::attester::TdxAttester;
                    attester_dispatch!(TdxAttester::new())
                }
            }
        }
        #[cfg(not(feature = "local"))]
        AttesterType::Local { r#type: _ } => {
            return Err(Error::kind_with_msg(
                ErrorKind::UnsupportedFeatures,
                "Local attester support is not enabled in rats-rs",
            ));
        }
        #[cfg(feature = "coco")]
        AttesterType::Coco {
            attest_mode,
            aa_addr,
            timeout_nano,
        } => {
            let aa_addr = unsafe { CStr::from_ptr(aa_addr) }
                .to_str()
                .kind(ErrorKind::InvalidParameter)
                .context("Invalid aa_addr")?;
            let coco_attester = CocoAttester::new_with_timeout_nano(aa_addr, timeout_nano)?;
            match attest_mode {
                crate::types::CocoAttestMode::Evidence => attester_dispatch!(coco_attester),
                crate::types::CocoAttestMode::Token {
                    as_addr,
                    policy_ids: policy_ids_ptr,
                    policy_ids_len,
                    as_is_grpc,
                } => {
                    let as_addr = ffi_convert_as_addr(as_addr)?;
                    let policy_ids = ffi_convert_policy_ids(policy_ids_ptr, policy_ids_len)?;
                    let coco_converter = CocoConverter::new(&as_addr, &policy_ids, as_is_grpc)?;
                    let attester_pipeline = AttesterPipeline::new(coco_attester, coco_converter);
                    attester_dispatch!(attester_pipeline)
                }
            }
        }
        #[cfg(not(feature = "coco"))]
        AttesterType::Coco {
            attest_mode,
            aa_addr,
            timeout,
        } => {
            return Err(Error::kind_with_msg(
                ErrorKind::UnsupportedFeatures,
                "Coco attester support is not enabled in rats-rs",
            ));
        }
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

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum CocoVerifyMode {
    /// Expect to receive a CoCo evidence (generated by attestation-agent from attester side) and verify it with CoCo attestation-service
    Evidence {
        /// The address of CoCo Attestation Service
        as_addr: *const c_char,
        /// If true, connect to Attestation Service via Grpc protocol. If false, connect via HTTP protocol.
        as_is_grpc: bool,
    },
    /// Expect to receive a CoCo token and verify the token directly.
    Token,
}

#[allow(non_camel_case_types)]
pub type coco_verify_mode_t = CocoVerifyMode;

/// Represents the different verification policies that can be applied to certificates.
#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum VerifyPolicy {
    /// Verify with Local Attester
    Local { claims_check: claims_check_t },
    /// Verify with CoCo policies. Should be used only when peer is using CoCo Attester
    Coco {
        /// The verify mode to select
        verify_mode: coco_verify_mode_t,
        /// The policy ids needed to check
        policy_ids: *const *const c_char,
        /// The length of policy_ids array
        policy_ids_len: usize,
        /// The path of all trusted certs to be used for checking CoCo AS token
        trusted_certs_paths: *const *const c_char,
        /// The length of trusted_certs_paths array
        trusted_certs_paths_len: usize,
        /// Additional strategy for checking cliams (both builtin claims and custom claims)
        claims_check: claims_check_t,
    },
}

#[allow(non_camel_case_types)]
pub type verify_policy_t = VerifyPolicy;

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum ClaimsCheck {
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
pub type claims_check_t = ClaimsCheck;

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

impl TryFrom<VerifyPolicy> for RatsRsVerifyPolicy {
    type Error = Error;

    fn try_from(value: VerifyPolicy) -> Result<Self> {
        Ok(match value {
            VerifyPolicy::Local { claims_check } => {
                RatsRsVerifyPolicy::Local(claims_check.try_into()?)
            }
            VerifyPolicy::Coco {
                verify_mode,
                policy_ids: policy_ids_ptr,
                policy_ids_len,
                trusted_certs_paths: trusted_certs_paths_ptr,
                trusted_certs_paths_len,
                claims_check,
            } => {
                let verify_mode = match verify_mode {
                    CocoVerifyMode::Evidence {
                        as_addr,
                        as_is_grpc,
                    } => {
                        let as_addr = ffi_convert_as_addr(as_addr)?;

                        RatsRsCocoVerifyMode::Evidence {
                            as_addr: as_addr,
                            as_is_grpc,
                        }
                    }
                    CocoVerifyMode::Token => RatsRsCocoVerifyMode::Token,
                };

                let policy_ids = ffi_convert_policy_ids(policy_ids_ptr, policy_ids_len)?;

                let trusted_certs_paths = if trusted_certs_paths_len == 0 {
                    None
                } else {
                    if trusted_certs_paths_ptr.is_null() {
                        return Err(Error::kind_with_msg(
                            ErrorKind::InvalidParameter,
                            "trusted_certs_paths should not be null, when trusted_certs_paths_len is not 0",
                        ));
                    }
                    let mut trusted_certs_paths = vec![];
                    for path in unsafe {
                        &*std::ptr::slice_from_raw_parts(
                            trusted_certs_paths_ptr,
                            trusted_certs_paths_len,
                        )
                    } {
                        let path = unsafe { CStr::from_ptr(*path) }
                            .to_str()
                            .context("bad trusted_certs_path")?;
                        trusted_certs_paths.push(path.to_owned())
                    }
                    Some(trusted_certs_paths)
                };

                RatsRsVerifyPolicy::Coco {
                    verify_mode,
                    policy_ids,
                    trusted_certs_paths,
                    claims_check: claims_check.try_into()?,
                }
            }
        })
    }
}

fn ffi_convert_policy_ids(
    policy_ids_ptr: *const *const c_char,
    policy_ids_len: usize,
) -> Result<Vec<String>> {
    if policy_ids_ptr.is_null() {
        return Err(Error::kind_with_msg(
            ErrorKind::InvalidParameter,
            "policy_ids should not be null",
        ));
    }
    if policy_ids_len == 0 {
        return Err(Error::kind_with_msg(
            ErrorKind::InvalidParameter,
            "policy_ids_len should not be 0",
        ));
    }
    let mut policy_ids = vec![];
    for policy_id in unsafe { &*std::ptr::slice_from_raw_parts(policy_ids_ptr, policy_ids_len) } {
        let policy_id = unsafe { CStr::from_ptr(*policy_id) }
            .to_str()
            .context("bad policy_id")?;
        policy_ids.push(policy_id.to_owned())
    }

    Ok(policy_ids)
}

fn ffi_convert_as_addr(as_addr: *const c_char) -> Result<String> {
    if as_addr.is_null() {
        return Err(Error::kind_with_msg(
            ErrorKind::InvalidParameter,
            "as_addr should not be null",
        ));
    }
    let as_addr = unsafe { CStr::from_ptr(as_addr) }
        .to_str()
        .context("bad as_addr")?
        .to_owned();
    Ok(as_addr)
}

impl TryFrom<ClaimsCheck> for RatsRsClaimsCheck {
    type Error = Error;

    fn try_from(value: ClaimsCheck) -> Result<Self> {
        Ok(match value {
            ClaimsCheck::Contains {
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
                RatsRsClaimsCheck::Contains(claims)
            }
            ClaimsCheck::Custom { func, args } => {
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
                RatsRsClaimsCheck::Custom(Box::new(f))
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
/// * `verify_policy` - An enum specifying the verification policy. See `verify_policy_t` for details.
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
    verify_policy: verify_policy_t,
    verify_policy_output_out: *mut verify_policy_output_t,
) -> *mut error_obj_t {
    if certificate.is_null() || verify_policy_output_out.is_null() {
        return Box::<Error>::into_raw(Box::new(Error::kind_with_msg(
            ErrorKind::InvalidParameter,
            "certificate and verify_policy_output_out should not be null",
        )));
    }
    let cert = unsafe { &*std::ptr::slice_from_raw_parts(certificate, certificate_len) };

    let verify_policy = match verify_policy
        .try_into()
        .context("The verify_policy parameter is invalid")
    {
        Ok(v) => v,
        Err(e) => return Box::<Error>::into_raw(Box::new(e)),
    };

    let output = match CertVerifier::new(verify_policy).verify_pem(cert) {
        Ok(v) => v,
        Err(e) => return Box::<Error>::into_raw(Box::new(e)),
    };

    /* Set output */
    unsafe { verify_policy_output_out.write(output) };

    return std::ptr::null_mut();
}
