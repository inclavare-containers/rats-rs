#ifndef _RATS_H_
#define _RATS_H_

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef enum rats_rs_AsymmetricAlgo {
  RATS_RS_ASYMMETRIC_ALGO_RSA2048,
  RATS_RS_ASYMMETRIC_ALGO_RSA3072,
  RATS_RS_ASYMMETRIC_ALGO_RSA4096,
  RATS_RS_ASYMMETRIC_ALGO_P256,
} rats_rs_AsymmetricAlgo;

typedef enum rats_rs_ErrorKind {
  RATS_RS_ERROR_KIND_UNKNOWN,
  RATS_RS_ERROR_KIND_UNSUPPORTED_TEE_TYPE,
  RATS_RS_ERROR_KIND_UNRECOGNIZED_EVIDENCE_TYPE,
  RATS_RS_ERROR_KIND_SGX_DCAP_UNSUPPORTED_EVIDENCE_TYPE,
  RATS_RS_ERROR_KIND_SGX_DCAP_ATTESTER_GENERATE_QUOTE_FAILED,
  RATS_RS_ERROR_KIND_SGX_DCAP_VERIFIER_VERIFY_QUOTE_FAILED,
  RATS_RS_ERROR_KIND_SGX_DCAP_VERIFIER_GET_SUPPLEMENTAL_DATA_FAILED,
  RATS_RS_ERROR_KIND_SGX_DCAP_MULFORMED_QUOTE,
  RATS_RS_ERROR_KIND_SGX_DCAP_VERIFIER_REPORT_DATA_MISMATCH,
  RATS_RS_ERROR_KIND_TDX_UNSUPPORTED_EVIDENCE_TYPE,
  RATS_RS_ERROR_KIND_TDX_ATTESTER_GENERATE_QUOTE_FAILED,
  RATS_RS_ERROR_KIND_TDX_VERIFIER_VERIFY_QUOTE_FAILED,
  RATS_RS_ERROR_KIND_TDX_VERIFIER_GET_SUPPLEMENTAL_DATA_FAILED,
  RATS_RS_ERROR_KIND_TDX_MULFORMED_QUOTE,
  RATS_RS_ERROR_KIND_TDX_VERIFIER_REPORT_DATA_MISMATCH,
  RATS_RS_ERROR_KIND_COCO_CONNECT_TTRPC_FAILED,
  RATS_RS_ERROR_KIND_COCO_REQUEST_AA_FAILED,
  RATS_RS_ERROR_KIND_COCO_REQUEST_AS_FAILED,
  RATS_RS_ERROR_KIND_COCO_VERIFY_TOKEN_FAILED,
  RATS_RS_ERROR_KIND_COCO_PARSE_TOKEN_FAILED,
  RATS_RS_ERROR_KIND_INVALID_PARAMETER,
  RATS_RS_ERROR_KIND_UNSUPPORTED_HASH_ALGO,
  RATS_RS_ERROR_KIND_CALCULATE_HASH_FAILED,
  RATS_RS_ERROR_KIND_GEN_CERT_ERROR,
  RATS_RS_ERROR_KIND_PARSE_CERT_ERROR,
  RATS_RS_ERROR_KIND_CERT_VERIFY_SIGNATURE_FAILED,
  RATS_RS_ERROR_KIND_CERT_EXTRACT_EXTENSION_FAILED,
  RATS_RS_ERROR_KIND_CERT_VERIFY_PUBLIC_KEY_HASH_FAILED,
  RATS_RS_ERROR_KIND_PARSE_PRIVATE_KEY,
  RATS_RS_ERROR_KIND_SPDM_NEGOTIATE,
  RATS_RS_ERROR_KIND_SPDM_SEND,
  RATS_RS_ERROR_KIND_SPDM_RECEIVE,
  RATS_RS_ERROR_KIND_SPDM_SHUTDOWN,
  RATS_RS_ERROR_KIND_SPDM_SESSION_NOT_READY,
  RATS_RS_ERROR_KIND_SPDM_BROKEN_SESSION,
  RATS_RS_ERROR_KIND_SPDMLIB_ERROR,
} rats_rs_ErrorKind;

typedef enum rats_rs_HashAlgo {
  RATS_RS_HASH_ALGO_SHA256,
  RATS_RS_HASH_ALGO_SHA384,
  RATS_RS_HASH_ALGO_SHA512,
} rats_rs_HashAlgo;

typedef enum rats_rs_LocalAttesterType {
  RATS_RS_LOCAL_ATTESTER_TYPE_AUTO,
  RATS_RS_LOCAL_ATTESTER_TYPE_SGX_DCAP,
  RATS_RS_LOCAL_ATTESTER_TYPE_TDX,
} rats_rs_LocalAttesterType;

typedef enum rats_rs_LogLevel {
  RATS_RS_LOG_LEVEL_OFF = 0,
  RATS_RS_LOG_LEVEL_ERROR = 1,
  RATS_RS_LOG_LEVEL_WARN = 2,
  RATS_RS_LOG_LEVEL_INFO = 3,
  RATS_RS_LOG_LEVEL_DEBUG = 4,
  RATS_RS_LOG_LEVEL_TRACE = 5,
} rats_rs_LogLevel;

/**
 * Represents the outcome of a certificate verification.
 */
typedef enum rats_rs_VerifyPolicyOutput {
  /**
   * Indicates the verification has failed.
   */
  RATS_RS_VERIFY_POLICY_OUTPUT_FAILED,
  /**
   * Indicates the verification has passed successfully.
   */
  RATS_RS_VERIFY_POLICY_OUTPUT_PASSED,
} rats_rs_VerifyPolicyOutput;

typedef struct rats_rs_Error rats_rs_Error;

typedef struct rats_rs_Error rats_rs_error_obj_t;

typedef enum rats_rs_HashAlgo rats_rs_hash_algo_t;

typedef enum rats_rs_AsymmetricAlgo rats_rs_asymmetric_algo_t;

typedef enum rats_rs_LocalAttesterType rats_rs_local_attester_type_t;

typedef enum rats_rs_CocoAttestMode_Tag {
  /**
   * Get CoCo evidence (generated by attestation-agent)
   */
  RATS_RS_COCO_ATTEST_MODE_EVIDENCE,
  /**
   * Get CoCo evidence from attestation-agent, and then convert it to CoCo attestation token.
   */
  RATS_RS_COCO_ATTEST_MODE_TOKEN,
} rats_rs_CocoAttestMode_Tag;

typedef struct rats_rs_CocoAttestMode_rats_rs_Token_Body {
  /**
   * The Grpc address of CoCo Attestation Service
   */
  const char *as_addr;
  /**
   * The policy ids needed to check
   */
  const char *const *policy_ids;
  /**
   * The length of policy_ids array
   */
  size_t policy_ids_len;
} rats_rs_CocoAttestMode_rats_rs_Token_Body;

typedef struct rats_rs_CocoAttestMode {
  rats_rs_CocoAttestMode_Tag tag;
  union {
    rats_rs_CocoAttestMode_rats_rs_Token_Body TOKEN;
  };
} rats_rs_CocoAttestMode;

typedef struct rats_rs_CocoAttestMode rats_rs_coco_attest_mode_t;

typedef enum rats_rs_AttesterType_Tag {
  RATS_RS_ATTESTER_TYPE_LOCAL,
  RATS_RS_ATTESTER_TYPE_COCO,
} rats_rs_AttesterType_Tag;

typedef struct rats_rs_AttesterType_rats_rs_Local_Body {
  /**
   * The type of local attester.
   */
  rats_rs_local_attester_type_t type;
} rats_rs_AttesterType_rats_rs_Local_Body;

typedef struct rats_rs_AttesterType_rats_rs_Coco_Body {
  /**
   * The detailed attest mode of CoCo to select
   */
  rats_rs_coco_attest_mode_t attest_mode;
  /**
   * The ttrpc unix domain socket address of attestation-agent to connect to.
   */
  const char *aa_addr;
  /**
   * Timeout for ttrpc call to AA, should be nano seconds. Wait indefinitely when set to 0.
   */
  int64_t timeout;
} rats_rs_AttesterType_rats_rs_Coco_Body;

typedef struct rats_rs_AttesterType {
  rats_rs_AttesterType_Tag tag;
  union {
    rats_rs_AttesterType_rats_rs_Local_Body LOCAL;
    rats_rs_AttesterType_rats_rs_Coco_Body COCO;
  };
} rats_rs_AttesterType;

typedef struct rats_rs_AttesterType rats_rs_attester_type_t;

typedef enum rats_rs_ErrorKind rats_rs_error_kind_t;

typedef struct rats_rs_error_msg_t {
  const char *msg;
  size_t msg_len;
} rats_rs_error_msg_t;

typedef enum rats_rs_LogLevel rats_rs_log_level_t;

typedef struct rats_rs_CClaim {
  const char *name;
  const uint8_t *value;
  size_t value_len;
} rats_rs_CClaim;

typedef struct rats_rs_CClaim rats_rs_claim_t;

typedef enum rats_rs_VerifyPolicyOutput rats_rs_verify_policy_output_t;

/**
 * Signature of a custom verification function provided by the user.
 * This function should implement the custom logic to verify certificate claims and return the result.
 * # Arguments
 *
 * * `claims` - A pointer to an array of `claim_t` structures representing the claims to be verified. Those claims are parsed from X.509 certs and provided by rats-rs.
 * * `claims_len` - The number of claims in the `claims` array.
 * * `args` - A pointer to arbitrary data provided by the caller when setting up the custom verification. Can be used within the function to hold additional context or configuration.
 */
typedef rats_rs_verify_policy_output_t (*rats_rs_custom_verifier_func)(const rats_rs_claim_t *claims,
                                                                       size_t claims_len,
                                                                       void *args);

typedef enum rats_rs_ClaimsCheck_Tag {
  /**
   * Verifies if the certificate contains a specific set of claims.
   */
  RATS_RS_CLAIMS_CHECK_CONTAINS,
  /**
   * Enables the use of a custom verification function, providing flexibility for specialized validation logic.
   */
  RATS_RS_CLAIMS_CHECK_CUSTOM,
} rats_rs_ClaimsCheck_Tag;

typedef struct rats_rs_ClaimsCheck_rats_rs_Contains_Body {
  /**
   * A pointer to an array of `claim_t` structures representing the required claims.
   */
  const rats_rs_claim_t *claims;
  /**
   * The number of claims in the `claims` array.
   */
  size_t claims_len;
} rats_rs_ClaimsCheck_rats_rs_Contains_Body;

typedef struct rats_rs_ClaimsCheck_rats_rs_Custom_Body {
  /**
   * A function pointer to the custom verification function that will be invoked.
   */
  rats_rs_custom_verifier_func func;
  /**
   * A pointer to arbitrary data that will be passed to the custom verification function.
   */
  void *args;
} rats_rs_ClaimsCheck_rats_rs_Custom_Body;

typedef struct rats_rs_ClaimsCheck {
  rats_rs_ClaimsCheck_Tag tag;
  union {
    rats_rs_ClaimsCheck_rats_rs_Contains_Body CONTAINS;
    rats_rs_ClaimsCheck_rats_rs_Custom_Body CUSTOM;
  };
} rats_rs_ClaimsCheck;

typedef struct rats_rs_ClaimsCheck rats_rs_claims_check_t;

typedef enum rats_rs_CocoVerifyMode_Tag {
  /**
   * Expect to receive a CoCo evidence (generated by attestation-agent from attester side) and verify it with CoCo attestation-service
   */
  RATS_RS_COCO_VERIFY_MODE_EVIDENCE,
  /**
   * Expect to receive a CoCo token and verify the token directly.
   */
  RATS_RS_COCO_VERIFY_MODE_TOKEN,
} rats_rs_CocoVerifyMode_Tag;

typedef struct rats_rs_CocoVerifyMode_rats_rs_Evidence_Body {
  /**
   * The Grpc address of CoCo Attestation Service
   */
  const char *as_addr;
} rats_rs_CocoVerifyMode_rats_rs_Evidence_Body;

typedef struct rats_rs_CocoVerifyMode {
  rats_rs_CocoVerifyMode_Tag tag;
  union {
    rats_rs_CocoVerifyMode_rats_rs_Evidence_Body EVIDENCE;
  };
} rats_rs_CocoVerifyMode;

typedef struct rats_rs_CocoVerifyMode rats_rs_coco_verify_mode_t;

/**
 * Represents the different verification policies that can be applied to certificates.
 */
typedef enum rats_rs_VerifyPolicy_Tag {
  /**
   * Verify with Local Attester
   */
  RATS_RS_VERIFY_POLICY_LOCAL,
  /**
   * Verify with CoCo policies. Should be used only when peer is using CoCo Attester
   */
  RATS_RS_VERIFY_POLICY_COCO,
} rats_rs_VerifyPolicy_Tag;

typedef struct rats_rs_VerifyPolicy_rats_rs_Local_Body {
  rats_rs_claims_check_t claims_check;
} rats_rs_VerifyPolicy_rats_rs_Local_Body;

typedef struct rats_rs_VerifyPolicy_rats_rs_Coco_Body {
  /**
   * The verify mode to select
   */
  rats_rs_coco_verify_mode_t verify_mode;
  /**
   * The policy ids needed to check
   */
  const char *const *policy_ids;
  /**
   * The length of policy_ids array
   */
  size_t policy_ids_len;
  /**
   * The path of all trusted certs to be used for checking CoCo AS token
   */
  const char *const *trusted_certs_paths;
  /**
   * The length of trusted_certs_paths array
   */
  size_t trusted_certs_paths_len;
  /**
   * Additional strategy for checking cliams (both builtin claims and custom claims)
   */
  rats_rs_claims_check_t claims_check;
} rats_rs_VerifyPolicy_rats_rs_Coco_Body;

typedef struct rats_rs_VerifyPolicy {
  rats_rs_VerifyPolicy_Tag tag;
  union {
    rats_rs_VerifyPolicy_rats_rs_Local_Body LOCAL;
    rats_rs_VerifyPolicy_rats_rs_Coco_Body COCO;
  };
} rats_rs_VerifyPolicy;

typedef struct rats_rs_VerifyPolicy rats_rs_verify_policy_t;

/**
 * Generates RATS X.509 Certificates, as part of the `rats-rs` certificate APIs.
 *
 * # Arguments
 *
 * * `cert_subject` - A pointer to a null-terminated string specifying the subject name for the output certificate.
 * * `hash_algo` - The hashing algorithm to be used.
 * * `asymmetric_algo` - The asymmetric encryption algorithm specified for the certificate.
 * * `attester_type` - Specifies the type of the attester.
 * * `privkey_in` - A pointer to the input private key content (PEM format). If not `NULL`, the function uses this key to generate the certificate.
 * * `privkey_len_in` - The length of the input private key content.
 * * `privkey_out` - (Only used when `privkey_in` is `NULL`) A mutable pointer to a pointer where the function will place the generated private key content in bytes (PEM format). The caller must free this memory with `rats_rs_rust_free()`.
 * * `privkey_len_out` - (Only used when `privkey_in` is `NULL`) A mutable pointer to hold the length of the generated private key. Must be initialized to 0 by the caller.
 * * `certificate_out` - A mutable pointer to a pointer where the function will place the generated certificate in PEM format. The caller is responsible for freeing this memory with `rats_rs_rust_free()`.
 * * `certificate_len_out` - A mutable pointer to hold the content length of the generated certificate.
 *
 * # Returns
 *
 * A pointer to an `error_obj_t` struct indicating success (`NULL`) or containing error details if the operation fails.
 *
 * # Safety
 *
 * This function is FFI compatibility, and caller should ensure proper handling of pointers to prevent memory leaks and undefined behavior.
 */
rats_rs_error_obj_t *rats_rs_create_cert(const char *cert_subject,
                                         rats_rs_hash_algo_t hash_algo,
                                         rats_rs_asymmetric_algo_t asymmetric_algo,
                                         rats_rs_attester_type_t attester_type,
                                         const uint8_t *privkey_in,
                                         size_t privkey_len_in,
                                         uint8_t **privkey_out,
                                         size_t *privkey_len_out,
                                         uint8_t **certificate_out,
                                         size_t *certificate_len_out);

/**
 * Free the `error_obj` returned by other apis.
 */
void rats_rs_err_free(rats_rs_error_obj_t *error_obj);

/**
 * Get error kind of this `error_obj`.
 */
rats_rs_error_kind_t rats_rs_err_get_kind(rats_rs_error_obj_t *error_obj);

/**
 * Get human-readable string for the detailed error message recoreded in this `error_obj`.
 * Caller should not modify the the message content returned by this api, and there is no need to deallocate the msg pointer. This api will not return null pointer in any case.
 */
struct rats_rs_error_msg_t rats_rs_err_get_msg_ref(rats_rs_error_obj_t *error_obj);

/**
 * This function is used to free the buffer pointed by pointers returned by some of the rats-rs APIs, to avoid memory leak. Note that you should not call libc's `free()` function on those pointers, because the allocater is different between C and Rust.
 */
void rats_rs_rust_free(uint8_t *data,
                       size_t len);

/**
 * Set log level of all log print in rats-rs, all of the supported levels can be found in `log_level_t`.
 */
void rats_rs_set_log_level(rats_rs_log_level_t log_level);

/**
 * Verifies RATS X.509 Certificates.
 *
 * This function verifies the provided X.509 certificate in PEM format against a verification policy.
 * It supports both predefined policies and custom verification logic through a user-supplied callback.
 *
 * # Arguments
 *
 * * `certificate` - A pointer to the PEM-encoded certificate data to be verified.
 * * `certificate_len` - The size of the certificate data content in bytes.
 * * `verify_policy` - An enum specifying the verification policy. See `verify_policy_t` for details.
 * * `verify_policy_output_out` - A mutable pointer where the result of the verification will be stored. See `See `verify_policy_output_t` for details.`
 *
 * # Returns
 *
 * A pointer to an error object if an error occurs during verification, or `NULL` on success.
 *
 * # Safety
 *
 * This function is FFI compatibility, and caller should ensure proper handling of pointers to prevent memory leaks and undefined behavior.
 *
 * The caller also must ensure that the pointers provided (`certificate`, `verify_policy_output_out`) are valid and that
 * any custom functions passed are correctly implemented and safe to call.
 */
rats_rs_error_obj_t *rats_rs_verify_cert(const uint8_t *certificate,
                                         size_t certificate_len,
                                         rats_rs_verify_policy_t verify_policy,
                                         rats_rs_verify_policy_output_t *verify_policy_output_out);

#endif /* _RATS_H_ */
