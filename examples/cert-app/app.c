#include <string.h>
#include <stdio.h>
#include <rats-rs/rats-rs.h>
#include <common.h>

#define EXPORT_CERT_FILE_PATH "/tmp/cert.pem"
#define EXPORT_CERT_FILE_PATH_OCCLUM "/host/cert.pem"

int app_startup(bool no_privkey, const rats_rs_claim_t *custom_claims,
                size_t custom_claims_len, rats_rs_attester_type_t attester_type,
                rats_rs_log_level_t log_level) {
    uint8_t *certificate = NULL;
    size_t certificate_len = 0;
    int ret;

    /* Set log level */
    rats_rs_set_log_level(log_level);

    /* Call sub funciton to get cert */
    ret = app_create_cert(no_privkey, attester_type, custom_claims,
                          custom_claims_len, &certificate, &certificate_len);
    if (ret) {
        printf("Certificate generation:\tFAILED\n");
        goto err;
    }
    if (certificate == NULL || certificate_len == 0) {
        printf("Certificate generation:\tFAILED (empty certificate)\n");
        goto err;
    }
    printf("Certificate generation:\tSUCCESS\n");

    if (getenv("OCCLUM") == NULL) {
        ret = export_cert(EXPORT_CERT_FILE_PATH, certificate, certificate_len);
    } else {
        ret = export_cert(EXPORT_CERT_FILE_PATH_OCCLUM, certificate,
                          certificate_len);
    }
    if (ret != 0)
        goto err;

    /* Call sub funciton to verify cert */
    const rats_rs_claim_t *expected_claims = custom_claims;
    /* TODO: In a real application, caller should append tee specific claims
     * like common_quote_type, sgx_mr_signer and sgx_mr_enclave. See:
     * rats-rs/src/tee/sgx_dcap/claims.rs, rats-rs/src/tee/tdx/claims.rs,
     * rats-rs/src/tee/claims.rs.
     */
    size_t expected_claims_len = custom_claims_len;

    ret = app_verify_cert(certificate, certificate_len, expected_claims,
                          expected_claims_len,
                          attester_type.tag == RATS_RS_ATTESTER_TYPE_COCO);
    if (ret) {
        printf("Certificate verification:\tFAILED\n");
        goto err;
    }
    printf("Certificate verification:\tSUCCESS\n");

    ret = 0;
err:
    if (certificate)
        rats_rs_rust_free(certificate, certificate_len);
    return ret;
}

int app_create_cert(bool no_privkey, rats_rs_attester_type_t attester_type,
                    const rats_rs_claim_t *custom_claims,
                    size_t custom_claims_len, uint8_t **certificate_out,
                    size_t *certificate_len_out) {
    uint8_t *privkey = NULL;
    size_t privkey_len = 0;
    rats_rs_error_obj_t *error_obj = NULL;

    int ret = -1;

    printf("\nGenerate certificate with rats-rs now ...\n");
    if (no_privkey) {
        printf("The flag no_privkey is true. We will let rats-rs to generate "
               "random key pairs.\n");

        uint8_t *privkey_out = NULL;
        size_t privkey_len_out = 0;

        error_obj = rats_rs_create_cert(
            "CN=Demo App,O=Inclavare Containers", RATS_RS_HASH_ALGO_SHA256,
            RATS_RS_ASYMMETRIC_ALGO_P256, attester_type, NULL, 0, &privkey_out,
            &privkey_len_out, certificate_out, certificate_len_out);

        if (error_obj == NULL) {
            privkey_len = privkey_len_out;
            privkey = malloc(privkey_len);
            memcpy(privkey, privkey_out, privkey_len);
            /* remenber to release mem allocated by rust */
            rats_rs_rust_free(privkey_out, privkey_len_out);
        }
    } else {
        printf("The flag no_privkey is false. Now generate key pairs for "
               "rats-rs.\n");

        /* Generate private key and public key */
        if (generate_key_pairs(&privkey, &privkey_len) < 0)
            goto err;

        error_obj = rats_rs_create_cert(
            "CN=Demo App,O=Inclavare Containers", RATS_RS_HASH_ALGO_SHA256,
            RATS_RS_ASYMMETRIC_ALGO_P256, attester_type, privkey, privkey_len,
            NULL, 0, certificate_out, certificate_len_out);
    }

    if (error_obj != NULL) {
        rats_rs_error_msg_t error_msg = rats_rs_err_get_msg_ref(error_obj);
        printf("Failed to generate certificate:\n");
        printf("\tError kind: %#x, msg: %.*s\n",
               rats_rs_err_get_kind(error_obj), (int)error_msg.msg_len,
               error_msg.msg);
        rats_rs_err_free(error_obj);
        goto err;
    }

    if (no_privkey) {
        printf("----------------------------------------\n");
        printf("The privkey generated by rats-rs (PEM format):\n");
        printf("privkey len: %zu\n", privkey_len);
        printf("privkey: \n%.*s\n",
               privkey[privkey_len - 1] == '\n' ? (int)privkey_len - 1
                                                : (int)privkey_len,
               privkey);
        printf("----------------------------------------\n");
    }

    ret = 0;
err:
    if (privkey)
        free(privkey);
    return ret;
}

int app_verify_cert(uint8_t *certificate, size_t certificate_len,
                    const rats_rs_claim_t *expected_claims,
                    size_t expected_claims_len, bool is_coco) {
    int ret = -1;

    printf("\n");
    printf("Verify certificate with rats-rs now ...\n");

    /* Verify certificate */
    rats_rs_verifiy_policy_t verifiy_policy;

    const char *policy_ids[] = {"default"};
    if (is_coco) {
        verifiy_policy = (rats_rs_verifiy_policy_t){
            .tag = RATS_RS_VERIFIY_POLICY_COCO,
            .COCO = {
                .verify_mode = {.tag = RATS_RS_COCO_VERIFY_MODE_EVIDENCE,
                                .EVIDENCE = {.as_addr =
                                                 "http://127.0.0.1:50004"}},
                .policy_ids = policy_ids,
                .policy_ids_len = sizeof(policy_ids) / sizeof(policy_ids[0]),
                .trusted_certs_paths = NULL,
                .trusted_certs_paths_len = 0,
                .claims_check = {
                    .tag = RATS_RS_CLAIMS_CHECK_CONTAINS,
                    .CONTAINS = {.claims = expected_claims,
                                 .claims_len = expected_claims_len},
                }}};
    } else {
        verifiy_policy = (rats_rs_verifiy_policy_t){
            .tag = RATS_RS_VERIFIY_POLICY_LOCAL,
            .LOCAL = {.claims_check = {
                          .tag = RATS_RS_CLAIMS_CHECK_CONTAINS,
                          .CONTAINS = {.claims = expected_claims,
                                       .claims_len = expected_claims_len},
                      }}};
    }

    rats_rs_verify_policy_output_t verify_policy_output =
        RATS_RS_VERIFY_POLICY_OUTPUT_FAILED;
    rats_rs_error_obj_t *error_obj = rats_rs_verify_cert(
        certificate, certificate_len, verifiy_policy, &verify_policy_output);

    if (error_obj == NULL) {
        printf("Verify cert result:\t%s\n",
               verify_policy_output == RATS_RS_VERIFY_POLICY_OUTPUT_PASSED
                   ? "PASSED"
                   : "FAILED");
        ret =
            verify_policy_output == RATS_RS_VERIFY_POLICY_OUTPUT_PASSED ? 0 : 1;
    } else {
        printf("Failed to verify cert\n");
        rats_rs_error_msg_t error_msg = rats_rs_err_get_msg_ref(error_obj);
        printf("\tError kind: %#x, msg: %.*s\n",
               rats_rs_err_get_kind(error_obj), (int)error_msg.msg_len,
               error_msg.msg);
        rats_rs_err_free(error_obj);
        ret = 1;
    }
err:
    return ret;
}
