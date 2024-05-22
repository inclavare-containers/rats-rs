#include <rats-rs/rats-rs.h>

int app_startup(bool no_privkey, const rats_rs_claim_t *custom_claims,
                size_t custom_claims_len, rats_rs_attester_type_t attester_type,
                rats_rs_log_level_t log_level);

int app_create_cert(bool no_privkey, rats_rs_attester_type_t attester_type,
                    const rats_rs_claim_t *custom_claims,
                    size_t custom_claims_len, uint8_t **certificate_out,
                    size_t *certificate_len_out);

int app_verify_cert(uint8_t *certificate, size_t certificate_len,
                    const rats_rs_claim_t *expected_claims,
                    size_t expected_claims_len, bool is_coco);

int export_cert(const char *cert_file_path, uint8_t *certificate,
                size_t certificate_size);

int generate_key_pairs(uint8_t **private_key_out, size_t *private_key_size_out);
