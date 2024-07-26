#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <rats-rs/rats-rs.h>
#include <common.h>

int main(int argc, char **argv) {
    printf("    - Welcome to rats-rs example cert-app program\n");

    char *const short_options = "hkC:a:l:";
    // clang-format off
    struct option long_options[] = {
        { "help", no_argument, NULL, 'h' },
        { "no-privkey", no_argument, NULL, 'k'},
        { "add-claim", required_argument, NULL, 'C' },
        { "attester", required_argument, NULL, 'a' },
        { "log-level", required_argument, NULL, 'l' },
        { 0, 0, 0, 0 }
    };
    // clang-format on

    bool no_privkey = false;
    rats_rs_claim_t claims[64];
    size_t claims_count = 0;
    rats_rs_attester_type_t attester_type = {
        .tag = RATS_RS_ATTESTER_TYPE_LOCAL,
        .LOCAL = {.type = RATS_RS_LOCAL_ATTESTER_TYPE_AUTO}};
    rats_rs_log_level_t log_level = RATS_RS_LOG_LEVEL_ERROR;
    int opt;

    do {
        opt = getopt_long(argc, argv, short_options, long_options, NULL);
        switch (opt) {
        case 'k':
            no_privkey = true;
            break;
        case 'C':;

            const char *divider = strchr(optarg, ':');
            if (!divider) {
                printf("Invalid argment '%s', shall in format: 'key:val'\n",
                       optarg);
                exit(1);
            }

            char *name = malloc(divider - optarg + 1);
            memcpy(name, optarg, divider - optarg);
            name[divider - optarg] = '\0';
            claims[claims_count].name = name;

            size_t value_len = strlen(optarg) - (divider - optarg + 1);
            uint8_t *value = malloc(value_len);
            memcpy(value, divider + 1, value_len);
            claims[claims_count].value = value;
            claims[claims_count].value_len = value_len;
            claims_count++;
            break;
        case 'a':
            if (!strcasecmp(optarg, "coco"))
                // TODO: allow specific aa address in cmdline arguments
                attester_type = (rats_rs_attester_type_t){
                    .tag = RATS_RS_ATTESTER_TYPE_COCO,
                    .COCO = {
                        .attest_mode = {.tag =
                                            RATS_RS_COCO_ATTEST_MODE_EVIDENCE},
                        .aa_addr = "unix:///tmp/attestation.sock",
                        .timeout = 0}};
            else if (!strcasecmp(optarg, "auto"))
                attester_type = (rats_rs_attester_type_t){
                    .tag = RATS_RS_ATTESTER_TYPE_LOCAL,
                    .LOCAL = {.type = RATS_RS_LOCAL_ATTESTER_TYPE_AUTO}};
            else if (!strcasecmp(optarg, "sgx-dcap"))
                attester_type = (rats_rs_attester_type_t){
                    .tag = RATS_RS_ATTESTER_TYPE_LOCAL,
                    .LOCAL = {.type = RATS_RS_LOCAL_ATTESTER_TYPE_SGX_DCAP}};
            else if (!strcasecmp(optarg, "tdx"))
                attester_type = (rats_rs_attester_type_t){
                    .tag = RATS_RS_ATTESTER_TYPE_LOCAL,
                    .LOCAL = {.type = RATS_RS_LOCAL_ATTESTER_TYPE_TDX}};
            else {
                printf("ERROR: unknown log level `%s` Supported attester type: "
                       "auto, sgx-ecdsa, tdx\n",
                       optarg);
                exit(1);
            }
            break;
        case 'l':
            if (!strcasecmp(optarg, "trace"))
                log_level = RATS_RS_LOG_LEVEL_TRACE;
            else if (!strcasecmp(optarg, "debug"))
                log_level = RATS_RS_LOG_LEVEL_DEBUG;
            else if (!strcasecmp(optarg, "info"))
                log_level = RATS_RS_LOG_LEVEL_INFO;
            else if (!strcasecmp(optarg, "warn"))
                log_level = RATS_RS_LOG_LEVEL_WARN;
            else if (!strcasecmp(optarg, "error"))
                log_level = RATS_RS_LOG_LEVEL_ERROR;
            else if (!strcasecmp(optarg, "off"))
                log_level = RATS_RS_LOG_LEVEL_OFF;
            else
                printf("WARN: unknown log level `%s` Supported log level: off, "
                       "error, warn, info, debug. The `error` level is "
                       "selected now\n",
                       optarg);
            break;
        case -1:
            break;
        case 'h':
            // clang-format off
			puts(
                 "    Usage:\n\n"
			     "        cert-app <options> [arguments]\n\n"
			     "    Options:\n\n"
			     "        --no-privkey/-k               Set to enable key pairs generation in rats-rs\n"
			     "        --add-claim/-C key:val        Add a user-defined custom claims\n"
			     "        --attester/-a value           Set the type of quote attester. (Should be one of: coco, auto, sgx-ecdsa, tdx. Default: auto)\n"
			     "        --log-level/-l                Set the log level. (Should be one of: off, error, warn, info, debug, trace. Default: error)\n"
			     "        --help/-h                     Show the usage\n"
            );
            // clang-format on
            exit(1);
        default:
            exit(1);
        }
    } while (opt != -1);

    return app_startup(no_privkey, claims, claims_count, attester_type,
                       log_level);
}
