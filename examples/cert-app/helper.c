#include <openssl/pem.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/* Exporting certificate to file */
int export_cert(const char *cert_file_path, uint8_t *certificate,
                size_t certificate_size) {
    int ret = -1;
    int fd = open(cert_file_path, O_RDWR | O_CREAT, 00755);
    if (fd == -1) {
        printf("Failed to export certificate file: %s\n", strerror(errno));
        return ret;
    }
    size_t count_wirte = 0;
    int t = 0;
    while (count_wirte < certificate_size) {
        t = write(fd, ((uint8_t *)certificate) + count_wirte,
                  certificate_size - count_wirte);
        if (t == -1) {
            printf("Failed to export certificate file: %s\n", strerror(errno));
            close(fd);
            return ret;
        }
        count_wirte += t;
    }
    close(fd);
    printf("Path to the generated certificate: %s\n", cert_file_path);
    ret = 0;
    return ret;
}

int generate_key_pairs(uint8_t **private_key_out,
                       size_t *private_key_size_out) {
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;

    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;

    uint8_t *private_key = NULL;
    long private_key_size;

    int ret = -1;

    /* Generate private key and public key */
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey)
        goto err;
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    if (!EC_KEY_generate_key(eckey))
        goto err;

    if (!EC_KEY_check_key(eckey))
        goto err;

    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    eckey = NULL;

    /* Encode private key */
    bio = BIO_new(BIO_s_mem());
    if (!bio)
        goto err;

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
        goto err;

    private_key_size = BIO_get_mem_data(bio, &private_key);
    if (private_key_size <= 0)
        goto err;

    BIO_get_mem_ptr(bio, &bptr);
    (void)BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);
    bio = NULL;
    bptr->data = NULL;
    BUF_MEM_free(bptr);
    bptr = NULL;

    /* Set function output */
    *private_key_out = private_key;
    private_key = NULL;
    *private_key_size_out = private_key_size;

    ret = 0;
err:
    if (private_key)
        free(private_key);
    if (bio)
        BIO_free(bio);
    if (bptr)
        BUF_MEM_free(bptr);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (eckey)
        EC_KEY_free(eckey);
    if (ret)
        printf("Failed to generate private key\n");
    return ret;
}
