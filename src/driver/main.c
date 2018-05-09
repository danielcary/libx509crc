#include <stdbool.h>
#include <getopt.h>
#include <openssl/err.h>
#include <openssl/ocsperr.h>

#include "ssl_connect.h"
#include "../lib/transparency.h"
#include "../lib/lib.h"

int main(int argc, char **argv)
{
    /* Possible argument options */
    static struct option long_options[] = {
        {"url", required_argument, 0, 'u'},
        {"port", required_argument, 0, 'p'},
        {"ocsp", no_argument, 0, 'o'},
        {"stapling", no_argument, 0, 's'},
        {"crl", no_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {"transparency", no_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    /* Parse arguments */
    const char *url = "https://www.cisco.com";
    int port = 443;
    bool ocsp = false;
    bool stapling = false;
    bool crl = false;
    bool verbose = false;
    bool transparency = false;

    int opt = -1;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "u:p:oscvt", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'u':
                url = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'o':
                ocsp = true;
                break;
            case 's':
                stapling = true;
                break;
            case 'c':
                crl = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 't':
                transparency = true;
                break;
            default:
                exit(1);
        }
    }

    /* Initialize the OpenSSL Library */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    ERR_load_OCSP_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0) {
        printf("Could not initialize the OpenSSL library !\n");
        return -1;
    }

    /* Set the error output log BIO for the X509CRC library */
    BIO *err_bio = BIO_new_fp(stderr, BIO_NOCLOSE);
    X509CRC_set_err_BIO(err_bio);

    /* Set the info output log BIO for the X509CRC library */
    BIO *out_bio = NULL;
    if(verbose) {
        out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509CRC_set_info_BIO(out_bio);
    }

    /* Create TLS/SSL connection to specified host */
    int stapling_status = 0;
    SSL *ssl = create_connection(url, port, stapling ? validate_ocsp_stapling : NULL, &stapling_status, out_bio);
    if(!ssl) {
        printf("Error creating connection!\n");
        if(stapling && stapling_status == 1) {
            printf("OCSP Stapling: Revoked\n");
        } else {
            printf("OCSP Stapling check failed!\n");
        }
        return -1;
    }

    /* Print the certificate out */
    if (verbose) {
        X509 *cert = SSL_get_peer_certificate(ssl);
        X509_print(out_bio, cert);
    }
    
    if (transparency) {
        switch(validate_transparency(ssl, NULL)) {
            case 1:
                printf("SCTs ok\n");
                break;
            default:
            case 0:
                printf("SCTs cannot be validated\n");
                break;
        }
    }
    
    if (stapling) {
        if(stapling_status == 0) {
            printf("OCSP Stapling: Good\n");
        }
    }

    if (ocsp) {
        ASN1_TIME* next_update = NULL;
        switch(validate_ocsp(ssl, &next_update)) {
            case 0:
                printf("OCSP: good");
                BIO_printf(out_bio, "\nNext update time: ");
                ASN1_TIME_print(out_bio, next_update);
                printf("\n");
                break;
            case 1:
                printf("OCSP: revoked\n");
                break;
            default:
                printf("OCSP check failed!\n");
                break;
        }
        ASN1_STRING_free((ASN1_STRING*)next_update);
    }

    if (crl) {
        ASN1_TIME* next_time = NULL;
        switch(validate_crl(ssl, &next_time)) {
            case 0:
                printf("The CRL has NOT listed the certificate as being revoked.");
                BIO_printf(out_bio, "\nNext CRL Update time: ");
                ASN1_TIME_print(out_bio, next_time);
                printf("\n");
                break;
            case 1:
                printf("The CRL lists the certificate as being REVOKED.\n");
                break;
            default:
                printf("CRL check failed!\n");
                break;
        }
        ASN1_STRING_free((ASN1_STRING*)next_time);
    }

    close_connection();
    BIO_free(out_bio);
    BIO_free(err_bio);

    return 0;
}
