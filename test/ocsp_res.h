#include <pthread.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

void ocsp_res_start(void (*res_ptr)(BIO*));

void ocsp_res_ssl_start(void (*res_ptr)(BIO*));

int ocsp_res_join();

void ocsp_res_bad_time(BIO *cbio);

void ocsp_res_internal_err(BIO *cbio);

void ocsp_res_null_res(BIO *cbio);

void ocsp_res_unknown(BIO *cbio);

void ocsp_res_no_res(BIO *cbio);

void ocsp_res_valid(BIO *cbio);

void ocsp_res_revoked(BIO *cbio);