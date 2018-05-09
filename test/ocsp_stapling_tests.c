#include <CUnit/Basic.h>
#include <unistd.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "tests.h"
#include "certs.h"
#include "servers.h"
#include "ocsp_res.h"
#include "../src/lib/lib.h"
#include "../src/lib/errs.h"

static BIO *cbio = NULL;
static SSL *ssl = NULL;
static SSL_CTX *ssl_ctx = NULL;

int ocsp_stapling_init();

static int connect_to(const char* host, int port, int usedir);
static void close_conn();

void ocsp_stapling_valid_test();
void no_ocsp_response_test();
void no_issuer_test();
void invalid_date();
void null_response();
void unsuccessful_response();
void revoked_ocsp_stapling_test();
void no_root_cert_test();
void null_cert_store();
void null_status_pointer();

int add_ocsp_stapling_suite() {

    // create suite
    CU_pSuite suite = CU_add_suite("lib/ocsp_stapling.c tests", ocsp_stapling_init, NULL);

    if(!suite) {
        return 1;
    }

     /* Add tests */
    return !(CU_add_test(suite, "ocsp_stapling_valid_test", ocsp_stapling_valid_test) &&
             CU_add_test(suite, "no_ocsp_response_test", no_ocsp_response_test) &&
             CU_add_test(suite, "no_issuer_test", no_issuer_test) &&
             CU_add_test(suite, "invalid_date", invalid_date) &&
             CU_add_test(suite, "null_response", null_response) &&
             CU_add_test(suite, "unsuccessful_response", unsuccessful_response) &&
             CU_add_test(suite, "null_cert_store", null_cert_store) &&
             CU_add_test(suite, "revoked_ocsp_stapling_test", revoked_ocsp_stapling_test) &&
             CU_add_test(suite, "no_root_cert_test", no_root_cert_test) &&
             CU_add_test(suite, "null_status_pointer", null_status_pointer));
}


int ocsp_stapling_init() {
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    X509CRC_set_err_BIO(NULL);
    //Setup test server
    setup();
    return 0;
}

void ocsp_stapling_valid_test() {
    int status = 1;
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), 1);
    CU_ASSERT_EQUAL(status, 0);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void no_ocsp_response_test() {
    int status = 0;
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_STAPLING_NO_RESPONSE);
    close_conn();
    
    servers_join_main();
}

void no_issuer_test() {
    int status = 0;
    ocsp_res_start(ocsp_res_valid);
    servers_start_main_no_fullchain(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_NO_ISSUER_CERT);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void unsuccessful_response() {
    int status = 0;
    ocsp_res_start(ocsp_res_internal_err);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_UNSUCCESSFUL_RES);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void revoked_ocsp_stapling_test() {
    int status = 0;
    ocsp_res_start(ocsp_res_revoked);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), 0);
    CU_ASSERT_EQUAL(status, 1);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void no_root_cert_test() {
    int status = 0;
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 0);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_BASIC_VERIFY);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void invalid_date() {
    int status = 0;
    ocsp_res_start(ocsp_res_bad_time);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_CHECK_VALIDITY);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void null_response() {
    int status = 0;
    ocsp_res_start(ocsp_res_null_res);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_NULL_RES);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void null_cert_store() {
    int status = 0;
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    SSL_CTX_set_cert_store(ssl_ctx, NULL);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, &status), -1);
    CU_ASSERT_EQUAL(status, ERR_OCSP_GET_STORE);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

void null_status_pointer() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp_stapling(ssl, NULL), 1);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}
int stapling_callback_test_helper(SSL *ssl, void *arg) {
    return 1;
}

static int connect_to(const char* host, int port, int usedir) {
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if(usedir){
        char buf[1024];
        char dir[1024];
        getcwd(buf, 1024);
        sprintf(dir, "%s/test/certs/root/ca/certs", buf);
        SSL_CTX_load_verify_locations(ssl_ctx, NULL, dir); 
    }
    
    cbio = BIO_new_ssl_connect(ssl_ctx);
    BIO_get_ssl(cbio, &ssl);
    if(ssl == NULL) {
        CU_FAIL("Error creating ssl");
        return 0;
    }
    
    SSL_set_tlsext_host_name(ssl, host);

    // STAPLING
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ssl_ctx, stapling_callback_test_helper);

     // Create a TCP connection
    char conn_str[strlen(host) + 10];
    sprintf(conn_str, "%s:%d", host, port);
    BIO_set_conn_hostname(cbio, conn_str);

    // tcp connect & ssl connect
    if(BIO_do_connect(cbio) <= 0) {
        CU_FAIL("Error creating TCP connection to server");
        return 0;
    }
    if(BIO_do_handshake(cbio) <= 0) {
        CU_FAIL("Error performing SSL handshake");
        return 0;
    }
    return 1;
}

static void close_conn() {
    BIO_free_all(cbio);
}
