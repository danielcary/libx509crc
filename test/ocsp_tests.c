#include <CUnit/Basic.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "tests.h"
#include "certs.h"
#include "ocsp_res.h"
#include "servers.h"
#include "../src/lib/lib.h"
#include "../src/lib/errs.h"


static int ocsp_init();

static void ocsp_valid();
static void ocsp_revoked();
static void ocsp_can_check();
static void ocsp_responder_down();
static void ocsp_verify();
static void ocsp_no_response();
static void ocsp_no_issuer();
static void ocsp_no_sslctx();
static void ocsp_cert_status_unknown();
static void ocsp_bad_validity_time();
static void ocsp_bad_res();
static void ocsp_null_res();
static void https_ocsp_responder();
static void set_next_update();

int add_ocsp_suite() {
    // create suite
    CU_pSuite suite = CU_add_suite("lib/ocsp.c tests", ocsp_init, NULL);

    if(!suite) {
        return 1;
    }

     /* Add tests */
    return  !CU_add_test(suite, "Valid hosts", ocsp_valid)
            || !CU_add_test(suite, "Revoked hosts", ocsp_revoked)
            || !CU_add_test(suite, "Can perform OCSP check", ocsp_can_check)
            || !CU_add_test(suite, "OCSP verfiy", ocsp_verify)
            || !CU_add_test(suite, "OCSP no issuer", ocsp_no_issuer)
            || !CU_add_test(suite, "OCSP no ssl ctx", ocsp_no_sslctx)
            || !CU_add_test(suite, "OCSP responder down", ocsp_responder_down)
            || !CU_add_test(suite, "OCSP unknown status response from responder", ocsp_cert_status_unknown)
            || !CU_add_test(suite, "OCSP no response from responder", ocsp_no_response)
            || !CU_add_test(suite, "OCSP time invalid response from responder", ocsp_bad_validity_time)
            || !CU_add_test(suite, "OCSP bad response from responder", ocsp_bad_res)
            || !CU_add_test(suite, "OCSP null response from responder", ocsp_null_res)
            || !CU_add_test(suite, "OCSP HTTPS OCSP responder", https_ocsp_responder)
            || !CU_add_test(suite, "OCSP Response time", set_next_update);
}

static int ocsp_init() {
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    X509CRC_set_err_BIO(NULL);
    setup();

    return 0;
}

static BIO *cbio = NULL;
static SSL *ssl = NULL;
static SSL_CTX *ssl_ctx = NULL;


static void connect_to(const char* host, int port, int usedir) {
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());

    if(usedir){
        char dir[PATH_MAX];
        char* wd = get_current_dir_name();
        sprintf(dir, "%s/test/certs/root/ca/certs", wd);
        SSL_CTX_load_verify_locations(ssl_ctx, NULL, dir); 
    }

    cbio = BIO_new_ssl_connect(ssl_ctx);
    BIO_get_ssl(cbio, &ssl);
    if(ssl == NULL) {
        CU_FAIL("Error creating ssl");
    }    
    
    SSL_set_tlsext_host_name(ssl, host);

     // Create a TCP connection
    char conn_str[strlen(host) + 10];
    sprintf(conn_str, "%s:%d", host, port);
    BIO_set_conn_hostname(cbio, conn_str);
    
    // tcp connect & ssl connect
    if(BIO_do_connect(cbio) <= 0) {
        CU_FAIL("Error creating TCP connection to server");
    } else if(BIO_do_handshake(cbio) <= 0) {
        CU_FAIL("Error performing SSL handshake");
    }
}

static void close_conn() {
    BIO_free_all(cbio);
}

static void ocsp_valid() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), 0);
    close_conn();

    ocsp_res_join();
    servers_join_main();

    // "revoke" the server
    ocsp_res_start(ocsp_res_revoked);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), 1);
    close_conn();

    ocsp_res_join();
    servers_join_main();
}

static void ocsp_revoked() {
    ocsp_res_start(ocsp_res_revoked);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), 1);

    close_conn();
    ocsp_res_join();
    servers_join_main();
}

static void https_ocsp_responder() {
    ocsp_res_ssl_start(ocsp_res_valid);
    servers_start_https_dists(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), 0);
    close_conn();

    ocsp_res_join();
    servers_join_https_dists();
}

static void set_next_update()
{
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);

    ASN1_TIME* time = NULL;
    CU_ASSERT_EQUAL(validate_ocsp(ssl, &time), 0);
    CU_ASSERT_PTR_NOT_NULL(time);

    // the next update time should be after
    ASN1_TIME* now = X509_gmtime_adj(NULL, 0);
    CU_ASSERT_EQUAL(ASN1_TIME_compare(time, now), 1);

    close_conn();
    
    servers_join_main();
    ocsp_res_join();
}

static void ocsp_responder_down() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), 0);
    close_conn();

    // wait for the servers to stop
    ocsp_res_join();
    servers_join_main();

    // run without ocsp server
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_NO_CONNECT);
    close_conn();

    servers_join_main();
}

static void ocsp_can_check() {
    X509* cert;

    servers_start_main(49202);
    servers_start_must_staple(49203);
    servers_start_no_ocsp(49204);

    connect_to("localhost", 49202, 1);
    cert = SSL_get_peer_certificate(ssl);
    CU_ASSERT_TRUE(can_check_ocsp(cert));
    close_conn();


    // check must staple server
    connect_to("localhost", 49203, 1);
    cert = SSL_get_peer_certificate(ssl);
    CU_ASSERT_FALSE(can_check_ocsp(cert));
    close_conn();


    // try one with only crl, no ocsp support
    connect_to("localhost", 49204, 1);
    cert = SSL_get_peer_certificate(ssl);
    CU_ASSERT_FALSE(can_check_ocsp(cert));
    close_conn();

    servers_join_main();
    servers_join_must_staple();
    servers_join_no_ocsp();
}

static void ocsp_verify() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    // dont set path for ssl
    connect_to("localhost", 49202, 0);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_BASIC_VERIFY);
    close_conn();

    servers_join_main();
    ocsp_res_join();
}

static void ocsp_no_response() 
{
    ocsp_res_start(ocsp_res_no_res);
    servers_start_main(49202);
    
    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_NO_RESPONSE);
    close_conn();

    servers_join_main();
    ocsp_res_join();
}

static void ocsp_no_issuer() {
    servers_start_main_no_fullchain(49202);

    // attempt to connect
    connect_to("localhost", 49202, 0);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_NO_ISSUER_CERT);
    close_conn();

    servers_join_main();
}

static void ocsp_no_sslctx() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    SSL_CTX_set_cert_store(SSL_get_SSL_CTX(ssl), NULL);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_GET_STORE);
    close_conn();
    
    servers_join_main();
    ocsp_res_join();
}

static void ocsp_cert_status_unknown() {
    ocsp_res_start(ocsp_res_unknown);
    servers_start_main(49202);
   
    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_UNKNOWN_STATUS);
    close_conn();

    servers_join_main();
    ocsp_res_join();
}


static void ocsp_bad_validity_time()
{
    ocsp_res_start(ocsp_res_bad_time);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_CHECK_VALIDITY);
    close_conn();

    servers_join_main();
    ocsp_res_join();
}

static void ocsp_bad_res()
{
    ocsp_res_start(ocsp_res_internal_err);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_UNSUCCESSFUL_RES);
    close_conn();
    
    servers_join_main();
    ocsp_res_join(); 
}

static void ocsp_null_res()
{
    ocsp_res_start(ocsp_res_null_res);
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_ocsp(ssl, NULL), ERR_OCSP_NULL_RES);
    close_conn();

    servers_join_main();
    ocsp_res_join();
}
