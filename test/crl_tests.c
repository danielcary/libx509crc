#include <CUnit/Basic.h>

#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/asn1.h>

#include "../src/lib/crl.h"
#include "../src/lib/lib.h"
#include "tests.h"
#include "certs.h"
#include "servers.h"
#include "../src/lib/errs.h"


/* crl.c suite methods */
static int crl_init() {
    setup();
    X509CRC_set_err_BIO(NULL);
    return 0;
}

static BIO *cbio = NULL;
static SSL *ssl = NULL;
static SSL_CTX *ssl_ctx = NULL;

static void connect_to(const char* host, int port, bool usedir) {
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
    }    
    
    SSL_set_tlsext_host_name(ssl, host);
    // (STAPLING)

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

void crl_valid() {
    servers_start_crl();
    servers_start_main(49202);
    servers_start_no_ocsp(49203);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), 0);
    close_conn();

    // start up crl server again
    servers_join_crl();
    servers_start_crl();

    connect_to("localhost", 49203, 1);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), 0);
    close_conn();

    servers_join_crl();
    servers_join_main();
    servers_join_no_ocsp();
}

void crl_revoked() {
    revoke_main_server();
    gen_crl();
    servers_start_crl();
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), 1);
    close_conn();

    servers_join_crl();
    servers_join_main();
    setup(); // clean up our revoked cert
}

void crl_can_check() {
    X509* cert;

    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    cert = SSL_get_peer_certificate(ssl);
    CU_ASSERT_TRUE(can_check_crl(cert));
    close_conn();
    
    servers_join_main();

    // need to test a server without crl
    servers_start_no_crl(49202);

    connect_to("localhost", 49202, 1);
    cert = SSL_get_peer_certificate(ssl);
    CU_ASSERT_FALSE(can_check_crl(cert));
    close_conn();

    servers_join_no_crl();   
}

static void cant_verify()
{
    servers_start_crl();
    servers_start_main(49202);

    connect_to("localhost", 49202, false);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), ERR_CRL_ERROR_CHECKING_CRL);
    close_conn();

    servers_join_crl();
    servers_join_main();
}

static void crl_server_down()
{
    servers_start_main(49202);

    connect_to("localhost", 49202, true);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), ERR_CRL_UNABLE_TO_RETRIEVE_CRL);
    close_conn();
    
    servers_join_main();
}

static void no_store()
{
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);
    SSL_CTX_set_cert_store(SSL_get_SSL_CTX(ssl), NULL);
    CU_ASSERT_EQUAL(validate_crl(ssl, NULL), ERR_CRL_NO_X509_STORE_OBTAINED);
    close_conn();
    
    servers_join_main();
}

static void set_next_update() 
{
    servers_start_crl();
    servers_start_main(49202);

    connect_to("localhost", 49202, 1);

    ASN1_TIME* time = NULL;
    CU_ASSERT_EQUAL(validate_crl(ssl, &time), 0);
    CU_ASSERT_PTR_NOT_NULL(time);

    // the next update time should be after
    // now, since crl was just generated
    ASN1_TIME* now = X509_gmtime_adj(NULL, 0);
    CU_ASSERT_EQUAL(ASN1_TIME_compare(time, now), 1);

    close_conn();
    
    servers_join_main();
    servers_join_crl();
}

/* Test is_revoked() from crl.c */
static void is_revoked_1 () {
    int serial1 = 1;
    int serial2 = 2;
    long notAfter = 86400L;
    // Create 2 X509 certificates and 1 CRL via OpenSSL
    X509 *cert1 = X509_new();
    X509 *cert2 = X509_new();
    X509_CRL *crl = X509_CRL_new();
    X509_REVOKED *rev1, *rev2;
    
    // Assign serial numbers and finish setting these up
    ASN1_INTEGER_set(X509_get_serialNumber(cert1), serial1);
    X509_gmtime_adj(X509_get_notBefore(cert1), 0);
    X509_gmtime_adj(X509_get_notAfter(cert1), notAfter);
    
    ASN1_INTEGER_set(X509_get_serialNumber(cert2), serial2);
    X509_gmtime_adj(X509_get_notBefore(cert2), 0);
    X509_gmtime_adj(X509_get_notAfter(cert2), notAfter);
    
    // Verify that neither certificate is listed as revoked by the CRL
    // OpenSSL used to verify, before testing crl.c.is_revoked()
    CU_ASSERT_EQUAL(X509_CRL_get0_by_cert(crl, NULL, cert1), 0);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_cert(crl, NULL, cert2), 0);
    
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert1)), 0);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert2)), 0);
    // Now test that is_revoked() correctly shows they are not listed
    // as revoked by the CRL
    CU_ASSERT_EQUAL(is_revoked(cert1, crl), 0);
    CU_ASSERT_EQUAL(is_revoked(cert2, crl), 0);
    
    // Revoke one of the certificates and add it to the CRL
    rev1 = X509_REVOKED_new();
    ASN1_INTEGER *cert1_ser = X509_get_serialNumber(cert1);
    X509_REVOKED_set_serialNumber(rev1, cert1_ser);
    X509_CRL_add0_revoked(crl, rev1);
    
    // Verify that the certificate not revoked is still not listed
    // cert1 was added to CRL, so make sure cert2 is not listed as revoked
    CU_ASSERT_EQUAL(X509_CRL_get0_by_cert(crl, NULL, cert2), 0);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert2)), 0);
    // Now verify it with is_revoked()
    CU_ASSERT_EQUAL(is_revoked(cert2, crl), 0);
    
    // Verify that the revoked certificate is found as revoked in the CRL
    CU_ASSERT_EQUAL(X509_CRL_get0_by_cert(crl, NULL, cert1), 1);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert1)), 1);
    // Now verify it with is_revoked()
    CU_ASSERT_EQUAL(is_revoked(cert1, crl), 1);
    
    // Revoke the other certificate and then verify both are listed as revoked
    rev2 = X509_REVOKED_new();
    ASN1_INTEGER *cert2_ser = X509_get_serialNumber(cert2);
    X509_REVOKED_set_serialNumber(rev2, cert2_ser);
    X509_CRL_add0_revoked(crl, rev2);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert2)), 1);
    CU_ASSERT_EQUAL(X509_CRL_get0_by_serial(crl, NULL, X509_get_serialNumber(cert1)), 1);
    
    CU_ASSERT_EQUAL(is_revoked(cert1, crl), 1);
    CU_ASSERT_EQUAL(is_revoked(cert2, crl), 1);
}

/*
 * Error checking for is_revoked()
 * Passes in in valid arguments and checks the error codes are correct
 */
static void is_revoked_2() {
    X509 *cert1 = X509_new();
    X509_CRL *crl = X509_CRL_new();
    // Test that it correctly returns -1 when a NULL or initialized
    // value is passed
    CU_ASSERT_EQUAL(is_revoked(NULL, NULL), -1);
    CU_ASSERT_EQUAL(is_revoked(cert1, NULL), -1);
    CU_ASSERT_EQUAL(is_revoked(NULL, crl), -1);
}

/*
void get_crl_url_1() {
    // Create a new X509 certificate and several Distribution points
    X509 *cert1 = X509_new();
    X509 *cert2 = X509_new();
    
    int nid = NID_crl_distribution_points;
    unsigned char *uri_1 = "http://crl.quovadisglobal.com/hydsslg2.crl";
    unsigned char *uri_2 = "http://pki.google.com/GIAG2.crl";
    
    ASN1_STRING x;
    ASN1_STRING_set(&x, uri_1, strlen(uri_1));
    X509_EXTENSION *ex = X509_EXTENSION_create_by_NID(NULL, nid, 0, &x);//(NULL, NULL, nid, uri_1);
    printf("%d\n", X509_add_ext(cert1, ex, 0));
    X509_EXTENSION_free(ex);
    
    // Test that get_crl_url correctly finds the distribution point URI
    char url[1024];
    bzero(url, 1024);
    CU_ASSERT_TRUE(get_crl_url(cert1, url));
    printf("%s\n", url);
    CU_ASSERT_STRING_EQUAL(url, uri_1);
    
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, uri_2);
    X509_add_ext(cert1, ex, -1);
    X509_EXTENSION_free(ex);
    
    // get_crl_url should still return the same URI since it returns the first
    // one found
    get_crl_url(cert1, url);
    CU_ASSERT_STRING_EQUAL(url, uri_1);
    

    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, uri_1);
    X509_add_ext(cert2, ex, -1);
    X509_EXTENSION_free(ex);
    
    
    
    
    
    // Add a new dist point to a different cert, with a different name type
    
    
    // Test that get_crl_url correctly finds the first dist point added
}
*/

int add_crl_suite() {
 
    // create suite
    CU_pSuite crl_suite = CU_add_suite("crl.c tests", crl_init, NULL);

    if(!crl_suite) {
        return 1;
    }

     /* Add tests */
    return 
        !CU_add_test(crl_suite, "Testing is_revoked()", is_revoked_1) ||
        !CU_add_test(crl_suite, "Testing is_revoked()", is_revoked_2) ||
        //!CU_add_test(crlSuite, "Testing get_crl_url()", get_crl_url_1) ||
        !CU_add_test(crl_suite, "Valid hosts", crl_valid) ||
        !CU_add_test(crl_suite, "Revoked hosts", crl_revoked) || 
        !CU_add_test(crl_suite, "verify failed (no load certs)", cant_verify) || 
        !CU_add_test(crl_suite, "crl server down (cant download crl)", crl_server_down) || 
        !CU_add_test(crl_suite, "cant get ssl ctx store", no_store) || 
        !CU_add_test(crl_suite, "Can preform crl check", crl_can_check) ||
        !CU_add_test(crl_suite, "Set time", set_next_update);
}
