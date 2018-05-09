#include <CUnit/Basic.h>

#include <openssl/ssl.h>

#include "tests.h"

#include "../src/lib/transparency.h"

static int init();
static int clean();

static void test_val_num_SCT();

int add_transparency_suite() {
    // create suite
    CU_pSuite suite = CU_add_suite("lib/transparency.c tests", init, clean);

    if(!suite) {
        return 1;
    }

     /* Add tests */
    return 
        !CU_add_test(suite, "transparency val_num_SCT", test_val_num_SCT);
}


static int init() {
    return 0;
}

static int clean() {
    return 0;
}


static void test_val_num_SCT() {
    
    X509* cert = NULL;

    // set times
    time_t now = time(NULL);
    ASN1_TIME* cur_time = ASN1_TIME_set(NULL, now);
    ASN1_TIME* _1month_time = ASN1_TIME_adj(NULL, now, 30, 0);
    ASN1_TIME* _15month_time = ASN1_TIME_adj(NULL, now, 30 * 15 + 2, 0);
    ASN1_TIME* _27month_time = ASN1_TIME_adj(NULL, now, 30 * 27 + 2, 0);
    ASN1_TIME* _39month_time = ASN1_TIME_adj(NULL, now, 30 * 39 + 2, 0);

    // test with no time sets
    cert = X509_new();
    CU_ASSERT_EQUAL(val_num_SCT(cert, 0), -1);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 1), -1); 
    
    // test with only one time set
    X509_set1_notBefore(cert, cur_time);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 0), -1); // try 2 different vals for sct
    CU_ASSERT_EQUAL(val_num_SCT(cert, 1), -1); 
    X509_set1_notAfter(cert, cur_time);

    // test with both times set
    CU_ASSERT_EQUAL(val_num_SCT(cert, 0), 0);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 0), 0); 

    X509_free(cert);

    //////////// try < 15 month cert
    cert = X509_new();
    X509_set1_notAfter(cert, _1month_time);
    X509_set1_notBefore(cert, cur_time);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 0), 0);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 2), 1); 
    CU_ASSERT_EQUAL(val_num_SCT(cert, 3), 1);
    // also test out when the number of scts is >5 while were at it
    CU_ASSERT_EQUAL(val_num_SCT(cert, 5), 1);
    X509_free(cert);
    
    /// try >15 <27 
    cert = X509_new();
    X509_set1_notAfter(cert, _15month_time);
    X509_set1_notBefore(cert, cur_time);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 2), 0); 
    CU_ASSERT_EQUAL(val_num_SCT(cert, 3), 1);
    X509_free(cert);
    
    /// try >27 <39 
    cert = X509_new();
    X509_set1_notAfter(cert, _27month_time);
    X509_set1_notBefore(cert, cur_time);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 3), 0); 
    CU_ASSERT_EQUAL(val_num_SCT(cert, 4), 1);
    X509_free(cert);
    
    /// try >27 <39 
    cert = X509_new();
    X509_set1_notAfter(cert, _39month_time);
    X509_set1_notBefore(cert, cur_time);
    CU_ASSERT_EQUAL(val_num_SCT(cert, 4), 0); 
    CU_ASSERT_EQUAL(val_num_SCT(cert, 5), 1);

    X509_free(cert);
    ASN1_TIME_free(cur_time);
}