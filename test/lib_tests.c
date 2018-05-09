#include <CUnit/Basic.h>

#include "tests.h"

#include "../src/lib/lib.h"
#include "../src/lib/errs.h"

static int init();
static int clean();

static void err_codes_exist_test();

int add_lib_suite() {
    // create suite
    CU_pSuite suite = CU_add_suite("lib/lib.c tests", init, clean);

     if(!suite) {
        return 1;
     }

     /* Add tests */
     return 
        !CU_add_test(suite, "lib error code strings exist", err_codes_exist_test);
}


static int init() {
    return 0;
}

static int clean() {
    return 0;
}

void err_codes_exist_test() {
    const char *str = NULL;

    /* OCSP 100s */
    str = X509CRC_err_to_str(ERR_OCSP_NO_PEER_CERT);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_MUST_STAPLE);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_PEER_CHAIN_ERR);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_CERT_TO_ID_FAIL);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NO_ISSUER_CERT);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NO_OCSP_URI);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NO_CONNECT);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NO_REQUEST_CTX);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NO_RESPONSE);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_UNSUCCESSFUL_RES);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_NULL_RES);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_GET_STORE);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_BASIC_VERIFY);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_CHECK_VALIDITY);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_OCSP_UNKNOWN_STATUS);
    CU_ASSERT_PTR_NOT_NULL(str);

    /* Stapling */
    str = X509CRC_err_to_str(ERR_STAPLING_NO_RESPONSE);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_STAPLING_RESPONSE_PARSE_ERR);
    CU_ASSERT_PTR_NOT_NULL(str);

    /* CRL */
    str = X509CRC_err_to_str(ERR_CRL_UNABLE_TO_RETRIEVE_CRL);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_DID_NOT_VERIFY);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_ERROR_CHECKING_CRL);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_NO_DIST_POINTS);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_NO_SSL_CTX);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_NO_X509_STORE_OBTAINED);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_NO_PEER_CERT_CHAIN);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_CRL_NO_PEER_CERT);
    CU_ASSERT_PTR_NOT_NULL(str);

    /* transparency */
    str = X509CRC_err_to_str(ERR_TRANSPARENCY_CANT_READ_CT_LOGS);
    CU_ASSERT_PTR_NOT_NULL(str);

    str = X509CRC_err_to_str(ERR_TRANSPARENCY_NO_SCT_OBTAINED);
    CU_ASSERT_PTR_NOT_NULL(str);
}