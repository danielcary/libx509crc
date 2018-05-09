#include <CUnit/Basic.h>
#include <string.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

#include "tests.h"

int main () {
    signal(SIGPIPE, SIG_IGN);

    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }

    /* Setup suites */
    if (    add_lib_suite()
            || add_http_suite()
            || add_crl_suite() 
            || add_ocsp_suite()
            || add_ocsp_stapling_suite()
            || add_transparency_suite()
            || add_blackbox_suite()) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_basic_show_failures(CU_get_failure_list());
    printf("\n\n");


    CU_cleanup_registry();
    return CU_get_error();
}
