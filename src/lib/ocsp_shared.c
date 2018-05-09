#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "ocsp_shared.h"
#include "lib.h"
#include "errs.h"

int X509CRC_read_ocsp_response(X509_STORE *store, STACK_OF(X509)* cert_chain, OCSP_CERTID* id, OCSP_RESPONSE* rsp, ASN1_TIME** next_update) {
    int retval = -1;
    OCSP_BASICRESP* cert_res = NULL;

    /* Get response status */
    int status = OCSP_response_status(rsp);
    if(status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        retval = ERR_OCSP_UNSUCCESSFUL_RES;
        goto end;
    }

    X509CRC_log_info("OCSP response successful! (%d: %s)\n", status, OCSP_response_status_str(status));

    /* Get the basic response from the whole ocsp response message */
    cert_res = OCSP_response_get1_basic(rsp);
    if(!cert_res) {
        retval = ERR_OCSP_NULL_RES;
        goto end;
    }

    /* Verfiy the signature of response */
    if (OCSP_basic_verify(cert_res, cert_chain, store, 0) != 1) {
        retval = ERR_OCSP_BASIC_VERIFY;
        goto end;
    }

    /* Get certicate status from response */
    int reason;
    ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
    OCSP_resp_find_status(cert_res, id, &status, &reason, &revtime, &thisupd, &nextupd);
    
    /* Check that response is not expired */
    if (OCSP_check_validity(thisupd, nextupd, 300, -1) != 1) {
        retval = ERR_OCSP_CHECK_VALIDITY;
        goto end;
    }

    if(next_update && nextupd) {
        struct tm time;
        ASN1_TIME_to_tm(nextupd, &time);
        *next_update = ASN1_TIME_set(NULL, mktime(&time));
    }

    /* Check status */
    if(status == V_OCSP_CERTSTATUS_GOOD) {
        retval = 0;
    } else if(status == V_OCSP_CERTSTATUS_REVOKED) {
        retval = 1;
    } else {
        retval = ERR_OCSP_UNKNOWN_STATUS;
    }

end:
    OCSP_BASICRESP_free(cert_res);

    return retval;
}

int must_staple(X509 *cert) 
{
    // Check if Must Staple extension is present
    int crit;
    X509_get_ext_d2i(cert, NID_tlsfeature, &crit, NULL);

    if(crit == 0) {
        return 1;
    } else {
        return 0;
    }
}

int can_check_ocsp(X509 *cert) 
{
    // If the must staple flag is set, don't query responder directly
    if(must_staple(cert)) {
        return 0;
    }

    // check if an OCSP responder address is listed in cert
    STACK_OF(OPENSSL_STRING) *list = X509_get1_ocsp(cert);
    int length = sk_num((const OPENSSL_STACK*)list);
    X509_email_free(list);

    if(length <= 0) {
        return 0;
    } else {
        return 1;
    }
}
