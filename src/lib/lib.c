#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/asn1.h>

#include "lib.h"
#include "errs.h"

static BIO *info_bio = NULL;
static BIO *err_bio = NULL;

void X509CRC_set_info_BIO(BIO* bio) {
    info_bio = bio;
}

void X509CRC_set_err_BIO(BIO* bio) {
    err_bio = bio;
}

static void print_timestamp(BIO* bio) {
    /* Get current time */
    time_t t = time(NULL);
    ASN1_TIME* tm = ASN1_TIME_set(NULL, t);

    /* Print out time stamp */
    BIO_printf(bio, "[");
    ASN1_TIME_print(bio, tm);
    BIO_printf(bio, "]");

    ASN1_STRING_free(tm);
}

BIO* X509CRC_log_info_bio() {
    if(!info_bio) {
        return NULL;
    }

    print_timestamp(info_bio);
    BIO_printf(info_bio, " INFO: ");

    return info_bio;
}

void X509CRC_log_error(int err) {
    if(!err_bio) {
        return;
    }

    print_timestamp(err_bio);
    BIO_printf(err_bio, " ERROR: %s\n", X509CRC_err_to_str(err));
}

const char* X509CRC_err_to_str(int err) {
    if(err >= 100 && err < 200) {
        // OCSP errors
        switch(err) {
            case ERR_OCSP_NO_PEER_CERT:
                return "OCSP: No peer certificate found";
            case ERR_OCSP_MUST_STAPLE:
                return "OCSP: Must Staple flag found, cannot perform check";
            case ERR_OCSP_PEER_CHAIN_ERR:
                return "OCSP: Unable to obtain a peer certificate chain";
            case ERR_OCSP_NO_ISSUER_CERT:
                return "OCSP: No issuer certificate found";
            case ERR_OCSP_CERT_TO_ID_FAIL:
                return "OCSP: cert_to_id() failed";
            case ERR_OCSP_NO_OCSP_URI:
                return "OCSP: No OCSP respond URI address found";
            case ERR_OCSP_NO_CONNECT:
                return "OCSP: Unable to connect to OCSP responder";
            case ERR_OCSP_NO_REQUEST_CTX:
                return "OCSP: Unable to create OCSP request context";
            case ERR_OCSP_NO_RESPONSE:
                return "OCSP: No OCSP response from OCSP responder";
            case ERR_OCSP_UNSUCCESSFUL_RES:
                return "OCSP: Unsuccessful OCSP Response";
            case ERR_OCSP_NULL_RES:
                return "OCSP: Null OCSP response";
            case ERR_OCSP_GET_STORE:
                return "OCSP: SSL_CTX_get_cert_store() failed";
            case ERR_OCSP_BASIC_VERIFY:
                return "OCSP: basic_verify() failed";
            case ERR_OCSP_CHECK_VALIDITY:
                return "OCSP: check_validity() failed, the OCSP response is expired";
            case ERR_OCSP_UNKNOWN_STATUS:
                return "OCSP: Certificate status is UNKNOWN";
        }
    } else if(err >= 200 && err < 300) {
        // STAPLING errors
        switch(err) {
            case ERR_STAPLING_NO_RESPONSE:
                return "OCSP Stapling: no response sent";
            case ERR_STAPLING_RESPONSE_PARSE_ERR:
                return "OCSP Stapling: response parse error";
           
        }
    } else if(err >= 300 && err < 400) {
        // CRL errors
        switch(err) {
            case ERR_CRL_UNABLE_TO_RETRIEVE_CRL:
                return "CRL: Unable to get CRL or bad CRL";
            case ERR_CRL_DID_NOT_VERIFY:
                return "CRL: Couldn't verify CRL";
            case ERR_CRL_ERROR_CHECKING_CRL:
                return "CRL: There was an error when trying to check the CRL for the certificate.";
            case ERR_CRL_NO_X509_STORE_OBTAINED:
                return "CRL: Couldn't obtain an X509_STORE";
            case ERR_CRL_NO_DIST_POINTS:
                return "CRL: No CRL Distribution points listed in cert";
            case ERR_CRL_NO_SSL_CTX:
                return "CRL: Unable to get SSL_CTX from SSL context";
            case ERR_CRL_NO_PEER_CERT_CHAIN:
                return "CRL: Unable to get peer cert chain from SSL context";
            case ERR_CRL_NO_PEER_CERT:
                return "CRL: Unable to get peer cert from SSL context";
        }
    } else if(err >= 400) {
        switch(err) {
            case ERR_TRANSPARENCY_CANT_READ_CT_LOGS:
                return "Could not read in the CT logs to the CTLOG_STORE";
            case ERR_TRANSPARENCY_NO_SCT_OBTAINED:
                return "No SCTs were obtained";
        }
    }

    return NULL;
}
