#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/asn1.h>

#include "crl.h"
#include "utils/http.h"
#include "lib.h"
#include "errs.h"

int validate_crl(SSL *ssl, ASN1_TIME **next_update) {
    int retval = 0;

    /* Get the X509 certificate of the site we want to check */
    X509 *cert = SSL_get_peer_certificate(ssl);
    if(!cert) {
        retval = ERR_CRL_NO_PEER_CERT;
        goto end;
    }

    /* Get cert store from the SSL_CTX */
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    if (!ssl_ctx) {
        retval = ERR_CRL_NO_SSL_CTX;
        goto end;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
    if (!store) {
        retval = ERR_CRL_NO_X509_STORE_OBTAINED;
        goto end;
    }

    /* Get cert chain */
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if(!chain) {
        retval = ERR_CRL_NO_PEER_CERT_CHAIN;
    }

end:
    if(retval) {
        X509CRC_log_error(retval);
        return retval;
    } else {
        /* No errors, so continue performing revocation check */
        return validate_crl_by_cert(cert, chain, store, next_update);
    }
}

int validate_crl_by_cert(X509 *cert, STACK_OF(X509) *chain, X509_STORE *store, ASN1_TIME **next_update) {
    int retval;
  
    /* Get the CRL */
    X509_CRL *crl = obtain_crl(cert);
    if(!crl) {
        retval = ERR_CRL_UNABLE_TO_RETRIEVE_CRL;
        goto end;
    }

    /* Verify CRL */
    int verify_result = verify_crl(cert, chain, crl, store);
    if(verify_result != 1) {
        retval = ERR_CRL_ERROR_CHECKING_CRL;
        goto end;
    }

    /* Get the next update time of the crl */
    if(next_update) {
        const ASN1_TIME* t = X509_CRL_get0_nextUpdate(crl);
        
        struct tm time;
        ASN1_TIME_to_tm(t, &time);
        *next_update = ASN1_TIME_set(NULL, mktime(&time));
    }

    /* Checks to see if the certificate is revoked or not */
    int revoked = is_revoked(cert, crl);
    if (revoked == 0 || revoked == 2) {
        retval = NOT_REVOKED;
    } else if (revoked == 1) {
        retval = REVOKED;
    } else {
        retval = ERR_CRL_ERROR_CHECKING_CRL;
    }

end:
    if(retval > 1) {
        X509CRC_log_error(retval);
    }
    X509_CRL_free(crl);
    return retval;
}

X509_CRL* obtain_crl(X509 *cert) {
    /* Obtain the URL of the CRL distribution point, if the cert has one */
    char *url = get_crl_url(cert);
    if (!url) {
        return NULL;
    }
    
    /* Now download the crl into memory */
    void *content = NULL;
    int len;
    if(http_get_by_url(url, &content, &len) <= 0) {
        return NULL;
    }
    free(url);

    /* Decode the .der file into a struct we can use */
    const unsigned char *content_ptr = (const unsigned char *)content;
    X509_CRL *crl = d2i_X509_CRL(NULL, &content_ptr, len);

    /* Free the downloaded content */
    free(content);

    return crl;
}

char* get_crl_url(X509 *cert) {
    char *url = NULL;

    /* Check if we got any distribution points (aka if there is a CRL for this certificate) */
    STACK_OF(DIST_POINT) *dist_points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (sk_DIST_POINT_num(dist_points) <= 0) {
        return NULL;
    }
    
    /* Grab the first distribution point and convert it to a string */
    DIST_POINT *dp = sk_DIST_POINT_value(dist_points, 0);
    DIST_POINT_NAME *dist_point = dp->distpoint;

    if (dist_point->type == 0) { // it was a generalized name
        GENERAL_NAME *gen_name = sk_GENERAL_NAME_value(dist_point->name.fullname, 0);
        ASN1_IA5STRING *asn1_str = gen_name->d.uniformResourceIdentifier;
        url = malloc(strlen((const char*)ASN1_STRING_get0_data(asn1_str)) + 1);
        strcpy(url, (const char*)ASN1_STRING_get0_data(asn1_str));
    } else if (dist_point->type == 1) { // it was a relative name
        // For some reason this requires different black magic
        STACK_OF(X509_NAME_ENTRY) *sk_relname = dist_point->name.relativename;
        X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, 0);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        url = malloc(strlen((const char*)ASN1_STRING_get0_data(d)) + 1);
        strcpy(url, (const char*)ASN1_STRING_get0_data(d));
    }

    /* Free the distribution points */
    CRL_DIST_POINTS_free(dist_points);

    return url;
}

int verify_crl(X509 *cert, STACK_OF(X509) *chain, X509_CRL *crl, X509_STORE *store) {
    /* Initial store context */
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, chain);
    X509_STORE_CTX_set_purpose(store_ctx, X509_PURPOSE_SSL_SERVER);

    /* Add crl and set for CRL checking */
    X509_STORE_add_crl(store, crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

    /* Verify */
    int verify_result = X509_verify_cert(store_ctx);

    /* Free resources */
    X509_STORE_CTX_cleanup(store_ctx);
    X509_STORE_CTX_free(store_ctx);

    return verify_result;
}

int is_revoked(X509 *cert, X509_CRL *crl) {
    if (!cert || !crl) {
        return -1;
    }
    
    /* get the serial number of the cert */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);

    /* Use X509_CRL_get0_by_serial() to attempt to find the cert */
    X509_REVOKED *ret = NULL;
    return X509_CRL_get0_by_serial(crl, &ret, serial);
}

int can_check_crl(X509 *cert) {
    /* Get list of crl distribution points */
    STACK_OF(DIST_POINT) *dist_points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    
    /* Check if there are any distribution points */
    int length = sk_DIST_POINT_num(dist_points);
    CRL_DIST_POINTS_free(dist_points);
    
    if (length <= 0) {
        return 0;
    } else {
        return 1;
    }
}
