/*
    Based on existing code given by sponsers
*/
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/tls1.h>
#include <openssl/ssl.h>

#include "lib.h"
#include "errs.h"
#include "ocsp_shared.h"

/* The values an OCSP stapling callback should return */
#define ERROR -1
#define REJECT_CERT 0
#define ACCEPT_CERT 1

/*
 * Setup before doing an SSL connection by calling SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp) then
 * SSL_CTX_set_tlsext_status_cb(ssl_ctx, validate_ocsp_stapling)
 * The actual check will be performed during the initial SSL connection
 * 
 * Return value is only for use by OpenSSL. To get actual status pass an int pointer into SSL_CTX_set_tlsext_status_arg()
 * Status will be 0 for good, 1 for revoked, or >1 for error
*/
int validate_ocsp_stapling(SSL *ssl, void *arg) {
    const unsigned char   *p = NULL;
    OCSP_RESPONSE         *rsp = NULL;
    OCSP_CERTID           *id = NULL;
    int                    len;
    X509                  *cert = NULL;
    X509                  *issuer = NULL;
    STACK_OF(X509)        *cert_chain = NULL;
    int                    status;
    
    /* Get stapled OCSP response */
    len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);
    if (!p) {
        status = ERR_STAPLING_NO_RESPONSE;
        goto end;
    }

    /* Parse OCSP response */
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        status = ERR_STAPLING_RESPONSE_PARSE_ERR;
        goto end;
    }

    OCSP_RESPONSE_print(X509CRC_log_info_bio(), rsp, 0);

    /* Get the cert chain */
    cert_chain = SSL_get_peer_cert_chain(ssl);
    if(!cert_chain) {
        status = ERR_OCSP_PEER_CHAIN_ERR;
        goto end;
    } else if (sk_num((_STACK*)cert_chain) < 2) {
        status = ERR_OCSP_NO_ISSUER_CERT;
        goto end;
    }

    /* The id of the certificate */
    cert = (X509*) sk_value((_STACK*)cert_chain, 0); //sk_value shouldn't require free later
    issuer = (X509*) sk_value((_STACK*)cert_chain, 1);
    id = OCSP_cert_to_id(NULL, cert, issuer);
    if (!id) {
        status = ERR_OCSP_CERT_TO_ID_FAIL;
        goto end;
    }

    /* Get the cert store in order to verify the response */
    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
    if (!store) {
        status = ERR_OCSP_GET_STORE;
        goto end;
    }

    /* Process OCSP response */
    status = X509CRC_read_ocsp_response(store, cert_chain, id, rsp, NULL);

end:
    /* Free any allocated resources */
    if(rsp) {
        OCSP_RESPONSE_free(rsp);
    }
    if(id) {
        OCSP_CERTID_free(id);
    }

    /* Set the passbacked status value */
    if (arg) {
        *((int *)arg) = status;
    }

    /* Log any errors */
    if(status > 1) {
        X509CRC_log_error(status);
    }

    /* Return the revocation status */
    if(status == 0) {
        return ACCEPT_CERT;
    } else if(status == 1) {
        return REJECT_CERT;
    } else {
        return ERROR;
    }
}
