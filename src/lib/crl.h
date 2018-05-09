#pragma once

#include <openssl/ssl.h>
#include <openssl/x509.h>

/**
 * Downloads and returns a pointer to the CRL that governs cert
 * 
 * @param cert the certificate to get CRL for
 * 
 * @returns the CRL of the certificate. NULL if one cannot be obtained.
 */
X509_CRL* obtain_crl(X509 *cert);

/**
 * Takes in an X509 certificate and returns a char* of the URL for the first
 * listed CRL Distribution Point for said X509 certificate. 
 * 
 * @param cert the certificate to attempt to a distribution point from.
 * 
 * @returns a char* string of the URL of the distribution point. Must be freed.
 *      NULL if unable to obtain an URL.
 */
char* get_crl_url(X509 *cert);

/**
 * Verifies that the CRL is valid and legitimate. 
 * 
 * @returns 1 if it is correctly verified, returns 0 otherwise.
 */
int verify_crl(X509 *cert, STACK_OF(X509)* chain, X509_CRL *crl, X509_STORE *store);

/**
 * X509_CRL_get0_by_serial() and X509_CRL_get0_by_cert() return 0 for failure, 1 on success except if the revoked entry has the reason removeFromCRL (8), in which case 2 is returned.
 * 
 * @returns 0 if the certificate was not listed as revoked in the CRL,
 * 2 if removedFromCRL
 * 1 if it was listed as revoked, -1 if there was an error.
 * 
 */
int is_revoked(X509 *cert, X509_CRL *crl);
