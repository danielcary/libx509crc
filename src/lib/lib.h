#pragma once

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

/**
 * Sets the output BIO for the library to use for logging info
 * messages. Extra information is written to the BIO when revocation
 * checks are performed. If not set, no logs are written.
 * 
 * @param bio the output BIO for the library to use,
 *              may be NULL if no output is desired
 */
void X509CRC_set_info_BIO(BIO* bio);

/**
 * Sets the output BIO for the library to use for logging error
 * messages. Any error messages are written to the BIO when revocation
 * checks are performed. If not set, no logs are written.
 * 
 * @param bio the output BIO for the library to use,
 *              may be NULL if no output is desired
 */
void X509CRC_set_err_BIO(BIO* bio);

/**
 * Returns the message string corresponding to a libx509crc error code.
 * 
 * @param err the error code to lookup
 * @return the corresponding message string. NULL if the error code
 *      cannot be matched. 
 */
const char* X509CRC_err_to_str(int err);

/**
 * \brief Internal library function used to for info log messages.
 * 
 * Prints out a timestamp to the info BIO (if set) then returns
 * the info BIO so the caller and print a custom message. Usually
 * used for OpenSSL calls like OCSP_RESPONSE_print() which require
 * a BIO.
 * 
 * @returns the info BIO to write to. Should not be closed.
 */
BIO* X509CRC_log_info_bio();

/**
 * \brief Internal library function used to for info log messages.
 * 
 * Prints out an info log message with a timestamp to the info BIO 
 * based on the passed format string and arguments.
 * 
 * @param fmt the format string to use
 * @param args the values to be printed
 */
#define X509CRC_log_info(fmt, args...) BIO_printf(X509CRC_log_info_bio(), fmt, args)

/**
 * \brief Internal library function used to for error log messages.
 * 
 * Prints out an error log message with a timestamp to the error BIO 
 * with an error message. 
 * 
 * @param err the x509crc error code (check errs.h)
 * 
 * @see X509CRC_err_to_str
 */
void X509CRC_log_error(int err);

/**
 * Performs an OCSP revocation check on the SSL connection.
 * The Must Staple extension must not be set on the certificate.
 * 
 * @param ssl the SSL context to perform the revocation check on
 * @param next_update a pointer to the next update time given in the OCSP 
 *      response. If not desired, NULL may be passed. Otherwise, the
 *      returned ASN1_TIME pointer must be freed.
 * 
 * @returns 0 on passed, 1 if revoked, > 1 is the error code (check errs.h)
 */
int validate_ocsp(SSL *ssl, ASN1_TIME** next_update);

/**
 * Performs an OCSP revocation check based on an X509 certification
 * and chain. The Must Staple extension must not be set on the certificate.
 * 
 * @param cert the certificate to perform the revocation check on
 * @param chain the certificate chain to use. The first element is expected
 *      to be the specified cert and the second is expected to be the issuer
 * @param store the X509_STORE to use to verify the OCSP response
 * @param next_update a pointer to the next update time given in the OCSP 
 *      response. If not desired, NULL may be passed. Otherwise, the
 *      returned ASN1_TIME pointer must be freed.
 * 
 * @returns 0 on passed, 1 if revoked, > 1 is the error code (check errs.h)
 */
int validate_ocsp_by_cert(X509 *cert, STACK_OF(X509) *chain, X509_STORE *store, ASN1_TIME** next_update);

/**
 * Callback to perform an OCSP Stapling revocation check on the SSL
 * connection.
 * 
 * @param ssl the SSL context to perform the revocation check on
 * @param arg part of the callback signature, used to pass back any error
 *      code or the revocation status. NULL may be passed in if getting
 *      back the value is not desired.
 * 
 * @returns 1 on passed, 0 if revoked, -1 on error. Check the value of
 *      arg to get the revocation status or error code (check errs.h).
 */
int validate_ocsp_stapling(SSL *ssl, void *arg);

/**
 * Performs a CRL revocation check on the SSL connection.
 * 
 * @param ssl the SSL context to perform the revocation check on
 * @param next_update a pointer to the next update time listed in the CRL.
 *      If not desired, NULL may be passed. Otherwise, the returned
 *      ASN1_TIME pointer must be freed.
 * 
 * @returns 0 on passed, 1 if revoked, > 1 on error (check errs.h)
 */
int validate_crl(SSL *ssl, ASN1_TIME** next_update);

/**
 * Performs a CRL revocation check based on an X509 certification
 * and chain.
 * 
 * @param cert the certificate to perform the revocation check on
 * @param chain the certificate chain to use. The first element is expected
 *      to be the specified cert and the second is expected to be the issuer
 * @param store the X509_STORE to use to verify the CRL
 * @param next_update a pointer to the next update time listed in the CRL.
 *      If not desired, NULL may be passed. Otherwise, the returned
 *      ASN1_TIME pointer must be freed.
 * 
 * @returns 0 on passed, 1 if revoked, >1 on error (check errs.h)
 */
int validate_crl_by_cert(X509 *cert, STACK_OF(X509) *chain, X509_STORE *store, ASN1_TIME** next_update);

/**
 * Determines if the Must Staple TLS extension is set.
 *   
 * @returns 1 if the Must Staple extension is set, 0 otherwise
 */
int must_staple(X509 *cert);

/**
 * Determines if an OCSP revocation check can be performed on the
 * specified certificate.
 * 
 * @returns 1 if the check is possible, 0 otherwise
 */
int can_check_ocsp(X509 *cert);

/**
 * Determines if an CRL revocation check can be performed on the
 * specified certificate.
 * 
 * @returns 1 if the check is possible, 0 otherwise
 */
int can_check_crl(X509 *cert);
