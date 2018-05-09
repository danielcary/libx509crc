#include <openssl/ocsp.h>

/**
 * \brief Internal helper function for the OCSP and Stapling functions
 * 
 * Processes an OCSP response. Does not log any errors.
 * 
 * @param store the X509_STORE to use to verify the response
 * @parma cert_chain the certificate chain used to verify the response
 * @param id the id of the certificate to check the response for
 * @param rsp the OCSP response to process
 * @param next_update if not NULL, sets the time the OCSP status will
 *      be updated
 * 
 * @returns 0 on good, 1 on revoked, >1 error
 */
int X509CRC_read_ocsp_response(X509_STORE *store, STACK_OF(X509)* cert_chain, OCSP_CERTID* id, OCSP_RESPONSE* rsp, ASN1_TIME** next_update);