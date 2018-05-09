// Technically these are imprecise, but good enough for now
// We assume 30 days in a month, perfect 24 hours in each day
#define FIFTEEN_MONTHS   60*60*24*30*15
#define TWENTY_SEVEN_MONTHS   60*60*24*30*27
#define THIRTY_NINE_MONTHS   60*60*24*30*39

/**
 * Performs a brief and shallow SCT validation for the X.509 certificate obtained
 * from the given SSL connection. Only checks that the SCTs are not from the
 * future, and that each SCT is associated with a known log found in the log store.
 * If filename is NULL, validate_transparency() will attempt to load the CT_log list from
 * python/log_list.cnf
 * Otherwise, validate_transparency() will attempt to load the CT_log list from the 
 * filename passed in.
 * The python script openssl_ct_logs.py will download the list of CT logs that are compliant with
 * Google Chrome's CT policy, which is found here 
 * https://www.gstatic.com/ct/log_list/log_list.json
 * and will then format them in the .cnf format that is required by OpenSSL, and save it
 * in python/log_list.cnf
 *
 *
 * @returns 1 if all SCTs obtained pass this brief validation,
 *      0 if there are any SCTs obtained that fail this brief validation,
 *      -1 if no SCTs were obtained
 */
int validate_transparency(SSL *ssl, char *filename);

/**
 * Checks that the number of SCTs provided for this certificate
 * is adequate given the lifetime of the certificate.
 * For a lifetime < 15 months, 2 SCTs are expected
 * elif lifetime <= 27 months, 3 SCTs are expected
 * elif lifetime <= 39 months, 4 SCTs are expected
 * otherwise 5 or more SCTs are expected
 *
 * @returns 1 if there are enough SCTs provided for this certificate,
 *      0 if there were not enough provided
 */
int val_num_SCT(X509*, int);
