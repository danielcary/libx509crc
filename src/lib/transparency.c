#include <stdio.h>

#include <openssl/ct.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ct.h>

#include "transparency.h"
#include "lib.h"
#include "errs.h"

int validate_transparency(SSL *ssl, char *filename) {
    const STACK_OF(SCT) *sct_stack = sk_SCT_new_null();
    sct_stack = SSL_get0_peer_scts(ssl);
    int num_SCT = sk_SCT_num(sct_stack);
    CTLOG_STORE *store = CTLOG_STORE_new();
    
    if(!num_SCT) {
        X509CRC_log_error(ERR_TRANSPARENCY_NO_SCT_OBTAINED);
        return ERR_TRANSPARENCY_NO_SCT_OBTAINED;
    } else {
        X509CRC_log_info("%d SCTs were obtained\n", num_SCT);
    }

    // Read in the list of CT logs to check against into a CTLOG_STORE
    int read_result = 0;
    if (!filename)
        read_result = CTLOG_STORE_load_file(store, "python/log_list.cnf");
    else
        read_result = CTLOG_STORE_load_file(store, filename);
        
    if (!read_result) {
        X509CRC_log_error(ERR_TRANSPARENCY_CANT_READ_CT_LOGS);
        return ERR_TRANSPARENCY_CANT_READ_CT_LOGS;
    }
    
    // Store the current time in order to check SCTs against
    // Use 5 minutes in the future to allow for some clock drift
    // time() gets the time in seconds, but SCTs work in milliseconds
    uint64_t cur_time = (time(NULL) + 300) * 1000;
    
    int ret = 1;
    for (int i = 0; i < num_SCT; i++) {
        SCT *cur_SCT = sk_SCT_value(sct_stack, i);
        uint64_t time_dif = cur_time - SCT_get_timestamp(cur_SCT);
        if (time_dif < 0) {
            // This SCT is from the future.
            X509CRC_log_info("%s", "The following SCT is from the future\n");
            SCT_print(cur_SCT, X509CRC_log_info_bio(), 3, store);
            ret = 0; 
            continue;// continue looping to see if any more SCTs are from the future
        }
        // Make sure that this SCT has the logID of a known CT log
        unsigned char *log_id;
        size_t log_id_len = SCT_get0_log_id(cur_SCT, &log_id);
        const CTLOG *ct_log = CTLOG_STORE_get0_log_by_id(store, log_id, log_id_len);
        if (!ct_log) {
            // This SCT does not have the logID of a CT log that is in the store
            X509CRC_log_info("%s", "The following SCT does not have a recognized logID\n");
            SCT_print(cur_SCT, X509CRC_log_info_bio(), 3, store);
            ret = 0;
        }
    }

    CTLOG_STORE_free(store);
    return ret;
}


int val_num_SCT(X509 *cert, int num_SCT) {
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    int day, sec;
    int valid = 0;
    
    if(0 == ASN1_TIME_diff(&day, &sec, not_before, not_after)) {
        X509CRC_log_info("%s", "There was an error comparing times.\n");
        return -1;
    }
    
    long int cert_lifetime = day*60*60*24 + sec;
    
    if (cert_lifetime < FIFTEEN_MONTHS && num_SCT >= 2) {
        valid = 1;
    } else if (cert_lifetime <= TWENTY_SEVEN_MONTHS && num_SCT >= 3) {
        valid = 1;
    } else if (cert_lifetime <= THIRTY_NINE_MONTHS && num_SCT >= 4) {
        valid = 1;
    } else  if (num_SCT >= 5) {
        valid = 1;
    } else {
        valid = 0;
    }
    return valid;
}
