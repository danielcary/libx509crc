#ifndef HEADER_SSLCONNECT_H
#define HEADER_SSLCONNECT_H

#include <openssl/ssl.h>

SSL* create_connection(const char *url, int port, void* staplingcb, int *stapling_status, BIO *outbio);
void close_connection();

#endif