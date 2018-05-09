#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/bio.h>

#include "ssl_connect.h"
#include "../lib/utils/http.h"

int create_socket(const char *url, int port, char **hostname);

static BIO *cbio = NULL;
static SSL *ssl = NULL;
static SSL_CTX *ssl_ctx = NULL;

SSL* create_connection(const char *url, int port, void* staplingcb, int *stapling_status, BIO *outbio)
{
    // Attempt to create a new SSL context
    // TLS_method will use the latest version the server and client share
    if (!(ssl_ctx = SSL_CTX_new(TLS_client_method()))) {
        printf("Unable to create a new SSL context structure.\n");
        return NULL;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_enable_ct(ssl_ctx, SSL_CT_VALIDATION_PERMISSIVE);
    
    SSL_CTX_load_verify_locations(ssl_ctx, NULL, "/etc/ssl/certs");
    char buf[1024];
    char dir[1024];
    getcwd(buf, 1024);
    sprintf(dir, "%s/test/certs/root/ca/certs", buf);
    // printf("%s\n", dir);
    SSL_CTX_load_verify_locations(ssl_ctx, NULL, dir);
    ssl = SSL_new(ssl_ctx);
    
    // Create a TCP connection
    char *hostname;
    if (create_socket(url, port, &hostname)) {
        printf("Successfully made the TCP connection to: %s:%d.\n", url, port);
    } else {
        printf("Error making TCP connection");
        return NULL;
    }

    // Use bio for ssl connection
    SSL_set_bio(ssl, cbio, cbio);

    // For SNI support
    SSL_set_tlsext_host_name(ssl, hostname);

    // Done using hostname
    free(hostname);
    // handling stapling
    if (staplingcb) {
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ssl_ctx, staplingcb);
        SSL_CTX_set_tlsext_status_arg(ssl_ctx, stapling_status);
    }

    // Make SSL connection
    if (SSL_connect(ssl) != 1) {
        printf("Error: Could not build a SSL session to: %s:%d.\n", url, port);
        return NULL;
    } else {
        printf("Successfully enabled SSL/TLS session to: %s:%d.\n", url, port);
    }

    // Free components used to create the connection
    return ssl;
}

void close_connection()
{
    if (!SSL_shutdown(ssl))
        SSL_shutdown(ssl); // For bi-directional shutdown, a second attempt may be required
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
}

/*
 * create_socket() creates the socket & TCP-connect to server
 */
int create_socket(const char *url, int port, char **hostname)
{
    // get hostname from url
    char *port_str = NULL, *schema = NULL, *path = NULL; // we don't need these two
    if(!http_parse_url(url, &schema, hostname, &port_str, &path)) {
        printf("Error: Could not parse URL: %s\n", url);
        return 0;
    }

    // create connect str
    char conn_str[strlen(*hostname) + 10];
    sprintf(conn_str, "%s:%d", *hostname, port);

    
    cbio = BIO_new_connect(conn_str);
    if(BIO_do_connect(cbio) <= 0) {
        // ERROR
        printf("ERROR connecting to server!\n");
        return 0;
    }

    return 1;
}
