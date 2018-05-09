#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "servers.h"
#include "../src/lib/utils/http.h"

static int load_certs(SSL_CTX *ctx, const char *server_name);
static void *servers_start_thread(void *args);
static pthread_t servers_start(const char* name, int port);
static int servers_stop(pthread_t t);

static int stapling_cb(SSL* ssl, void* arg);

static pthread_t crl_server_thread;
static pthread_t main_server_thread;
static pthread_t must_staple_server_thread;
static pthread_t no_ocsp_server_thread;
static pthread_t no_crl_server_thread;
static pthread_t https_dist_server_thread;

static bool no_fullchain = false;

void servers_start_main(int port) {
    main_server_thread = servers_start(MAIN_SERVER_HOSTNAME, port);
}

void servers_start_main_no_fullchain(int port) {
    no_fullchain = true;
    main_server_thread = servers_start(MAIN_SERVER_HOSTNAME, port);
}

void servers_start_must_staple(int port) {
    must_staple_server_thread = servers_start(MUSTSTAPLE_SERVER_HOSTNAME, port);
}

void servers_start_no_ocsp(int port) {
    no_ocsp_server_thread = servers_start(NOOCSP_SERVER_HOSTNAME, port);
}

void servers_start_no_crl(int port) {
    no_crl_server_thread = servers_start(NOCRL_SERVER_HOSTNAME, port);
}

void servers_start_https_dists(int port) {
    https_dist_server_thread = servers_start(HTTPSDIST_SERVER_HOSTNAME, port);
}

int servers_join_main() {
    return servers_stop(main_server_thread);
}

int servers_join_must_staple() {
    return servers_stop(must_staple_server_thread);
}

int servers_join_no_ocsp() {
    return servers_stop(no_ocsp_server_thread);
}

int servers_join_no_crl() {
    return servers_stop(no_crl_server_thread);
}

int servers_join_crl() {
    return servers_stop(crl_server_thread);
}

int servers_join_https_dists() {
    return servers_stop(https_dist_server_thread);
}

static int load_certs(SSL_CTX *ctx, const char *server_name)
{
    //  load certificates
    char wd[1024];
    char i_dir_path[1024];
    getcwd(wd, 1024);
    sprintf(i_dir_path, "%s/test/certs/root/ca/intermediate", wd);

    char cert_filepath[1024];
    if(no_fullchain) {
        sprintf(cert_filepath, "%s/certs/%s.cert.pem", i_dir_path, server_name);
    } else {
        sprintf(cert_filepath, "%s/certs/%s.fullchain.pem", i_dir_path, server_name);
    }
    char key_filepath[1024];
    sprintf(key_filepath, "%s/private/%s.key.pem", i_dir_path, server_name);

    int ret = no_fullchain ? 
        SSL_CTX_use_certificate_file(ctx, (const char*)cert_filepath, SSL_FILETYPE_PEM)
        :  SSL_CTX_use_certificate_chain_file(ctx, (const char*)cert_filepath);

    no_fullchain = false;

    return ret 
        && SSL_CTX_use_PrivateKey_file(ctx, (const char*)key_filepath, SSL_FILETYPE_PEM) 
        && SSL_CTX_check_private_key(ctx);
}

static pthread_t servers_start(const char* name, int port)
{
    char hostport[20];
    sprintf(hostport, "127.0.0.1:%d", port);

    // init mutex
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    int bound = 0;

    // start thread
    const void *params[] = {&mutex, &cond, &bound, hostport, name, stapling_cb};
    pthread_t thread;
    pthread_create(&thread, NULL, servers_start_thread, params);

    // wait for it to bind
    pthread_mutex_lock(&mutex);
    while (!bound) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    return thread;
}

static int stapling_cb(SSL* ssl, void* arg) 
{
    //  load certificates
    char wd[1024];
    char ca_dir_path[1024];
    getcwd(wd, 1024);
    sprintf(ca_dir_path, "%s/test/certs/root/ca", wd);

    char i_path[1024];
    sprintf(i_path, "%s/intermediate/certs/intermediate.cert.pem", ca_dir_path);

    FILE *i_fp = fopen(i_path, "r");

    X509 *i_cert = PEM_read_X509(i_fp, NULL, NULL, NULL);

    X509* cert = SSL_get_certificate(ssl);
    

    // create request
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, i_cert);
    OCSP_request_add0_id(req, id);
    OCSP_request_add1_nonce(req, NULL, -1);
    
    char *host = NULL, *schema = NULL, *port = NULL, *path = NULL;
    STACK_OF(OPENSSL_STRING) *emlist = X509_get1_ocsp(cert);
    http_parse_url(sk_OPENSSL_STRING_value(emlist, 0), &schema, &host, &port, &path);
    X509_email_free(emlist); // frees that stack
    
    // connect to the OCSP responder
    BIO* ocsp_bio = BIO_new_connect(host);
    BIO_set_conn_port(ocsp_bio, port);

    // send request
    if(BIO_do_connect(ocsp_bio) <= 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    OCSP_REQ_CTX *ocsp_req_ctx = OCSP_sendreq_new(ocsp_bio, path, NULL, 0);
    OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "Host", host);
    OCSP_REQ_CTX_set1_req(ocsp_req_ctx, req);

    OCSP_RESPONSE *res;
    OCSP_sendreq_nbio(&res, ocsp_req_ctx);    

    // staple response
    unsigned char* data = NULL;
    int len = i2d_OCSP_RESPONSE(res, &data);
    SSL_set_tlsext_status_ocsp_resp(ssl, data, len);

    return SSL_TLSEXT_ERR_OK;
}

static void *servers_start_thread(void *args)
{
    // get passed args
    pthread_mutex_t *mutex = ((void **)args)[0];
    pthread_cond_t *cond = ((void **)args)[1];
    int *bound = ((void **)args)[2];
    const char *hostport = ((void **)args)[3];
    const char *name = ((void **)args)[4];
    void* stapling_cb = ((void**)args)[5];

    // use the highest aviable version of ssl/tls
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    // load the certificates
    if (!load_certs(ctx, name))
    {
        printf("Error loading certificates\n");
        pthread_exit((void*)1);
    }

    // set up ssl bio
    BIO *sbio = BIO_new_ssl(ctx, 0);
    SSL *ssl;
    BIO_get_ssl(sbio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO *bbio = BIO_new(BIO_f_buffer());
    sbio = BIO_push(bbio, sbio);

    if(stapling_cb) {
        // stapling support
        SSL_CTX_set_tlsext_status_cb(ctx, stapling_cb);
    }

    // create accepting socket
    BIO *acpt = BIO_new(BIO_s_accept());
    BIO_set_accept_name(acpt, hostport);
    BIO_set_bind_mode(acpt, BIO_BIND_REUSEADDR);
    BIO_set_accept_bios(acpt, sbio);

    // bind & listen
    if (BIO_do_accept(acpt) <= 0)
    {
        printf("SERVER: Error binding\n");
        pthread_exit((void*)1);
    }

    // signal that we are bound
    pthread_mutex_lock(mutex);
    *bound = 1;
    pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);

    if (BIO_do_accept(acpt) <= 0)
    {
        printf("SERVER: Error accept\n");
        pthread_exit((void*)1);
    }

    // accept a connection
    BIO *cbio = BIO_pop(acpt);
    BIO_free_all(acpt); // we're only accepting one connection

    if (BIO_do_handshake(cbio) <= 0)
    {
        printf("Error performing handshake\n");
        pthread_exit((void*)1);
    }

    BIO_puts(cbio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");

    BIO_flush(cbio);
    BIO_free_all(cbio);

    pthread_exit(0);
}

int servers_stop(pthread_t t)
{
    int* ret;
    pthread_join(t, (void**)&ret);
    return (long)ret;
}

static void *servers_start_crl_thread(void *args);
static void _servers_start_crl(bool use_ssl)
{
    // init mutex
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    int bound = 0;

    // start thread
    void *params[] = {&mutex, &cond, &bound, (void*)use_ssl};
    pthread_create(&crl_server_thread, NULL, servers_start_crl_thread, params);

    // wait for it to bind
    pthread_mutex_lock(&mutex);
    while (!bound) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);
}


void servers_start_crl() {
    _servers_start_crl(false);
}

void servers_start_crl_https() {
    _servers_start_crl(true);
}

static void *servers_start_crl_thread(void *args)
{
    // get passed args
    pthread_mutex_t *mutex = ((void **)args)[0];
    pthread_cond_t *cond = ((void **)args)[1];
    int *bound = ((void **)args)[2];
    bool use_ssl = ((void**)args)[3];

    // load crl
    char wd[1024];
    char crl_path[1024];
    getcwd(wd, 1024);
    sprintf(crl_path, "%s/test/certs/root/ca/intermediate/crl/intermediate.crl.der", wd);

    FILE* crl_fp = fopen(crl_path, "r+");
    X509_CRL* crl = d2i_X509_CRL_fp(crl_fp, NULL);
    fclose(crl_fp);

    // start server
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    BIO *ssl_bio = NULL;

    if(use_ssl) {
        ssl_ctx = SSL_CTX_new(SSLv23_server_method());
         // load the certificates
        if (!load_certs(ssl_ctx, "crl.libx509crc.test"))
        {
            printf("Error loading certificates\n");
            pthread_exit((void*)1);
        }
        ssl_bio = BIO_new_ssl(ssl_ctx, 0);
        BIO_get_ssl(ssl_bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    }

    // create accepting socket
    BIO *acpt = BIO_new(BIO_s_accept());
    BIO *bufbio = BIO_new(BIO_f_buffer());

    if(use_ssl) {
        bufbio = BIO_push(bufbio, ssl_bio);
    }

    BIO_set_accept_name(acpt, "127.0.0.1:49201");
    BIO_set_bind_mode(acpt, BIO_BIND_REUSEADDR);
    BIO_set_accept_bios(acpt, bufbio);

    // bind & listen
    if (BIO_do_accept(acpt) <= 0)
    {
        printf("SERVER: Error binding\n");
        pthread_exit((void*)1);
    }

    // signal that we are bound
    pthread_mutex_lock(mutex);
    *bound = 1;
    pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);

    if (BIO_do_accept(acpt) <= 0)
    {
        printf("SERVER: Error accept\n");
        pthread_exit((void*)1);
    }

    // accept a connection
    BIO *cbio = BIO_pop(acpt);
    
    if(use_ssl) {
        if(BIO_do_handshake(cbio) <= 0) {
            printf("Error performing handshake\n");
            pthread_exit((void*)1);
        }
    }

    BIO_free_all(acpt); // we're only accepting one connection

    // send data to client
    BIO_puts(cbio, "HTTP/1.0 200 OK\r\nContent-type: application/pkix-crl\r\n\r\n");
    i2d_X509_CRL_bio(cbio, crl);

    BIO_flush(cbio);
    BIO_free_all(cbio);

    pthread_exit(0);
}