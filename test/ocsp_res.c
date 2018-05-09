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
#include <openssl/ocsp.h>


void ocsp_res_sign_name(const char* name, OCSP_BASICRESP* res)
{
    //  load certificates
    char wd[1024];
    char ca_dir_path[1024];
    getcwd(wd, 1024);
    sprintf(ca_dir_path, "%s/test/certs/root/ca", wd);

    char rsigner_filepath[1024];
    sprintf(rsigner_filepath, "%s/intermediate/certs/%s.cert.pem", ca_dir_path, name);

    char rkey_filepath[1024];
    sprintf(rkey_filepath, "%s/intermediate/private/%s.key.pem", ca_dir_path, name);

    char i_path[1024];
    sprintf(i_path, "%s/intermediate/certs/intermediate.cert.pem", ca_dir_path);

    char ca_path[1024];
    sprintf(ca_path, "%s/certs/ca.cert.pem", ca_dir_path);

    FILE *rsigner_fp = fopen(rsigner_filepath, "r");
    FILE *rkey_fp = fopen(rkey_filepath, "r");
    FILE *ca_fp = fopen(ca_path, "r");
    FILE *i_fp = fopen(i_path, "r");

    X509* rsigner = PEM_read_X509(rsigner_fp, NULL, NULL, NULL);
    EVP_PKEY* rkey = PEM_read_PrivateKey(rkey_fp, NULL, NULL, NULL);
    X509 *ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL);
    X509 *i_cert = PEM_read_X509(i_fp, NULL, NULL, NULL);

    STACK_OF(X509)* certs = sk_X509_new_null();
    sk_X509_push(certs, i_cert);
    sk_X509_push(certs, ca_cert);

    fclose(rsigner_fp);
    fclose(rkey_fp);
    fclose(ca_fp);
    fclose(i_fp);

    // sign response
    OCSP_basic_sign(res, rsigner, rkey, NULL, certs, 0);
}

static void ocsp_res_sign(OCSP_BASICRESP* res)
{
    ocsp_res_sign_name("ocsp-res.libx509crc.test", res);
}

void ocsp_res_bad_time(BIO *cbio)
{
    // read in request
    char reqbuf[8096];
    for (;;)
    {
        BIO_gets(cbio, reqbuf, sizeof(reqbuf));
        if ((reqbuf[0] == '\r') || (reqbuf[0] == '\n'))
            break;
    }
    OCSP_REQUEST *req = d2i_OCSP_REQUEST_bio(cbio, NULL);

    // create response
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, 0);
    OCSP_CERTID *cid = OCSP_onereq_get0_id(one);
    ASN1_TIME *thisupd = X509_gmtime_adj(NULL, -600);
    ASN1_TIME *nextupd = X509_time_adj_ex(NULL, 0, -301, NULL);
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL, thisupd, nextupd);
    OCSP_copy_nonce(bs, req);

    // sign response
    ocsp_res_sign(bs);

    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_valid(BIO *cbio)
{
    // read in request
    char reqbuf[8096];
    for (;;)
    {
        BIO_gets(cbio, reqbuf, sizeof(reqbuf));
        if ((reqbuf[0] == '\r') || (reqbuf[0] == '\n'))
            break;
    }
    OCSP_REQUEST *req = d2i_OCSP_REQUEST_bio(cbio, NULL);

    // create response
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, 0);
    OCSP_CERTID *cid = OCSP_onereq_get0_id(one);
    ASN1_TIME *thisupd = X509_gmtime_adj(NULL, 0);
    ASN1_TIME *nextupd = X509_time_adj_ex(NULL, 0, 30, NULL);
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL, thisupd, nextupd);
    OCSP_copy_nonce(bs, req);

    // sign response
    ocsp_res_sign(bs);

    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_revoked(BIO *cbio)
{
    // read in request
    char reqbuf[8096];
    for (;;)
    {
        BIO_gets(cbio, reqbuf, sizeof(reqbuf));
        if ((reqbuf[0] == '\r') || (reqbuf[0] == '\n'))
            break;
    }
    OCSP_REQUEST *req = d2i_OCSP_REQUEST_bio(cbio, NULL);

    // create response
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, 0);
    OCSP_CERTID *cid = OCSP_onereq_get0_id(one);
    ASN1_TIME *revtime = X509_gmtime_adj(NULL, -1);
    ASN1_TIME *thisupd = X509_gmtime_adj(NULL, 0);
    ASN1_TIME *nextupd = X509_time_adj_ex(NULL, 0, 30, NULL);
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_REVOKED, 0, revtime, thisupd, nextupd);
    OCSP_copy_nonce(bs, req);

    // sign response
    ocsp_res_sign(bs);

    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_unknown(BIO *cbio)
{
    // read in request
    char reqbuf[8096];
    for (;;)
    {
        BIO_gets(cbio, reqbuf, sizeof(reqbuf));
        if ((reqbuf[0] == '\r') || (reqbuf[0] == '\n'))
            break;
    }
    OCSP_REQUEST *req = d2i_OCSP_REQUEST_bio(cbio, NULL);

    // create response
    OCSP_ONEREQ *one = OCSP_request_onereq_get0(req, 0);
    OCSP_CERTID *cid = OCSP_onereq_get0_id(one);
    ASN1_TIME *thisupd = X509_gmtime_adj(NULL, 0);
    ASN1_TIME *nextupd = X509_time_adj_ex(NULL, 0, 30, NULL);
    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
    OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_UNKNOWN, 0, NULL, thisupd, nextupd);
    OCSP_copy_nonce(bs, req);

    // sign response
    ocsp_res_sign(bs);

    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_internal_err(BIO *cbio)
{
    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR, NULL);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_null_res(BIO *cbio)
{
    OCSP_RESPONSE *res = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, NULL);

    //////////////////////////
    // send data
    BIO_printf(cbio,
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: application/ocsp-response\r\n"
               "Content-Length: %d\r\n\r\n",
               i2d_OCSP_RESPONSE(res, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, res);

    BIO_flush(cbio);
}

void ocsp_res_no_res(BIO *cbio)
{ 
    BIO_printf(cbio, "HTTP/1.0 500 BAD\r\n\r\n");
    BIO_flush(cbio);
}

static void *ocsp_res_start_thread(void *arg);
static pthread_t thread;
static pthread_mutex_t* exit_mutex;
static bool should_listen;

static void _ocsp_res_start(void (*res_ptr)(BIO *), bool use_ssl)
{
    // init mutex
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    int bound = 0;
    exit_mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(exit_mutex, NULL);
    should_listen = true;

    // start thread
    void *params[] = {&mutex, &cond, &bound, res_ptr, (void*)use_ssl};
    pthread_create(&thread, NULL, ocsp_res_start_thread, params);

    // wait for it to bind
    pthread_mutex_lock(&mutex);
    while(!bound) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);
}

void ocsp_res_start(void (*res_ptr)(BIO*))
{
    _ocsp_res_start(res_ptr, false);
}

void ocsp_res_ssl_start(void (*res_ptr)(BIO*)) 
{
    _ocsp_res_start(res_ptr, true);
}

int ocsp_res_join()
{
    pthread_mutex_lock(exit_mutex);
    should_listen = false;
    pthread_mutex_unlock(exit_mutex);

    int* ret;
    pthread_join(thread, (void**)&ret);

    pthread_mutex_destroy(exit_mutex);
    free(exit_mutex);

    return (long)ret;
}

static int load_certs(SSL_CTX *ctx, const char *server_name)
{
    //  load certificates
    char wd[1024];
    char i_dir_path[1024];
    getcwd(wd, 1024);
    sprintf(i_dir_path, "%s/test/certs/root/ca/intermediate", wd);

    char cert_filepath[1024];
    sprintf(cert_filepath, "%s/certs/%s.fullchain.pem", i_dir_path, server_name);
    
    char key_filepath[1024];
    sprintf(key_filepath, "%s/private/%s.key.pem", i_dir_path, server_name);

    return SSL_CTX_use_certificate_file(ctx, (const char*)cert_filepath, SSL_FILETYPE_PEM) 
        && SSL_CTX_use_PrivateKey_file(ctx, (const char*)key_filepath, SSL_FILETYPE_PEM) 
        && SSL_CTX_check_private_key(ctx);
}

static void *ocsp_res_start_thread(void *args)
{
    // get passed args
    pthread_mutex_t* mutex = ((void**)args)[0];
    pthread_cond_t* cond = ((void**)args)[1];
    int* bound = ((void**)args)[2];
    void (*res_ptr)(BIO *) = ((void**)args)[3];
    bool use_ssl = (bool)((void**)args)[4];

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    BIO *ssl_bio = NULL;

    if(use_ssl) {
        ssl_ctx = SSL_CTX_new(SSLv23_server_method());
        // load the certificates
        if (!load_certs(ssl_ctx, "ocsp.libx509crc.test")) {
            printf("Error loading certificates\n");
            pthread_exit((void*)1);
        }    
        ssl_bio = BIO_new_ssl(ssl_ctx, 0);
        BIO_get_ssl(ssl_bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    }

    // create socket
    BIO *sbio = BIO_new(BIO_s_accept());
    BIO *bufbio = BIO_new(BIO_f_buffer());

    if(use_ssl) {
        bufbio = BIO_push(bufbio, ssl_bio);
    }

    BIO_set_accept_name(sbio, "127.0.0.1:49200");
    BIO_set_bind_mode(sbio, BIO_BIND_REUSEADDR);
    BIO_set_accept_bios(sbio, bufbio);
    // set to non blocking
    BIO_set_nbio_accept(sbio, 1);

    // bind
    if (BIO_do_accept(sbio) <= 0)
    {
        printf("Couldn't bind\n");
        pthread_exit((void*)1);
    }

    // signal that we are bound
    pthread_mutex_lock(mutex);
    *bound = 1;
    pthread_cond_signal(cond);
    pthread_mutex_unlock(mutex);
    
    while(1) {
        // make sure we should still be looping
        pthread_mutex_lock(exit_mutex);
        if(!should_listen) {
            pthread_mutex_unlock(exit_mutex);
            break;
        }
        pthread_mutex_unlock(exit_mutex);

        // try to accept a connection
        if (BIO_do_accept(sbio) <= 0) {
            continue;
        }

        BIO *cbio = BIO_pop(sbio);

        if(use_ssl) {
            if(BIO_do_handshake(cbio) <= 0) {
                printf("Error performing handshake\n");
                pthread_exit((void*)1);
            }
        }

        res_ptr(cbio);

        // exit
        BIO_free(cbio);
    }

    BIO_free_all(sbio);
    pthread_exit((void*)0);
}
