#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "http.h"

int get_header(const void *res, char **header) {
    // determine length of header
    void *end = strstr(res, "\r\n\r\n");
    if(!end) {
        return 0;
    }
    // increment past the header terminator
    end += 4;

    int len = end - res;

    // allocate header copy
    *header = malloc(len + 1);
    
    // copy header data
    strncpy(*header, res, len);
    (*header)[len - 1] = '\0';

    // lower case all of data
    for(int i = 0; i < len -1; i++) {
        (*header)[i] = tolower((*header)[i]);
    }

    return 1;
}

int http_get_by_url(const char *url, void **content, int *len) {
    // parse url
    char *host = NULL, *port = NULL, *schema = NULL, *path = NULL;
    http_parse_url(url, &schema, &host, &port, &path);
    
    // perform get
    bool use_ssl = !strcmp(schema, "https");
    int ret = http_get(host, port, use_ssl, path, content, len);

    // free up parsed url parts
    free(host);
    free(port);
    free(schema);
    free(path);

    return ret;
}

int http_get(const char *hostname, const char *port, bool use_ssl, const char *path, void **content, int *len)
{   
    SSL* ssl = NULL;
    BIO* web = NULL;
    SSL_CTX* ssl_ctx = NULL;
    
    // create connect str
    char conn_str[strlen(hostname) + strlen(port) + 2];
    sprintf(conn_str, "%s:%s", hostname, port);

    if(use_ssl) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            //printf("Unable to create a new SSL context structure.\n");
            return 0;
        }
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
        web = BIO_new_ssl_connect(ssl_ctx);
        BIO_set_conn_hostname(web, conn_str);
        BIO_get_ssl(web, &ssl);
        SSL_set_tlsext_host_name(ssl, hostname);
    } else {
        web = BIO_new_connect(conn_str);
    }

    // connect to CRL dist point
    if(BIO_do_connect(web) <= 0) {
      //  printf("ERROR connecting to server!\n");
        return 0;
    }

    if(use_ssl) {
        BIO_do_handshake(web);
    }

    // create GET request
    char req[strlen(path) + strlen(hostname) + 30];
    sprintf(req, "GET %s HTTP/1.0\nHost: %s\n\n", path, hostname); 
    
    // write HTTP GET request to TCP stream
    BIO_puts(web, req);

    int tmp_buf_len = 0;
    int tmp_buf_size = 512;
    char *tmp_buf = malloc(tmp_buf_size);
    //BIO_should_retry(web)
    while(1) {
        // read from stream
        char buf[512];
        
        int len = BIO_read(web, buf, 512);
        if(len <= 0) {
            break;
        }
        
        // make sure enough space is in buffer
        if(tmp_buf_len + len >= tmp_buf_size) {
            // increase buffer
            tmp_buf_size = tmp_buf_size << 1;
            if(!(tmp_buf = realloc(tmp_buf, tmp_buf_size))) {
                return 0;
            }
        }

        // copy to buffer
        memcpy(tmp_buf + tmp_buf_len, buf, len);
        tmp_buf_len += len;
    }

    // free tcp connection
    BIO_free_all(web);
    if(ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    
    // get the header
    char *header = NULL;
    if(!get_header(tmp_buf, &header)) {
        return 0;
    }
    
    // check for an OKAY
    if(!strstr(header, "200 ok\r\n")) {
        return 0;
    }

    // calc content length;
    *len = tmp_buf_len - strlen(header) - 1;

    // copy message body
    *content = malloc(*len);
    memcpy(*content, tmp_buf + strlen(header) + 1, *len);
    
    // free tmp buffers
    free(tmp_buf);
    free(header);

    return 1;
}

// only works for urls in this format
// [schema://]host[:port][/path]
int http_parse_url(const char *url, char** schema, char **host, char **port, char **path) {
    // make working copy
    char _url[strlen(url) + 1];
    char *url_p = _url;
    strcpy(_url, url);

    // get scheme
    char *schemeEnd = strstr(url_p, ":");
    if(!schemeEnd) {
        schemeEnd = url_p;
    }
    *schema = malloc(schemeEnd - url_p + 1);
    strncpy(*schema, url_p, schemeEnd - url_p);
    (*schema)[schemeEnd - url_p] = '\0';

    // get host name
    if(strlen(*schema)) {
        url_p += strlen(*schema) + 3;
    }
    int host_len;

    if(strstr(url_p, ":")) {
        host_len = strstr(url_p, ":") - url_p;
    } else if(strstr(url_p, "/")) {
        host_len = strstr(url_p, "/") - url_p;
    } else {
        host_len = strlen(url_p);
    }
    
    *host = malloc(host_len + 1);
    strncpy(*host, url_p, host_len);
    (*host)[host_len] = '\0';
    url_p += strlen(*host) + 1;

    // get port
    if(*(url_p - 1) == ':') {
        int port_len;
        if(strstr(url_p, "/")) {
            port_len = strstr(url_p, "/") - url_p;
        } else {
            port_len = strlen(url_p);
        }

        *port = malloc(port_len + 1);
        strncpy(*port, url_p, port_len);
        (*port)[port_len] = '\0';
        url_p += strlen(*port) + 1;
    } else {
        if(!strcmp(*schema, "http") || !strcmp(*schema, "HTTP")) {
            *port = malloc(3);
            strcpy(*port, "80");
        } else if(!strcmp(*schema, "https") || !strcmp(*schema, "HTTPS")) {
            *port = malloc(4);
            strcpy(*port, "443");
        } else {
            *port = NULL;
        }
    }

    // get path
    if(*(url_p - 1) == '/') {
        url_p -= 1;
        int path_len = strlen(url_p);
        *path = malloc(path_len + 1);
        strncpy(*path, url_p, path_len);
        (*path)[path_len] = '\0';
    } else {
        *path = malloc(2);
        strcpy(*path, "/");
    }

    return 1;
}