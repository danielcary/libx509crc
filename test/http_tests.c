#include <CUnit/Basic.h>

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

#include "tests.h"
#include "certs.h"
#include "servers.h"

#include "../src/lib/utils/http.h"

static int http_init();
static int http_clean();

static void http_parse_url_test();
static void https_get_test();

int add_http_suite() {
    // create suite
    CU_pSuite suite = CU_add_suite("lib/utils/http.c tests", http_init, http_clean);

    if(!suite) {
        return 1;
    }

     /* Add tests */
    return 
        !CU_add_test(suite, "HTTP parse url", http_parse_url_test) ||
        !CU_add_test(suite, "HTTP perform HTTPS GET", https_get_test);
}


static int http_init() {
    return 0;
}

static int http_clean() {
    return 0;
}

// test parsing urls in different formats
static void http_parse_url_test() {

    const char* urls[] = {
        "http://cisco.com",
        "http://cisco.com/index.html",
        "https://www.cisco.com",
        "https://www.cisco.com/",
        "www.cisco.com",
        "ftp://ftp.cisco.com"
    };

    const char* values[][4] = {
        {"http", "cisco.com", "80", "/"},
        {"http", "cisco.com", "80", "/index.html"},
        {"https", "www.cisco.com", "443", "/"},
        {"https", "www.cisco.com", "443", "/"},
        {"", "www.cisco.com", NULL, "/"},
        {"ftp", "ftp.cisco.com", NULL, "/"},
    };

    for(int i = 0; i < 6; i++) {
        char *schema, *host, *port, *path;
        http_parse_url(urls[i], &schema, &host, &port, &path);

        CU_ASSERT_STRING_EQUAL(schema, values[i][0]);
        CU_ASSERT_STRING_EQUAL(host, values[i][1]);
        if(values[i][2]) {
            CU_ASSERT_STRING_EQUAL(port, values[i][2]);
        } else {
            CU_ASSERT_PTR_NULL(port);
        }
        CU_ASSERT_STRING_EQUAL(path, values[i][3]);

        free(schema);
        free(host);
        free(port);
        free(path);
    }

}

// test performing an HTTPS GET request
// by connecting to an HTTPS CRL server
static void https_get_test() {
    setup();
    // revoke a server to make crl file size larger
    revoke_main_server();
    gen_crl();
    servers_start_crl_https();
    
    // load crl (which is going to be the content of the HTTPS GET response)
    char* wd = get_current_dir_name();
    char crl_path[PATH_MAX];
    sprintf(crl_path, "%s/test/certs/root/ca/intermediate/crl/intermediate.crl.der", wd);

    // get the crl file size and content
    FILE* crl_fp = fopen(crl_path, "r+");
    fseek(crl_fp, 0, SEEK_END);
    int crl_size = ftell(crl_fp);
    rewind(crl_fp);
    char crl[crl_size];
    fread(crl, 1, crl_size, crl_fp);
    fclose(crl_fp);

    // perform the HTTPS GET request
    void* content = NULL;
    int len;
    CU_ASSERT_EQUAL_FATAL(http_get_by_url("https://localhost:49201", &content, &len), 1);

    // make sure the size and content match
    CU_ASSERT_EQUAL(len, crl_size);
    CU_ASSERT_EQUAL(memcmp(crl, content, crl_size), 0);

    free(content);
    servers_join_crl();
}
