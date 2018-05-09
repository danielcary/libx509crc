#include <CUnit/Basic.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>

#include "tests.h"
#include "certs.h"
#include "servers.h"
#include "ocsp_res.h"

static int run_driver(const char* args, const char* out_file) {
    int pid;

    if((pid = fork()) == 0) {
        char buf[1024];
        char f[1024];
        getcwd(buf, 1024);
        sprintf(f, "%s/test/blackbox.sh", buf);

        execl("/bin/sh", "sh", f, args, out_file, NULL);
        printf("here\n");
        exit(-1);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);

        return WEXITSTATUS(status);
    }
}

// returns 0 if same
static int diff(const char* actual_fname, const char* expected_fname) {
    char buf[1024];
    getcwd(buf, 1024);

    char actual_fpath[1024];
    char expected_fpath[1024];    
    
    sprintf(actual_fpath, "%s/bb_actual/%s", buf, actual_fname);
    sprintf(expected_fpath, "%s/test/expected/%s", buf, expected_fname);

    FILE* actual_fp = fopen(actual_fpath, "r+");
    FILE* expected_fp = fopen(expected_fpath, "r+");

    int actual_size, expected_size;
    
    fseek(actual_fp, 0, SEEK_END);
    actual_size = ftell(actual_fp);
    rewind(actual_fp);

    fseek(expected_fp, 0, SEEK_END);
    expected_size = ftell(expected_fp);
    rewind(expected_fp);

    char actual[actual_size];
    char expected[expected_size];
    
    fread(actual, 1, actual_size, actual_fp);
    fread(expected, 1, expected_size, expected_fp);

    fclose(actual_fp);
    fclose(expected_fp);

    if(actual_size != expected_size) {
        return 1;
    }

    return memcmp(actual, expected, actual_size);
}

static int blackbox_init();
static int blackbox_clean();

static void blackbox_valid_ocsp();
static void blackbox_valid_stapling();
static void blackbox_valid_crl();

static void blackbox_ocsp_revoked();
static void blackbox_stapling_revoked();
static void blackbox_crl_revoked();


int add_blackbox_suite() {
    // create suite
    CU_pSuite suite = CU_add_suite("Blackbox tests", blackbox_init, blackbox_clean);

    if(!suite) {
        return 1;
    }

     /* Add tests */
    return 
        !CU_add_test(suite, "Valid OCSP", blackbox_valid_ocsp)
        || !CU_add_test(suite, "Valid OCSP Stapling", blackbox_valid_stapling)
        || !CU_add_test(suite, "Valid CRL", blackbox_valid_crl)
        || !CU_add_test(suite, "Revoked OCSP", blackbox_ocsp_revoked)
        || !CU_add_test(suite, "Revoked OCSP Stapling", blackbox_stapling_revoked)
        || !CU_add_test(suite, "Revoked CRL", blackbox_crl_revoked);
}


static int blackbox_init() {
    setup();
    return 0;
}

static int blackbox_clean() {
    return 0;
}

static void blackbox_valid_ocsp() {
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --ocsp", "1-actual.txt");
    CU_ASSERT_EQUAL(val, 0);
    CU_ASSERT_FALSE(diff("1-actual.txt", "1.txt"));

    servers_join_main();
    ocsp_res_join();
}

static void blackbox_valid_stapling()
{
    ocsp_res_start(ocsp_res_valid);
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --stapling", "2-actual.txt");
    CU_ASSERT_EQUAL(val, 0);
    CU_ASSERT_FALSE(diff("2-actual.txt", "2.txt"));

    servers_join_main();
    ocsp_res_join();
}

static void blackbox_valid_crl() 
{
    servers_start_crl();
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --crl", "3-actual.txt");
    CU_ASSERT_EQUAL(val, 0);
    CU_ASSERT_FALSE(diff("3-actual.txt", "3.txt"));

    servers_join_main();
    servers_join_crl();
}

static void blackbox_ocsp_revoked() {
    ocsp_res_start(ocsp_res_revoked);
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --ocsp", "4-actual.txt");
    CU_ASSERT_EQUAL(val, 0);
    CU_ASSERT_FALSE(diff("4-actual.txt", "4.txt"));

    servers_join_main();
    ocsp_res_join();
}

// note that we should probably get an "Error performing handshake" in output
// as the connection will exit early cause its revoked
static void blackbox_stapling_revoked() {
    ocsp_res_start(ocsp_res_revoked);
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --stapling", "5-actual.txt");
    CU_ASSERT_EQUAL(val, (unsigned char)-1); // -1 cause connection should fail with revoked staple
    CU_ASSERT_FALSE(diff("5-actual.txt", "5.txt"));

    servers_join_main();
    ocsp_res_join();
}

static void blackbox_crl_revoked() 
{
    revoke_main_server();
    gen_crl();
    servers_start_crl();
    servers_start_main(49202);
    
    int val = run_driver("-u localhost -p 49202 --crl", "6-actual.txt");
    CU_ASSERT_EQUAL(val, 0);
    CU_ASSERT_FALSE(diff("6-actual.txt", "6.txt"));

    servers_join_main();
    servers_join_crl();
}