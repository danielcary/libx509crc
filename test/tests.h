#ifndef HEADER_LIBX509CRC_TEST_TESTS_H
#define HEADER_LIBX509CRC_TEST_TESTS_H

// should return 0 on success

int add_crl_suite();
int add_ocsp_suite();
int add_ocsp_stapling_suite();
int add_http_suite();
int add_lib_suite();
int add_transparency_suite();

int add_blackbox_suite();

#endif