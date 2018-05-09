#ifndef HEADER_LIBX509CRC_TEST_CERTS_H
#define HEADER_LIBX509CRC_TEST_CERTS_H

#define MAIN_SERVER_HOSTNAME "libx509crc.test"
#define MUSTSTAPLE_SERVER_HOSTNAME "muststaple.libx509crc.test"
#define NOOCSP_SERVER_HOSTNAME "noocsp.libx509crc.test"

/* Cleans and setups the new certificates */
void setup();

//void add_server(const char *hostname, int must_staple);
void revoke_server(const char *hostname);

/* revokes the default server */
void revoke_main_server();
/* revokes the server with the must staple extension */
void revoke_muststaple_server();

void gen_crl();


#endif