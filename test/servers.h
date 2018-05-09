#pragma once

#define MAIN_SERVER_HOSTNAME "libx509crc.test"
#define MUSTSTAPLE_SERVER_HOSTNAME "muststaple.libx509crc.test"
#define NOOCSP_SERVER_HOSTNAME "noocsp.libx509crc.test"
#define NOCRL_SERVER_HOSTNAME "nocrl.libx509crc.test"
#define HTTPSDIST_SERVER_HOSTNAME "https.libx509crc.test"

void servers_start_crl();
void servers_start_crl_https();

// note, servers only accept one connection then exit
void servers_start_main(int port);
void servers_start_must_staple(int port);
void servers_start_no_ocsp(int port);
void servers_start_no_crl(int port);
void servers_start_main_no_fullchain(int port);
void servers_start_https_dists(int port);

// returns thread exit code
int servers_join_crl();
int servers_join_main();
int servers_join_must_staple();
int servers_join_no_ocsp();
int servers_join_no_crl();
int servers_join_https_dists();
