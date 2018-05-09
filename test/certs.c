#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "certs.h"

#define exec(options...) execl("./test/certs/certs.sh", "certs.sh", options, (char*)NULL);

static void hide_stdout() {
    int fd = open("/dev/null", O_WRONLY);

    dup2(fd, 1);    /* make stdout a copy of fd (> /dev/null) */
    dup2(fd, 2);
    close(fd);      /* close fd */
}

void setup() {
    pid_t pid;

    if((pid = fork()) == 0) {
        hide_stdout();
        exec("clean");
    }

    int status;
    waitpid(pid, &status, 0);

    if((pid = fork()) == 0) {
        hide_stdout();
        exec("setup");
    }

    waitpid(pid, &status, 0);
}

void revoke_server(const char *hostname) {
    pid_t pid;

    if((pid = fork()) == 0) {
        hide_stdout();
        exec("revoke", hostname);
    } 

    int status;
    waitpid(pid, &status, 0);
}

void revoke_main_server() {
    revoke_server(MAIN_SERVER_HOSTNAME);
}

void revoke_muststaple_server() {
    revoke_server(MUSTSTAPLE_SERVER_HOSTNAME);
}

void gen_crl() {
    pid_t pid;

    if((pid = fork()) == 0) {
        hide_stdout();
        exec("gencrl");
    } 

    int status;
    waitpid(pid, &status, 0);
}
