CC = gcc
CFLAGS_DRIVER = -Wall -std=c99 -g -O0 -D_GNU_SOURCE
LDLIBS = -lssl -lcrypto

CFLAGS_LIB = -Wall -std=c99 -D_GNU_SOURCE -fPIC

CFLAGS_TEST = -Wall -std=c99 -D_GNU_SOURCE -fprofile-arcs -ftest-coverage -g -O0 -pthread
LDLIBS_TEST = -lcunit -lssl -lcrypto

vpath % src/driver
vpath % src/lib
vpath % src/lib/utils
vpath % test/

LIB_SRCS = http.c ocsp.c crl.c ocsp_stapling.c lib.c ocsp_shared.c transparency.c
LIB_HEADERS = http.h crl.h lib.h validators.h errs.h
LIB_NAME = libx509crc.so

INSTALL_DIR = /usr/local

DRIVER_SRCS = main.c ssl_connect.c
DRIVER_HEADERS = ssl_connect.h

TEST_SRCS = run_tests.c transparency_tests.c servers.c lib_tests.c ocsp_res.c certs.c crl_tests.c http_tests.c ocsp_tests.c ocsp_stapling_tests.c blackbox_tests.c

#### DRIVER
driverprogram: $(DRIVER_SRCS) $(LIB_SRCS) #$(DRIVER_HEADERS) $(LIB_HEADERS)
	$(CC) $(CFLAGS_DRIVER) $^ -o $@ $(LDLIBS)

#### LIBRARY
lib: $(LIB_SRCS) #$(LIB_HEADERS)
	$(CC) $(CFLAGS_LIB) $^ -o $(LIB_NAME) -shared

#### Installs the header files in /usr/local/include/libx509crc
install: lib
	mkdir -p $(INSTALL_DIR)/include/libx509crc
	cp src/lib/crl.h $(INSTALL_DIR)/include/libx509crc/crl.h
	chmod 644 $(INSTALL_DIR)/include/libx509crc/crl.h
	cp src/lib/errs.h $(INSTALL_DIR)/include/libx509crc/errs.h
	chmod 644 $(INSTALL_DIR)/include/libx509crc/errs.h
	cp src/lib/lib.h $(INSTALL_DIR)/include/libx509crc/lib.h
	chmod 644 $(INSTALL_DIR)/include/libx509crc/lib.h
	cp src/lib/transparency.h $(INSTALL_DIR)/include/libx509crc/transparency.h
	chmod 644 $(INSTALL_DIR)/include/libx509crc/transparency.h
	cp $(LIB_NAME) $(INSTALL_DIR)/lib/$(LIB_NAME)
	chmod 755 $(INSTALL_DIR)/lib/$(LIB_NAME)
    

#### TEST
run_tests: clean tests driverprogram
	./tests
	rm -f $(TEST_SRCS:.c=.gcda) $(TEST_SRCS:.c=.gcno)
	gcovr -b -r .
	gcovr -r .

tests: $(LIB_SRCS) $(TEST_SRCS)
	$(CC) $(CFLAGS_TEST) $^ -o tests $(LDLIBS_TEST)
    

clean:
	rm -f *.o
	rm -f driverprogram
	rm -f run_tests tests
	rm -f libx509crc.so
	rm -f *.gcno
	rm -f *.gcov
	rm -f *.gcda
	rm -fr bb_actual
