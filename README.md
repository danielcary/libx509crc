# libx509crc
### NCSU Senior Design 2018 Spring Team 13 - Daniel Cary, Brian Hogan, Joseph Tew

### Installation
Please refer to [INSTALL.md](INSTALL.md) for installation and setup. 

### Usage

#### Command Line Interface Usage
Once compiled (check the Installation Guide) the command line interface can be used to perform Certificate Revocation Lists (CRL), Online Certificate Status Protocol (OCSP), and OCSP stapling revocation checks. The CLI will set-up its own SSL connection and will print the revocation test(s) output to the command line. Note that not all hosts support all of the revocation testing methods (for example, Google does not implement OCSP Stapling), in such cases the program will report this. If a connection cannot be made to the desired host over the desired port, the program will terminate. All arguments are optional, but if no tests are specifically requested, the program will setup an SSL/TLS connection, close it, and then terminate.


Usage: ./driverprogram [-u hostname] [-p port] [-o] [-c] [-s] [-t] [-d]
  - -u --url
    - Set the URL or hostname of the host to connect to
(default: https://www.cisco.com)
  - -p --port
    - Set the port of the host to connect to (default: 443)
  - -o --ocsp
    - Perform OCSP revocation checking
  - -c --crl
    - Perform CRL revocation checking
  - -s --stapling
    - Perform OCSP Stapling revocation checking
  - -t --transparency
    - Perform Certificate Transparency SCT checks
  - -v --verbose
    - Verbose mode. Has more output, including printing the entire X.509 certificate, to help track down bugs


