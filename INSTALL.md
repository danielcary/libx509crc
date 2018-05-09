## libx509crc Installation Manual

This manual describes the installation of the x509crc library on Linux based systems.

### External Dependencies
The following programs/libraries are required to compile and run the library:
- gcc
- GNU Make
- OpenSSL v1.1.1-pre1 or newer
- Python v2.7

The following additional libraries are required to compile and run the test suite:
- CUnit v2.1+
- gcovr


### Library Installation
After cloning or downloading the repository, navigate to the root project directory and run the following commands in order:
```
make lib
```
Compiles the library. Be sure to check the output of the command to confirm the library compile successfully. Any errors are likely the result of having the wrong OpenSSL version.
```
make run_tests
```
Compiles the test suite and then runs the unit tests. Check the output to see that all tests passed. It is an optional step, but it allows you to confirm that there are no compilation errors and that the library is working on your system as intended.
```
make install
```
Copies the compiled shared library, libx509crc.so, from project folder into the /usr/local/lib directory. The library headers will be copied to /usr/local/include/libx509crc. After this is complete, the library can be linked to your project with the -lx509crc argument when compiling with gcc. Also, make sure that gcc is setup to use libraries in /usr/local/lib directory by running `ldconfig /usr/local/lib`. 

To verify the library has been installed correctly run: `ldcondif -p | grep libx509crc`. If it has been installed correctly, there should be output indicating where libx509crc.so is located, otherwise there will be no output printed. If there is no output, try running “ldconfig” or rebooting the system.

### Command Line Interface Setup

While in the root project directory, run the following command:
make driverprogram

The executable can be run by calling ./driverprogram. Reference the README for instructions on how to use the program.

### Makefile Targets
- lib 
  - Will compile the library into an .so shared library.
- install
  - Will compile the library into an .so shared library and copy it to /usr/local/lib/libx509crc.so, as well as copy the header files into /usr/local/include/libx509crc.
- driverprogram
  - Will compile a driver program that allows a user to use libX509crc from the command line. 
- tests
  - Will compile the unit tests into an executable.
- run_tests
  - Will compile tests and run them. It will output test results along with library code and branch coverage. Note that “make run_tests” calls “make clean” before compiling and running the test suite.
- clean
  - Removes all build and testing files created from the project directory
