# Introduction

This example implements a self-hosted version of the benchmark by including
a `main()` entry point with an wolfSSL crypto SDK. It does not require a UART
or GPIO timestamp, nor does it require the host UI. It can be compiled into 
a stand-alone executable which can be run from an OS, or bare-metal on an
embedded platform.

# Details

## Harness

The `th_printf` and `th_timestamp` functions are implemented in `main.c`. By
compiling with the `EE_CFG_SELFHOSTED` flag set, all of the code for the UART
is removed and replaced with these two local functions. To run the benchmark,
a set of wrapper functions in `main.c` prepare the primitives for local
execution. Keys, plaintext, and ciphertext are all generated randomly with
`ee_srand()` which is seeded with zero for each primitive invocation.

The `th_timestamp` function is implemented with the POSIX `clock_gettime`
function, which reports elapsed time down to nanoseconds (if supported). If
your compiler does not support this function, edit the `th_timestamp` function
to generate a counter that increases at least once per microsecond.

## Self-timing

The benchmark determines the correct number of iterations automatically by
proportionally increasing the count until a minimum number of seconds (or
minimum number of iterations) elapse. These requirements are defined in the
auto-tune macro in `profile/ee_bench.c`.

## Self-checking

A set of 16-bit CRC values are provided per sub-test, precomputed by EEMBC. As
long as the seeds in the code aren't changed, these should always be the same.
This is to help verify the primitive SDK implementation is was done correctly.

# Compile and run

This example expects the wolfSSL library to be installed on your host.

```
% mkdir build
% cd build
% cmake .. -DSELFHOSTED=1 -DWOLFSSL=1
% make
% ./sec-tls
```

## wolfSSL Library

To build with using wolfSSL for crypto (https://github.com/wolfssl/wolfssl)
install wolfSSL version 4.8.0 or later on the system. On the host a good configure option to use when
building wolfSSL is:

```Bash
% ./autogen.sh
% ./configure 'CFLAGS=-DWOLFSSL_AES_DIRECT -DHAVE_AES_ECB -DWOLFSSL_ECDSA_DETERMINISTIC_K' \
    --enable-ecc --enable-keygen --enable-aesccm --enable-sp --enable-sp-asm \
    --enable-eccencrypt --enable-curve25519 --enable-ed25519 --enable-aesctr
% make
% sudo make install
```

## mbedTLS Library

mbedTLS does not support Ed25519 operation so it is currently incomplete and
will not generate a score.

# Scoring

This code is provided as an example of how the benchmark operates. In order to
generate an official score, the host software must be used to verify operation
of the benchmark (to discourage cheating). Please contact 
[support@eembc.org](mailto:support@eembc.org) for information on how to license the host
software.

