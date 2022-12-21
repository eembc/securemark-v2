/*
 * Copyright (C) EEMBC(R). All Rights Reserved
 *
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.
 *
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#ifndef __EE_BENCH_H
#define __EE_BENCH_H

#include "ee_main.h"
#include "ee_aes.h"
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_rng.h"
#include "ee_rsa.h"
#include "ee_sha.h"
#include "ee_variations.h"
#include "ee_util.h"

/* These are to help unify the AES and ChaChaPoly code for simplicity. */
typedef enum
{
    EE_CIPHER_AES_ECB = 0,
    EE_CIPHER_AES_CTR,
    EE_CIPHER_AES_CCM,
    EE_CIPHER_AES_GCM,
    EE_CIPHER_CHACHAPOLY
} ee_cipher_t;

typedef enum
{
    EE_CIPHER_FUNC_ENC = 0,
    EE_CIPHER_FUNC_DEC
} ee_cipher_func_t;

/* Similarly, we unify the verify functions for simplicity. */
typedef enum
{
    EE_DSA_ALG_ECDSA_P256R1 = 0,
    EE_DSA_ALG_ECDSA_P384R1 = 1,
    EE_DSA_ALG_ECDSA_C25519 = 2, /* sic. placeholder, unused! */
    EE_DSA_ALG_ED25519      = 3,
    EE_DSA_ALG_RSA2048,
    EE_DSA_ALG_RSA3072,
    EE_DSA_ALG_RSA4096
} ee_dsa_alg_t;

typedef struct ee_bench_result_t
{
    uint32_t iter;
    uint32_t dt;
} ee_bench_result_t;

/**
 * @brief The top-level SHA benchmark wrapper.
 *
 * The `th_buffer` will be populated by the function. The resulting contents
 * shall be as follows:
 *
 * Offset   Size    Data
 * ------   ----    ---------------------------------------------
 * 0        4       Number of messages to hash = N
 * 4        ...     See ee_sha.h for a description of the message format
 *
 * @param size - The enum indicating the number of bits in the SHA
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @param res - Result structure (output)
 */
void ee_bench_sha(ee_sha_size_t      size,
                  uint32_t           i,
                  bool               verify,
                  ee_bench_result_t *res);

/**
 * @brief The top-level AES benchmark wrapper.
 *
 * The `th_buffer` will be populated by the caller. The resulting contents
 * shall be as follows:
 *
 * Offset   Size    Data
 * ------   ----    ---------------------------------------------
 * 0        4       Key length = n
 * 4        4       IV length = m
 * 8        4       Number of messages = N
 * 12       n       Key (n=16 or 32 depending on AES128 or AES256)
 * " + n    m       Initialization vector*
 * " + m    ...     See ee_aes.h for a description of the message format
 *
 * * If the initialization vector or tag is not used (ECB), these fields are
 *   still required but are ignored.
 *
 * @param mode - The enum indicating the cipher mode
 * @param func - The enum indicating the function (encrypt/decrypt)
 * @param i - The number of iterations to perform
 * @param res - Result structure (output)
 */
void ee_bench_cipher(ee_cipher_t        mode,
                     ee_cipher_func_t   func,
                     uint32_t           i,
                     bool               verify,
                     ee_bench_result_t *res);

/**
 * @brief The top-level ECDH benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: length of public key (32-bits)
 * 4            Input: public key
 * " + publen   Output: length of secret (32-bits)
 * " + seclen   Output: secret
 *
 * For SECP/NIST curves 256r1 and 384r1, the public key is uncompressed X, Y
 * coordinates, 256 or 384 bits as SECP1 format { 04 | X | Y }; For X25519, it
 * is 256 bits.
 *
 * @param g - See the `ee_ecdh_group_t` enum
 * @param i - The number of iterations to perform
 * @param res - Result structure (output)
 */
void ee_bench_ecdh(ee_ecc_group_t     g,
                   uint32_t           i,
                   bool               verify,
                   ee_bench_result_t *res);

/**
 * @brief The top-level ECDSA/EdDSA sign benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: size of message in bytes (n)
 * " + 4        Input: message data (n bytes)
 * " + n        Output: 256-byte buffer for public key
 * " + 256      Output: 256-byte buffer for signature
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param g - See the `ee_ecdh_group_t` enum
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @param res - Result structure (output)
 */
void ee_bench_ecdsa_sign(ee_ecc_group_t     g,
                         uint32_t           i,
                         bool               verify,
                         ee_bench_result_t *res);

/**
 * @brief The top-level ECDSA/EdDSA sign benchmark wrapper.
 *
 * The wrapper expects this format to the `th_buffer`:
 *
 * Offset       Data
 * -----------  ----------------------------------------
 * 0            Input: size of message in bytes (n)
 * " + 4        Input: message data (n bytes)
 * " + n        Input: 32-bit length of public key in bytes
 * " + 4        Input: Public key buffer
 * " + publen   Input: 32-bit length of signature in bytes
 * " + 4        Input: Signature buffer
 * " + siglen   Output: pass/fail byte (1=pass 0=fail)
 *
 * For SECP/NIST curves 256r1 and 384r1, the public key is uncompressed X, Y
 * coordinates, 256 or 384 bits as SECP1 format { 04 | X | Y }; For X25519, it
 * is 256 bits.
 *
 * For EcDSA, the signature format is the ASN.1 DER of R and S. For Ed25519,
 * the signature is the raw, little endian encoding of R and S, padded to 256
 * bits.
 *
 * Note that even if the message is a hash, Ed25519 will perform another SHA-
 * 512 operation on it, as this is part of RFC 8032.
 *
 * @param alg - The type of verify algorithm (see enum)
 * @param i - The number of iterations to perform
 * @param verify - Print verification messages for the host
 * @param res - Result structure (output)
 */
void ee_bench_verify(ee_dsa_alg_t       alg,
                     uint32_t           i,
                     bool               verify,
                     ee_bench_result_t *res);

arg_claimed_t ee_bench_parse(char *p_command, bool verify);
void ee_bench_var01(uint32_t i, ee_bench_result_t *res);

#endif /* __EE_BENCH_H */
