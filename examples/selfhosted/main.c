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

/**
 * This file, main.c, is provided as a simple way to run the benchmark without
 * the host GUI framework. The function main() invokes all of the benchmark
 * components in self-timing mode, and then computes the score. The only
 * porting compnents required is th_timestamp(). th_printf() may be ported
 * to observe what is happening during the benchmark, but is not required, so
 * the main() function calls "printf" to present the score. However, output
 * may be modified to suit the particular port needs.
 *
 * The point of this code is to give the user an idea of what the real
 * benchmark looks like. The scores generated here are not official scores
 * since they have not been generated with the test harness.
 *
 * Please contact support@eembc.org for information on obtaining the official
 * test harness.
 */
#include "ee_aes.h"
#include "ee_bench.h"
#include "ee_buffer.h"
#include "ee_chachapoly.h"
#include "ee_ecdh.h"
#include "ee_ecdsa.h"
#include "ee_main.h"
#include "ee_rsa.h"
#include "ee_sha.h"
#include "ee_util.h"
#include "ee_variations.h"
/* Pre-made keys just for this self-hosted main.c */
#include "keys.h"

/* There are several POSIX assumptions in this implementation. */
#if (__linux__ || __APPLE__)
#include <time.h>
#elif _WIN32
#include <sys\timeb.h>
#else
#error "Operating system not recognized"
#endif

/* `1` to turn on debugging messages */
#define DEBUG_VERIFY 0
/* Only run a single iteration of each task (for debug) */
#define CRC_ONLY 0

/* Wrapper functions fill out a results structure. */
typedef struct
{
    uint32_t iter; /* Final iterations performed (if autotuned) */
    uint32_t dt;   /* Delta time in microseconds */
    uint16_t crc;  /* crc16, depends on the primitive */
} wres_t;
/* All wrapper functions fit this prototype (dataset octets, iterations, res) */
typedef void wrapper_function_t(void *, uint32_t, uint32_t, wres_t *);
/* For functions that process multiple data records betwee init/free */
typedef struct ee_array_uint32
{
    uint32_t  size;
    uint32_t *data;
} ee_array_uint32_t;
/* This macro makes a global array structure out of an array. */
#define MAKE_ARRAY(PREFIX)              \
    static ee_array_uint32_t g_##PREFIX \
        = { sizeof(ee_##PREFIX) / sizeof(uint32_t), ee_##PREFIX }
/* These are the running digest and aead values */
static uint32_t ee_single_use[]   = { 0 };
static uint32_t ee_sha_digest_l[] = { 123, 6, 15, 299, 80, 36, 385, 80, 36 };
static uint32_t ee_sha_digest_m[] = { 123, 6, 15, 300, 80, 36, 299, 79, 36 };
static uint32_t ee_sha_digest_h[] = { 155, 6, 17, 361, 110, 52, 360, 111, 52 };
static uint32_t ee_aead_e_multi_l[] = { 400, 96, 48 };
static uint32_t ee_aead_e_multi_m[] = { 300, 80, 48 };
static uint32_t ee_aead_e_multi_h[] = { 368, 112, 64 };
static uint32_t ee_aead_d_multi_l[] = { 16, 16, 304, 96, 48 };
static uint32_t ee_aead_d_multi_m[] = { 16, 16, 304, 96, 48 };
static uint32_t ee_aead_d_multi_h[] = { 16, 32, 368, 112, 64 };
MAKE_ARRAY(single_use);
MAKE_ARRAY(sha_digest_l);
MAKE_ARRAY(sha_digest_m);
MAKE_ARRAY(sha_digest_h);
MAKE_ARRAY(aead_e_multi_l);
MAKE_ARRAY(aead_e_multi_m);
MAKE_ARRAY(aead_e_multi_h);
MAKE_ARRAY(aead_d_multi_l);
MAKE_ARRAY(aead_d_multi_m);
MAKE_ARRAY(aead_d_multi_h);

/* Self-hosted might be hosted on an O/S or it might not. Use can edit this. */
static void
error_handler(void)
{
    exit(-1);
}

/**
 * The function th_printf() is used extensively throughout the monitor and
 * profile code. However, for the self-hosted mode, it is not required. You
 * may comment out the content of this function with no consequence.
 */
void
th_printf(const char *fmt, ...)
{
#if (EE_CFG_QUIET != 1) || (DEBUG_VERIFY)
    va_list args;
    va_start(args, fmt);
    /*@-retvalint*/
    th_vprintf(fmt, args);
    va_end(args);
    /* Emulate the GUI and fail on error message. */
    if (fmt[0] == 'e' && fmt[1] == '-')
    {
        error_handler();
    }
#else
    /* If quiet mode is on, at least print the error (see README.md). */
    if (fmt[0] == 'e' && fmt[1] == '-')
    {
        va_list args;
        va_start(args, fmt);
        /*@-retvalint*/
        th_vprintf(fmt, args);
        va_end(args);
        error_handler();
    }
#endif
}

/**
 * @brief Generate a timestamp for performance compuation. Since we are running
 * self-hosted, there's no need for GPIO or an output message, just return
 * the elapsedMicroSeconds.
 *
 * @return uint32_t - Elapsed microseconds
 */
uint32_t
th_timestamp(void)
{
#if (__linux__ || __APPLE__)
    struct timespec t;
    /*@-unrecog*/
    clock_gettime(CLOCK_REALTIME, &t);
    const unsigned long NSEC_PER_SEC      = 1000000000UL;
    const unsigned long TIMER_RES_DIVIDER = 1000UL;
    uint64_t            elapsedMicroSeconds;
    /*@-usedef*/
    elapsedMicroSeconds = t.tv_sec * (NSEC_PER_SEC / TIMER_RES_DIVIDER)
                          + t.tv_nsec / TIMER_RES_DIVIDER;
#elif _WIN32
    struct timeb t;
    uint64_t     elapsedMicroSeconds;
    ftime(&t);
    elapsedMicroSeconds
        = ((uint64_t)t.time) * 1000 * 1000 + ((uint64_t)t.millitm) * 1000;
#else
#error "Operating system not recognized"
#endif
    return elapsedMicroSeconds;
}

/**
 * @brief Helper function to copy a number of pseudo-random octets to a buffer.
 *
 * @param p_buffer Destination buffer.
 * @param len Number of octets.
 */
static void
fill_rand(uint8_t *p_buffer, size_t len)
{
    for (size_t x = 0; x < len; ++x)
    {
        p_buffer[x] = ee_rand();
    }
}

static uint16_t
crcu8(uint8_t data, uint16_t crc)
{
    size_t  i     = 0;
    uint8_t x16   = 0;
    uint8_t carry = 0;

    for (i = 0; i < 8; i++)
    {
        x16 = (uint8_t)((data & 1) ^ ((uint8_t)crc & 1));
        data >>= 1;

        if (x16 == 1)
        {
            crc ^= 0x4002;
            carry = 1;
        }
        else
        {
            carry = 0;
        }
        crc >>= 1;
        if (carry)
        {
            crc |= 0x8000;
        }
        else
        {
            crc &= 0x7fff;
        }
    }
    return crc;
}

static uint16_t
crcu16(uint16_t newval, uint16_t crc)
{
    crc = crcu8((uint8_t)(newval), crc);
    crc = crcu8((uint8_t)((newval) >> 8), crc);
    return crc;
}

static void
pre_wrap_sha(ee_sha_size_t size, uint32_t n, uint32_t i, void *ex, wres_t *res)
{
    uint32_t          *p32      = NULL;
    uint8_t           *p8       = NULL;
    void              *p_msgs   = NULL;
    uint8_t           *p_digest = NULL;
    ee_array_uint32_t *input    = NULL;
    uint32_t           length   = 0;
    size_t             x, y;
    ee_bench_result_t  bres;

    /* If single value, use the premade single-element structure. */
    input = (ee_array_uint32_t *)ex;
    if (n > 0 && ex == 0)
    {
        g_single_use.data[0] = n;
        input                = &g_single_use;
    }
    /* See ee_bench_sha comments in ee_bench.h for memory layout. */
    /* Set up the scratchpad buffer values */
    p32    = (uint32_t *)th_buffer_address();
    *p32++ = input->size;
    /* Save where we are as the start of the message list */
    p_msgs = p32;
    /* Fill in message length and bytes, and leave space for output & tag */
    for (x = 0; x < input->size; ++x)
    {
        length = input->data[x];
        *p32++ = length;
        p8     = (uint8_t *)p32;
        /* Create a random message */
        fill_rand(p8, length);
        /* Skip to next message */
        p8 += length;
        p32 = (uint32_t *)p8;
    }
    p_digest = p8;
    /* With the filled buffer, call the benchmark routine */
    ee_bench_sha(size, i, DEBUG_VERIFY, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    res->crc  = 0;
    /* Calculate the CRC16 over the output */
    for (p32 = p_msgs, x = 0; x < input->size; ++x)
    {
        for (y = 0; y < (size / 8); ++y)
        {
            res->crc = crcu16(res->crc, (uint8_t)p_digest[y]);
        }
    }
}

#define MAKE_WRAP_SHA(x)                                            \
    void wrap_sha##x(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                               \
        pre_wrap_sha(EE_SHA##x, n, i, ex, res);                     \
    }

MAKE_WRAP_SHA(256)
MAKE_WRAP_SHA(384)

/* In order to perform a decrypt, we have to encrypt first. Hence this func.
   Normally the GUI host sends down encrypted data. */
static void
ee_encrypt(ee_cipher_t cipher,
           uint8_t    *p_key,
           uint32_t    keylen,
           uint8_t    *p_iv,
           uint32_t    ivlen,
           uint8_t    *p_pt,
           uint32_t    ptlen,
           uint8_t    *p_ct,
           uint8_t    *p_tag,
           uint32_t    taglen)
{
    void *p_context;
    switch (cipher)
    {
        case EE_CIPHER_AES_ECB:
            th_aes_create(&p_context, EE_AES_ECB);
            th_aes_init(p_context, p_key, keylen, p_iv, EE_AES_ENC, EE_AES_ECB);
            th_aes_ecb_encrypt(p_context, p_pt, ptlen, p_ct);
            th_aes_deinit(p_context);
            th_aes_destroy(p_context);
            break;
        case EE_CIPHER_AES_CTR:
            th_aes_create(&p_context, EE_AES_CTR);
            th_aes_init(p_context, p_key, keylen, p_iv, EE_AES_ENC, EE_AES_CTR);
            th_aes_ctr_encrypt(p_context, p_pt, ptlen, p_ct);
            th_aes_deinit(p_context);
            th_aes_destroy(p_context);
            break;
        case EE_CIPHER_AES_CCM:
            th_aes_create(&p_context, EE_AES_CCM);
            th_aes_init(p_context, p_key, keylen, p_iv, EE_AES_ENC, EE_AES_CCM);
            th_aes_ccm_encrypt(
                p_context, p_pt, ptlen, p_ct, p_tag, taglen, p_iv, ivlen);
            th_aes_deinit(p_context);
            th_aes_destroy(p_context);
            break;
        case EE_CIPHER_AES_GCM:
            th_aes_create(&p_context, EE_AES_GCM);
            th_aes_init(p_context, p_key, keylen, p_iv, EE_AES_ENC, EE_AES_GCM);
            th_aes_gcm_encrypt(
                p_context, p_pt, ptlen, p_ct, p_tag, taglen, p_iv, ivlen);
            th_aes_deinit(p_context);
            th_aes_destroy(p_context);
            break;
        case EE_CIPHER_CHACHAPOLY:
            th_chachapoly_create(&p_context);
            th_chachapoly_init(p_context, p_key, keylen);
            th_chachapoly_encrypt(
                p_context, p_pt, ptlen, p_ct, p_tag, taglen, p_iv, ivlen);
            th_chachapoly_deinit(p_context);
            th_chachapoly_destroy(p_context);
            break;
    }
    th_memcpy(p_pt, p_ct, ptlen);
}

static void
pre_wrap_cipher(ee_cipher_t      cipher,
                ee_cipher_func_t func,
                uint32_t         keylen,
                uint32_t         n, /* if n=0 use ex */
                uint32_t         i,
                void            *ex, /* null if n>0 */
                wres_t          *res)
{
    uint32_t           ivlen  = 0;
    uint32_t           taglen = 0;
    uint8_t           *p_key  = NULL;
    uint8_t           *p_iv   = NULL;
    uint32_t          *p32;
    uint8_t           *p8;
    ee_array_uint32_t *input;  /* Extended input data */
    void              *p_msgs; /* A pointer to the message list */
    uint32_t           msglen; /* The length of each message */
    size_t             x, y;
    ee_bench_result_t  bres;

    ivlen = (cipher == EE_CIPHER_AES_CTR)
                ? EE_AES_CTR_IVLEN
                : ((cipher == EE_CIPHER_CHACHAPOLY) ? EE_CHACHAPOLY_IVLEN
                                                    : EE_AES_AEAD_IVLEN);

    taglen = (cipher == EE_CIPHER_CHACHAPOLY) ? EE_CHACHAPOLY_TAGLEN
                                              : EE_AES_TAGLEN;

    input = (ee_array_uint32_t *)ex;
    /* If single value, use the premade single-element structure. */
    if (n > 0 && ex == 0)
    {
        g_single_use.data[0] = n;
        input                = &g_single_use;
    }

    /* Set up the scratchpad buffer values (all ciphers & AEADs are the same) */
    p32 = (uint32_t *)th_buffer_address();
    /* First the lengths and count */
    *p32++ = keylen;
    *p32++ = ivlen;
    *p32++ = input->size;
    /* Then the key and iv */
    p8    = (uint8_t *)p32;
    p_key = p8;
    fill_rand(p8, keylen);
    p8 += keylen;
    p_iv = p8;
    fill_rand(p8, ivlen);
    p8 += ivlen;
    p32 = (uint32_t *)p8;
    /* Save where we are as the start of the message list */
    p_msgs = p32;
    /* Then place the length values for each message packet (same as above) */
    for (x = 0; x < input->size; ++x)
    {
        msglen = input->data[x];
        *p32++ = msglen;
        p8     = (uint8_t *)p32;
        fill_rand(p8, msglen);
        /* Skip to next message */
        if (func == EE_CIPHER_FUNC_DEC)
        {
            /* Encrypt the message first. */
            ee_encrypt(cipher,
                       p_key,
                       keylen,
                       p_iv,
                       ivlen,
                       p8,
                       msglen,
                       p8 + msglen,
                       p8 + msglen + msglen,
                       taglen);
        }
        p8  = p8 + (msglen + msglen + taglen);
        p32 = (uint32_t *)p8;
    }
    /* With the filled buffer, call the benchmark routine */
    ee_bench_cipher(cipher, func, i, DEBUG_VERIFY, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    res->crc  = 0;
    /* Calculate the CRC16 over the output */
    for (p32 = p_msgs, x = 0; x < input->size; ++x)
    {
        msglen = *p32++;
        p8     = (uint8_t *)p32;
        p8     = p8 + msglen; /* move to output message */
        for (y = 0; y < msglen; ++y)
        {
            res->crc = crcu16(res->crc, (uint8_t)p8[y]);
        }
        /* Skip to next message */
        p8  = p8 + (msglen + taglen);
        p32 = (uint32_t *)p8;
    }
}

#define MAKE_WRAP_AES(bits, MODE, nick)                \
    void wrap_aes##bits##_##nick##_encrypt(            \
        void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                  \
        pre_wrap_cipher(EE_CIPHER_AES_##MODE,          \
                        EE_CIPHER_FUNC_ENC,            \
                        bits / 8,                      \
                        n,                             \
                        i,                             \
                        ex,                            \
                        res);                          \
    }                                                  \
    void wrap_aes##bits##_##nick##_decrypt(            \
        void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                  \
        pre_wrap_cipher(EE_CIPHER_AES_##MODE,          \
                        EE_CIPHER_FUNC_DEC,            \
                        bits / 8,                      \
                        n,                             \
                        i,                             \
                        ex,                            \
                        res);                          \
    }

MAKE_WRAP_AES(128, ECB, ecb)
MAKE_WRAP_AES(128, CTR, ctr)
MAKE_WRAP_AES(128, CCM, ccm)
MAKE_WRAP_AES(128, GCM, gcm)
MAKE_WRAP_AES(256, ECB, ecb)
MAKE_WRAP_AES(256, CTR, ctr)
MAKE_WRAP_AES(256, CCM, ccm)
MAKE_WRAP_AES(256, GCM, gcm)

static void
wrap_chachapoly_encrypt(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    pre_wrap_cipher(
        EE_CIPHER_CHACHAPOLY, EE_CIPHER_FUNC_ENC, 256 / 8, n, i, ex, res);
}

static void
wrap_chachapoly_decrypt(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    pre_wrap_cipher(
        EE_CIPHER_CHACHAPOLY, EE_CIPHER_FUNC_DEC, 256 / 8, n, i, ex, res);
}

static void
pre_wrap_ecdh(ee_ecc_group_t g, uint32_t i, wres_t *res)
{
    uint32_t         *p_publen = NULL;
    uint8_t          *p_pub    = NULL;
    uint32_t         *p_seclen = NULL;
    ee_bench_result_t bres;

    p_publen  = (uint32_t *)th_buffer_address();
    *p_publen = g_public_key_sizes[g];
    p_pub     = (uint8_t *)p_publen + sizeof(uint32_t);
    p_seclen  = (uint32_t *)(p_pub + *p_publen);
    th_memcpy(p_pub, g_public_keys[g], *p_publen);
    *p_seclen = 256; /* Reasonably-sized space for the sig. */
    ee_bench_ecdh(g, i, DEBUG_VERIFY, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    /* We don't have access to the private key so we cannot verify. */
    res->crc = 0;
}

#define MAKE_WRAP_ECDH(nick, group)                                      \
    void wrap_ecdh_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                    \
        pre_wrap_ecdh(group, i, res);                                    \
    }

MAKE_WRAP_ECDH(p256r1, EE_ECC_GROUP_P256R1)
MAKE_WRAP_ECDH(p384r1, EE_ECC_GROUP_P384R1)
MAKE_WRAP_ECDH(x25519, EE_ECC_GROUP_C25519)

static void
pre_wrap_ecdsa_sign(ee_ecc_group_t g, uint32_t i, wres_t *res)
{
    uint32_t         *p_msglen = NULL;
    uint8_t          *p_msg    = NULL;
    ee_bench_result_t bres;

    p_msglen  = (uint32_t *)th_buffer_address();
    *p_msglen = sizeof(g_dsa_message);
    p_msg     = (uint8_t *)p_msglen + 4;
    th_memcpy(p_msg, g_dsa_message, *p_msglen);
    ee_bench_ecdsa_sign(g, i, DEBUG_VERIFY, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    /* Since the DUT generates a new keypair every run, we can't CRC */
    res->crc = 0;
}

static void
pre_wrap_verify(ee_dsa_alg_t alg, uint32_t i, wres_t *res)
{
    uint32_t         *p_msglen = NULL;
    uint8_t          *p_msg    = NULL;
    uint32_t         *p_publen = NULL;
    uint8_t          *p_pub    = NULL;
    uint32_t         *p_siglen = NULL;
    uint8_t          *p_sig    = NULL;
    uint8_t          *p_pass   = NULL;
    ee_bench_result_t bres;

    /* Input message */
    p_msglen  = (uint32_t *)th_buffer_address();
    *p_msglen = sizeof(g_dsa_message);
    p_msg     = (uint8_t *)p_msglen + 4;
    th_memcpy(p_msg, g_dsa_message, *p_msglen);
    /* Length of public key ... */
    p_publen  = (uint32_t *)(p_msg + *p_msglen);
    *p_publen = g_public_key_sizes[alg];
    /* Public key */
    p_pub = (uint8_t *)p_publen + sizeof(uint32_t);
    th_memcpy(p_pub, g_public_keys[alg], *p_publen);
    /* Length of signature */
    p_siglen  = (uint32_t *)(p_pub + *p_publen);
    *p_siglen = g_dsa_signature_sizes[alg];
    /* Signature */
    p_sig = (uint8_t *)p_siglen + sizeof(uint32_t);
    th_memcpy(p_sig, g_dsa_signatures[alg], *p_siglen);
    /* Results of verification */
    p_pass  = p_sig + *p_siglen;
    *p_pass = 0;
    /* This function calls the primitives and manages the buffer. */
    ee_bench_verify(alg, i, DEBUG_VERIFY, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    /* No CRC here, just pass/fail, e.g. 1/0 */
    res->crc = *p_pass;
}

#define MAKE_WRAP_ECDSA(nick, sgroup, vgroup)                                  \
    void wrap_ecdsa_sign_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                          \
        pre_wrap_ecdsa_sign(sgroup, i, res);                                   \
    }                                                                          \
    void wrap_ecdsa_verify_##nick(                                             \
        void *ex, uint32_t n, uint32_t i, wres_t *res)                         \
    {                                                                          \
        pre_wrap_verify(vgroup, i, res);                                       \
    }

MAKE_WRAP_ECDSA(p256r1, EE_ECC_GROUP_P256R1, EE_DSA_ALG_ECDSA_P256R1)
MAKE_WRAP_ECDSA(p384r1, EE_ECC_GROUP_P384R1, EE_DSA_ALG_ECDSA_P384R1)
MAKE_WRAP_ECDSA(ed25519, EE_ECC_GROUP_ED25519, EE_DSA_ALG_ED25519)

#define MAKE_WRAP_RSA(nick, vgroup)                                            \
    void wrap_rsa_verify_##nick(void *ex, uint32_t n, uint32_t i, wres_t *res) \
    {                                                                          \
        pre_wrap_verify(vgroup, i, res);                                       \
    }

MAKE_WRAP_RSA(2048, EE_DSA_ALG_RSA2048)
MAKE_WRAP_RSA(3072, EE_DSA_ALG_RSA3072)
MAKE_WRAP_RSA(4096, EE_DSA_ALG_RSA4096)

/* TODO: forgot to autotune variation */
static void
wrap_variation_001(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    ee_bench_result_t bres;
    n = 0; /* unused */
    ee_bench_var01(0, &bres);
    res->iter = bres.iter;
    res->dt   = bres.dt;
    /**
     * There is no way to compute CRC without touching deeper code, but since
     * we've already exercised the primitives in the variation, we don't
     * actually need a CRC.
     */
    res->crc = 0;
}

static void
wrap_nop(void *ex, uint32_t n, uint32_t i, wres_t *res)
{
    n        = 0;
    res->dt  = 0;
    res->crc = 0;
}

/* This structure and macros facilitates a more readable task list. */
typedef struct
{
    wrapper_function_t *func;         /* The primitive for this task */
    uint32_t            n;            /* Number of octets for input data */
    float               ips;          /* iterations-per-second */
    float               weight;       /* equation scaling weight */
    uint16_t            actual_crc;   /* CRC computed for 1 iter. seed 0 */
    uint16_t            expected_crc; /* Precomputed CRC by EEMBC */
    char               *name;         /* Name of the task */
    void               *ex;           /* Extra data */
} task_entry_t;

/* iterations is set to 0 to autotune */
#define TASK(name, n, w, crc) \
    { wrap_##name, n, 0.0, (float)w, 0x0, crc, #name, (void *)0 },

/* Is there a portable variadic macro? No? Use an "extra" struct. */
#define TASKEX(name, w, crc, data) \
    { wrap_##name, 0, 0.0, (float)w, 0x0, crc, #name, (void *)data },

/**
 * The weights are used for scoring and are defined by the EEMBC working group.
 *
 * The expected_crc values were computed by EEMBC for the given parameters.
 * The CRC of the resulting output should be the same regardless of the
 * software or hardware implementation. Changing the random seed, the number
 * of input bytes, or any of the values in keys.h will cause CRC errors.
 */
// clang-format off
static task_entry_t g_task[] =
{
    /* Version 1: TLS1.2 */
    TASK(aes128_ecb_encrypt   ,  144,  1.0f, 0x515f)
    TASK(aes128_ecb_encrypt   ,  224,  1.0f, 0xff04)
    TASK(aes128_ecb_encrypt   ,  320,  1.0f, 0x0b7a)
    TASK(aes128_ccm_encrypt   ,   52,  1.0f, 0xd82d)
    TASK(aes128_ccm_decrypt   ,  168,  1.0f, 0x9a42)
    TASK(ecdh_p256r1          ,    0,  1.0f, 0)
    TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0)
    TASK(ecdsa_verify_p256r1  ,   32,  1.0f, 1)
    TASK(sha256               ,   23,  3.0f, 0x2151)
    TASK(sha256               ,   57,  1.0f, 0x3b3c)
    TASK(sha256               ,  384,  1.0f, 0x1d3f)
    TASK(variation_001        ,    0,  3.0f, 0x0000)
    TASK(sha256               , 4224,  4.0f, 0x9284)
    TASK(aes128_ecb_encrypt   , 2048, 10.0f, 0xc380)
    /* Version 2: */
    /*   Light */
    /*     TLS1.3 */
    TASK(sha256               ,  102, 10.0f, 0x880c)
    TASK(sha256               ,   94, 26.0f, 0xd86b)
    TASK(sha256               ,   93,  8.0f, 0x551b)
    TASKEX(sha256             ,        1.0f, 0x5c37, &g_sha_digest_l)
    TASKEX(chachapoly_encrypt ,        1.0f, 0xb645, &g_aead_e_multi_l)
    TASKEX(chachapoly_decrypt ,        1.0f, 0x7b1a, &g_aead_d_multi_l)
    TASK(ecdsa_sign_ed25519   ,  130,  1.0f, 0)
    TASK(ecdsa_verify_ed25519 ,   64,  2.0f, 1)
    TASK(ecdh_x25519          ,    0,  1.0f, 0)
    TASK(nop                  ,    0,  0.0f, 0) /* sic. DSA SHA placeholder */
    /*     Secure Boot, RSA */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    TASK(sha256               , 2048, 20.0f, 0x39ec)
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    /*     Secure Boot, ECC */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    /*   Medium */
    /*     TLS1.3/CCM */
    TASK(sha256               ,  102, 10.0f, 0x880c)
    TASK(sha256               ,   94, 26.0f, 0xd86b)
    TASK(sha256               ,   93,  8.0f, 0x551b)
    TASKEX(sha256             ,        3.0f, 0xa23c, &g_sha_digest_m)
    TASKEX(aes128_ccm_encrypt ,        1.0f, 0xb9d9, &g_aead_e_multi_m)
    TASKEX(aes128_ccm_decrypt ,        1.0f, 0x7b96, &g_aead_d_multi_m)
    TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0)
    TASK(ecdsa_verify_p256r1  ,   32,  2.0f, 1)
    TASK(ecdh_p256r1          ,    0,  1.0f, 0)
    TASK(sha256               ,  152,  8.0f, 0xd3ea)
    /*     TLS1.3/GCM */
    TASK(sha256               ,  102, 10.0f, 0x880c)
    TASK(sha256               ,   94, 26.0f, 0xd86b)
    TASK(sha256               ,   93,  8.0f, 0x551b)
    TASKEX(sha256             ,        1.0f, 0xa23c, &g_sha_digest_m)
    TASKEX(aes128_gcm_encrypt ,        1.0f, 0x954b, &g_aead_e_multi_m)
    TASKEX(aes128_gcm_decrypt ,        1.0f, 0x7b96, &g_aead_d_multi_m)
    TASK(ecdsa_sign_p256r1    ,   32,  1.0f, 0)
    TASK(ecdsa_verify_p256r1  ,   32,  2.0f, 1)
    TASK(ecdh_p256r1          ,    0,  1.0f, 0)
    TASK(sha256               ,  152,  8.0f, 0xd3ea)
    /*     Secure Boot, RSA */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    TASK(sha256               , 2048, 20.0f, 0x39ec)
    TASK(rsa_verify_2048      ,   32,  1.0f, 1)
    /*     Secure Boot, ECC */
    TASK(nop                  ,    0,  0.0f, 0) /* math placeholder */
    TASK(sha256               , 2048, 20.0f, 0x39ec)
    TASK(ecdsa_verify_p256r1  ,   32,  1.0f, 1)
    /*   High */
    /*     TLS1.3/CCM */
    TASK(sha384               ,  182, 10.0f, 0x4505)
    TASK(sha384               ,  169, 26.0f, 0x0c17)
    TASK(sha384               ,  169,  8.0f, 0x0c17)
    TASKEX(sha384             ,        1.0f, 0xa6b6, &g_sha_digest_h)
    TASKEX(aes256_ccm_encrypt ,        1.0f, 0xf16d, &g_aead_e_multi_h)
    TASKEX(aes256_ccm_decrypt ,        1.0f, 0x56f1, &g_aead_d_multi_h)
    TASK(ecdsa_sign_p384r1    ,   48,  1.0f, 0)
    TASK(ecdsa_verify_p384r1  ,   48,  2.0f, 1)
    TASK(ecdh_p384r1          ,    0,  1.0f, 0)
    TASK(sha384               ,  173,  1.0f, 0x7bf9)
    /*     TLS1.3/GCM */
    TASK(sha384               ,  182, 10.0f, 0x4505)
    TASK(sha384               ,  169, 26.0f, 0x0c17)
    TASK(sha384               ,  169,  8.0f, 0x0c17)
    TASKEX(sha384             ,        1.0f, 0xa6b6, &g_sha_digest_h)
    TASKEX(aes256_gcm_encrypt ,        1.0f, 0x9f97, &g_aead_e_multi_h)
    TASKEX(aes256_gcm_decrypt ,        1.0f, 0x56f1, &g_aead_d_multi_h)
    TASK(ecdsa_sign_p384r1    ,   48,  1.0f, 0)
    TASK(ecdsa_verify_p384r1  ,   48,  2.0f, 1)
    TASK(ecdh_p384r1          ,    0,  1.0f, 0)
    TASK(sha384               ,  173,  1.0f, 0x7bf9)
    /*     Secure Boot, RSA */
    TASK(aes256_ctr_decrypt   , 2048, 20.0f, 0xd203)
    TASK(sha384               , 2048, 20.0f, 0xff90)
    TASK(rsa_verify_4096      ,   32,  1.0f, 1)
    /*     Secure Boot, ECC */
    TASK(aes256_ctr_decrypt   , 2048, 20.0f, 0xd203)
    TASK(sha384               , 2048, 20.0f, 0xff90)
    TASK(ecdsa_verify_p384r1  ,   32,  1.0f, 1)
};
static const size_t g_numtasks = sizeof(g_task) / sizeof(task_entry_t);
/* This is how we scale the final score for each group*/
static struct scalar_tuples
{
    char        *suite;
    unsigned int places;
    unsigned int scalar;
    float        score;
} g_scalars[] = {
    { "TLSv1.2",                  14, 1000, 0.0f },
    { "TLSv1.3_Light",           10,   10, 0.0f },
    { "Boot_Light",        3,    1, 0.0f },
    { "",                          3,    0, 0.0f },
    { "TLSv1.3_Med_CCM",       10,   10, 0.0f },
    { "TLSv1.3_Med_GCM",       10,   10, 0.0f },
    { "Boot_Med_RSA",       3,    1, 0.0f },
    { "Boot_Med_ECC",      3,    1, 0.0f },
    { "TLSv1.3_Heavy_CCM", 10,   10, 0.0f },
    { "TLSv1.3_Heavy_GCM",      10,   10, 0.0f },
    { "Boot_Heavy_RSA",   3,    1, 0.0f },
    { "Boot_Heavy_ECC",   3,    1, 0.0f },
    { NULL, 0, 0, 0.0f } /* Done */
};
// clang-format on

int
main(void)
{
    char   namebuf[30];
    size_t scalar_idx = 0;
    wres_t res;
#if DEBUG_VERIFY == 0
    float component_score;
#endif
    setbuf(stdout, 0);
    /* N.B.: We use printf here rather than th_printf because we mute it to
       keep things less messy. If you can't use printf, use th_printf and turn
       off QUIET in the CMakeLists.txt file. */
    printf("---------------------------------------------------\n");
    printf("The SecureMark(R) Benchmark, Copyright (C) EEMBC(R)\n");
    printf("---------------------------------------------------\n");
    printf("Scratch buffer is %u bytes\n", th_buffer_size());
    printf("Number of subtests: %zu\n", g_numtasks);
    printf("\nCollecting component data...\n\n");
    printf(" # Suite             Component                    iterations/s\n");
    printf("-- ----------------- ------------------------- ---------------\n");
    for (size_t i = 0, j = 0; i < g_numtasks; ++i)
    {
        int do_print = g_task[i].weight != 0.0f;
        if (do_print)
        {
            if (g_task[i].ex == 0)
            {
                printf("%2zu %-17s %-25s ",
                       i + 1,
                       g_scalars[scalar_idx].suite,
                       g_task[i].name);
            }
            else
            {
                sprintf(namebuf, "%s_multi", g_task[i].name);
                printf("%2zu %-17s %-25s ",
                       i + 1,
                       g_scalars[scalar_idx].suite,
                       namebuf);
            }
#if DEBUG_VERIFY == 1
            printf("\n");
#endif
        }
        /* CRC's are always computed with seed 0 */
        ee_srand(0);
        (*g_task[i].func)(g_task[i].ex, g_task[i].n, 1, &res);
        g_task[i].actual_crc = res.crc;
#if DEBUG_VERIFY == 0
#if CRC_ONLY == 0
        /* Iterations = 0 means "autotune" to 10 seconds / 10 iterations. */
        (*g_task[i].func)(g_task[i].ex, g_task[i].n, 0, &res);
        if (g_task[i].weight != 0.0f)
        {
            g_task[i].ips = (float)res.iter / (res.dt / 1e6f);
        }
        else
        {
            g_task[i].ips = 0;
        }
#endif /* CRC_ONLY == 0 */
        if (g_task[i].weight != 0.0f)
        {
            component_score = g_task[i].weight / g_task[i].ips;
            g_scalars[scalar_idx].score += component_score;
        }
        if (j == g_scalars[scalar_idx].places - 1)
        {
            g_scalars[scalar_idx].score
                = g_scalars[scalar_idx].scalar / g_scalars[scalar_idx].score;
            ++scalar_idx;
            j = 0;
        }
        else
        {
            ++j;
        }
        if (do_print)
        {
            printf("%15.3f", g_task[i].ips);
#endif /* DEBUG_VERIFY == 0 */
            if (g_task[i].actual_crc != g_task[i].expected_crc)
            {
                printf(
                    " ***ERROR: CRCs did not match, expected 0x%04x, got "
                    "0x%04x",
                    g_task[i].expected_crc,
                    g_task[i].actual_crc);
            }
#if DEBUG_VERIFY == 0 && CRC_ONLY == 0
            printf("\n");
#endif
        }
    }
#if DEBUG_VERIFY == 0 && CRC_ONLY == 0
    printf("\nComputing suite scores...\n\n");
    printf("Suite                         Score\n");
    printf("----------------- -----------------\n");
    for (size_t i = 0; g_scalars[i].suite != NULL; ++i)
    {
        if (g_scalars[i].scalar == 0)
        {
            continue;
        }
        printf("%-19s %15.3f\n", g_scalars[i].suite, g_scalars[i].score);
    }
    printf(
        "\nDisclaimer: these are not official scores. In order to generate an\n"
        "official score, please contact support@eembc.org.\n");
#endif
    return 0;
}
