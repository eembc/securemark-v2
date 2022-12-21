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
 * In this file are wrapper functions that facilitate benchmarking each
 * individual primitive. The Host provides all of the input data through
 * the generic buffer interface. For each primitive wrapper ("benc" function),
 * the code must set up the `th_` funciton parameters from pointers into this
 * flat buffer. For each primitive, the buffer layout is explained in the
 * `ee_bench.h` header file. Each benchmark function returns the runtime in
 * microseconds. If there is an error, it will be in the form of a `th_printf`
 * message that the host must acknowledge.
 *
 * In addition to benchmarking each of the primitives in their own wrappers,
 * there is a macro for "auto-tuning" each run. The Run Rules for the benchmark
 * state that every primitive must run for at least 10 seconds or 10 iterations.
 * The autotuner does a binary search to determine the iterations-per-second
 * of the primitive, and then sets the total iterations to meet the 10-or-10
 * requirements. It adds about 3 seconds of runtime per primitive, but it
 * makes benchmarking much easier.
 *
 * Lastly, the `ee_bench` function parses the command string and routes the
 * call to the proper benchmark wrapper.
 *
 * Keep in mind the following:
 *
 * 1. Any time a 32 bit value is passed from the HOST to the DUT, it is always
 *    big endian. Two macros fix and check the endian-ness: FIX_ENDIAN and
 *    CHECK_RANGE. THe former is in `th_util.h` and must but coded to match
 *    the DUT endian if the compiler cannot resolve it. The latter is a simple
 *    sanity check because none of the incoming parameters should be huge.
 *
 * 2. If the number of iterations is zero, the AUTOTUNE function will find the
 *    correct number of iterations to meet the Run Rules.
 *
 * 3. The Host parses all of the `th_printf` calls and uses them to coordinate
 *    and verify the correctness. The `if (verify) ...` statements report back
 *    the necessary information for a third party to verify correctness. This
 *    is an optional parameter set with `verify (0|1)` because it can produce
 *    an enormous amount of data. Typically a smaller "verification" set of
 *    commands is sent down by the host which is different from the actual
 *    benchmark primitive mix.
 */

#include "ee_bench.h"

/* These make the verification messages more clear. */
static char *ee_ecdh_group_names[] = { "p256r1", "p384", "x25519", "ed25519" };
static char *ee_rsa_id_names[]     = { "rsa2048", "rsa3072", "rsa4096" };
/**
 * @brief This is a bit of a kludge so that we can avoid confusing the host
 * with hundreds of unused timestamps during autotuning.
 */
extern bool g_mute_timestamps;

/* Compute `i` for one second of execution, then go from there */
#define AUTOTUNE(FUNC)                                    \
    if (i == 0)                                           \
    {                                                     \
        bool mute         = g_mute_timestamps;            \
        g_mute_timestamps = true;                         \
        dt                = 0;                            \
        i                 = 1;                            \
        while (dt < 1e6)                                  \
        {                                                 \
            i = i * 2;                                    \
            FUNC;                                         \
        }                                                 \
        g_mute_timestamps = mute;                         \
        float scale       = 11e6f / (float)dt;            \
        i                 = (uint32_t)((float)i * scale); \
        i                 = i < 10 ? 10 : i;              \
    }                                                     \
    FUNC;

/* There will not be an endian value that should exceed this, so be safe. */
#define CHECK_RANGE(X)                                                      \
    if ((X) > 0x800000)                                                     \
    {                                                                       \
        th_printf("e-[Possible incorrect endian configuration: %08lx]\r\n", \
                  X);                                                       \
        return;                                                             \
    }

void
ee_bench_sha(ee_sha_size_t      size,
             uint32_t           i,
             bool               verify,
             ee_bench_result_t *res)
{
    uint32_t *p32    = NULL;
    uint8_t  *p8     = NULL;
    void     *p_msgs = NULL;
    uint32_t  nmsgs  = 0;
    uint32_t  msglen = 0;
    uint32_t  dt     = 0;
    size_t    x      = 0;

    p32 = (uint32_t *)th_buffer_address();
    CHECK_RANGE(nmsgs = EE_FIX_ENDIAN(*p32++));
    p_msgs = (void *)p32;
    /* Fix the endian-ness of all the message lengths from the host */
    for (p32 = (uint32_t *)p_msgs, x = 0; x < nmsgs; ++x)
    {
        CHECK_RANGE(msglen = EE_FIX_ENDIAN(*p32));
        *p32++ = msglen;
        p8     = ((uint8_t *)p32 + msglen);
        p32    = (uint32_t *)p8;
    }
    AUTOTUNE(dt = ee_sha(size, nmsgs, p_msgs, i));
    if (verify)
    {
        th_printf("m-bench-prim[digest]-alg[sha]-size[%d]\r\n", size);
        for (p32 = (uint32_t *)p_msgs, x = 0; x < nmsgs; ++x)
        {
            msglen = *p32++;
            p8     = (uint8_t *)p32;
            th_printf("m-bench-msg%d[", x);
            ee_hextotxt(p8, msglen);
            th_printf("]\r\n");
            p8  = p8 + msglen;
            p32 = (uint32_t *)p8;
        }
        th_printf("m-bench-out[");
        ee_hextotxt(p8, size / 8);
        th_printf("]\r\n");
    }
    res->iter = i;
    res->dt   = dt;
}

void
ee_bench_cipher(ee_cipher_t        cipher,
                ee_cipher_func_t   func,
                uint32_t           i,
                bool               verify,
                ee_bench_result_t *res)
{
    uint32_t *p32    = NULL;
    uint8_t  *p8     = NULL;
    uint32_t  keylen = 0;
    uint8_t  *p_key  = NULL;
    uint32_t  ivlen  = 0;
    uint8_t  *p_iv   = NULL;
    uint32_t  count  = 0;
    void     *p_msgs = NULL;
    uint32_t  msglen = 0;
    uint32_t  taglen = 0;
    uint32_t  dt     = 0;
    size_t    x      = 0;

    taglen = (cipher == EE_CIPHER_CHACHAPOLY) ? EE_CHACHAPOLY_TAGLEN
                                              : EE_AES_TAGLEN;

    p32 = (uint32_t *)th_buffer_address();
    CHECK_RANGE(keylen = EE_FIX_ENDIAN(*p32++));
    CHECK_RANGE(ivlen = EE_FIX_ENDIAN(*p32++));
    CHECK_RANGE(count = EE_FIX_ENDIAN(*p32++));
    /* Switch to a byte pointer for the key and IV data */
    p8    = (uint8_t *)p32;
    p_key = p8;
    p8    = p8 + keylen;
    p_iv  = p8;
    p8    = p8 + ivlen;
    /* Switch back to a 32-bit pointer for setting up the message list */
    p32 = (uint32_t *)p8;
    /* Save where we are as the start of the message list */
    p_msgs = (void *)p32;
    /* Fix the endian-ness of all the message lengths from the host */
    for (p32 = (uint32_t *)p_msgs, x = 0; x < count; ++x)
    {
        CHECK_RANGE(msglen = EE_FIX_ENDIAN(*p32));
        *p32++ = msglen;
        p8     = (uint8_t *)p32;
        /* Skip to next operation block (input + output + tag) */
        p8  = p8 + (msglen + msglen + taglen);
        p32 = (uint32_t *)p8;
    }
    if (cipher != EE_CIPHER_CHACHAPOLY)
    {
        /* Generally bad form but the enums overlap; prevent compiler warns */
        ee_aes_mode_t m = (ee_aes_mode_t)cipher;
        ee_aes_func_t f = (ee_aes_func_t)func;
        AUTOTUNE(dt = ee_aes(m, f, p_key, keylen, p_iv, count, p_msgs, i));
    }
    else
    {
        ee_chachapoly_func_t f = (ee_chachapoly_func_t)func;
        AUTOTUNE(dt = ee_chachapoly(f, p_key, p_iv, count, p_msgs, i));
    }
    if (verify)
    {
        th_printf("m-bench-prim[cipher]-alg[%s]-size[%d]-func[%s]\r\n",
                  (cipher == EE_CIPHER_AES_ECB)   ? "ecb"
                  : (cipher == EE_CIPHER_AES_CTR) ? "ctr"
                  : (cipher == EE_CIPHER_AES_GCM) ? "gcm"
                  : (cipher == EE_CIPHER_AES_CCM) ? "ccm"
                                                  : "ccp",
                  keylen * 8,
                  (func == EE_CIPHER_FUNC_ENC) ? "enc" : "dec");
        th_printf("m-bench-key[");
        ee_hextotxt(p_key, keylen);
        th_printf("]\r\n");
        if (cipher != EE_CIPHER_AES_ECB)
        {
            th_printf("m-bench-iv[");
            ee_hextotxt(p_iv, ivlen);
            th_printf("]\r\n");
        }
        for (p32 = (uint32_t *)p_msgs, x = 0; x < count; ++x)
        {
            msglen = *p32++;
            p8     = (uint8_t *)p32;
            th_printf("m-bench-in%d[", x);
            ee_hextotxt(p8, msglen);
            th_printf("]\r\n");
            p8 = p8 + msglen;
            th_printf("m-bench-out%d[", x);
            ee_hextotxt(p8, msglen);
            th_printf("]\r\n");
            p8 = p8 + msglen;
            if ((cipher != EE_CIPHER_AES_ECB) && (cipher != EE_CIPHER_AES_CTR))
            {
                th_printf("m-bench-tag%d[", x);
                ee_hextotxt(p8, EE_AES_TAGLEN);
                th_printf("]\r\n");
            }
            p8  = p8 + taglen;
            p32 = (uint32_t *)p8;
        }
    }
    res->iter = i;
    res->dt   = dt;
}

static uint32_t
ee_core_ecdh(ee_ecc_group_t g,
             uint8_t       *p_peer,
             uint32_t       peerlen,
             uint8_t       *p_secret,
             uint32_t      *p_seclen,
             /* Provide this so that the host can check the computation */
             uint8_t  *p_mypubkey,
             uint32_t *p_mypublen,
             uint32_t  i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_ecdh_create(&p_context, g);
    th_printf("m-ecdh-%s-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdh-%s-start\r\n", ee_ecdh_group_names[g]);
    t0 = th_timestamp();
    th_pre();
    do
    {
        /* 2022-10-19: Moved peer-load into loop to prevent cheating. */
        ret = th_ecdh_set_peer_public_key(p_context, p_peer, peerlen);
        if (ret != EE_STATUS_OK)
        {
            break;
        }
        ret = th_ecdh_calc_secret(p_context, p_secret, p_seclen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-ecdh-%s-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdh_get_public_key(p_context, p_mypubkey, p_mypublen);
    th_ecdh_destroy(p_context);
    return t1 - t0;
}

void
ee_bench_ecdh(ee_ecc_group_t g, uint32_t i, bool verify, ee_bench_result_t *res)
{
    uint32_t *p_publen  = NULL;
    uint8_t  *p_pub     = NULL;
    uint32_t *p_seclen  = NULL;
    uint8_t  *p_sec     = NULL;
    uint32_t  dt        = 0;
    uint32_t  dutpublen = 256;
    uint8_t  *p_dutpub  = NULL;

    p_publen = (uint32_t *)th_buffer_address();
    CHECK_RANGE(*p_publen = EE_FIX_ENDIAN(*p_publen));
    p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    p_seclen = (uint32_t *)(p_pub + *p_publen);
    CHECK_RANGE(*p_seclen = EE_FIX_ENDIAN(*p_seclen));
    p_sec    = (uint8_t *)p_seclen + sizeof(uint32_t);
    p_dutpub = p_sec + *p_seclen;
    AUTOTUNE(
        dt = ee_core_ecdh(
            g, p_pub, *p_publen, p_sec, p_seclen, p_dutpub, &dutpublen, i));
    if (verify)
    {
        th_printf("m-bench-prim[exchange]-group[%s]-publen[%d]\r\n",
                  ee_ecdh_group_names[g],
                  dutpublen);
        th_printf("m-bench-pub[");
        ee_hextotxt(p_dutpub, dutpublen);
        th_printf("]\r\n");
        th_printf("m-bench-sec[");
        ee_hextotxt(p_sec, *p_seclen);
        th_printf("]\r\n");
    }
    res->iter = i;
    res->dt   = dt;
}

static uint32_t
ee_core_ecdsa_sign(ee_ecc_group_t g,
                   uint8_t       *p_msg,
                   uint32_t       msglen,
                   uint8_t       *p_sig,
                   uint32_t      *p_siglen,
                   /* Provide this so that the host can check the computation */
                   uint8_t  *p_pub,
                   uint32_t *p_publen,
                   uint32_t  i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_ecdsa_create(&p_context, g);
    th_printf("m-ecdsa-%s-sign-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdsa-%s-sign-start\r\n", ee_ecdh_group_names[g]);
    t0 = th_timestamp();
    th_pre();
    do
    {
        /* reset siglen back to maximum each round since sigs vary in size */
        *p_siglen = 256;
        ret       = th_ecdsa_sign(p_context, p_msg, msglen, p_sig, p_siglen);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-ecdsa-%s-sign-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdsa_get_public_key(p_context, p_pub, p_publen);
    th_ecdsa_destroy(p_context);
    return t1 - t0;
}

void
ee_bench_ecdsa_sign(ee_ecc_group_t     g,
                    uint32_t           i,
                    bool               verify,
                    ee_bench_result_t *res)
{
    uint32_t  dt       = 0;
    uint32_t *p_msglen = NULL;
    uint8_t  *p_msg    = NULL;
    uint8_t  *p_pub    = NULL;
    uint8_t  *p_sig    = NULL;
    /* Sig will be ASN.1 so this may vary, init with some reasonable values. */
    uint32_t publen = 256;
    uint32_t siglen = 256;

    p_msglen = (uint32_t *)th_buffer_address();
    CHECK_RANGE(*p_msglen = EE_FIX_ENDIAN(*p_msglen));
    p_msg = th_buffer_address() + 4 /* sizeof(uint32_t) = msglen */;
    p_pub = p_msg + *p_msglen;
    p_sig = p_pub + publen;
    AUTOTUNE(dt = ee_core_ecdsa_sign(
                 g, p_msg, *p_msglen, p_sig, &siglen, p_pub, &publen, i));
    if (verify)
    {
        th_printf("m-bench-prim[sign]-group[%s]-siglen[%d]-publen[%d]\r\n",
                  ee_ecdh_group_names[g],
                  siglen,
                  publen);
        th_printf("m-bench-msg[");
        ee_hextotxt(p_msg, *p_msglen);
        th_printf("]\r\n");
        th_printf("m-bench-sig[");
        ee_hextotxt(p_sig, siglen);
        th_printf("]\r\n");
        th_printf("m-bench-pub[");
        ee_hextotxt(p_pub, publen);
        th_printf("]\r\n");
    }
    res->iter = i;
    res->dt   = dt;
}

static uint32_t
ee_core_ecdsa_verify(ee_ecc_group_t g,
                     uint8_t       *p_pub,
                     uint32_t       publen,
                     uint8_t       *p_msg,
                     uint32_t       msglen,
                     uint8_t       *p_sig,
                     uint32_t       siglen,
                     bool          *p_pass,
                     uint32_t       i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_ecdsa_create(&p_context, g);
    th_ecdsa_set_public_key(p_context, p_pub, publen);
    th_printf("m-ecdsa-%s-verify-iter[%d]\r\n", ee_ecdh_group_names[g], i);
    th_printf("m-ecdsa-%s-verify-start\r\n", ee_ecdh_group_names[g]);
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_ecdsa_verify(p_context, p_msg, msglen, p_sig, siglen, p_pass);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-ecdsa-%s-verify-finish\r\n", ee_ecdh_group_names[g]);
    th_ecdsa_destroy(p_context);
    return t1 - t0;
}

static uint32_t
ee_core_rsa_verify(ee_rsa_id_t id,
                   uint8_t    *p_pub,
                   uint32_t    publen,
                   uint8_t    *p_msg,
                   uint32_t    msglen,
                   uint8_t    *p_sig,
                   uint32_t    siglen,
                   bool       *p_pass,
                   uint32_t    i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_rsa_create(&p_context);
    th_rsa_set_public_key(p_context, p_pub, publen);
    th_printf("m-%s-verify-iter[%d]\r\n", ee_rsa_id_names[id], i);
    th_printf("m-%s-verify-start\r\n", ee_rsa_id_names[id]);
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_rsa_verify(p_context, p_msg, msglen, p_sig, siglen, p_pass);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-%s-verify-finish\r\n", ee_rsa_id_names[id]);
    th_rsa_destroy(p_context);
    return t1 - t0;
}

void
ee_bench_verify(ee_dsa_alg_t       alg,
                uint32_t           i,
                bool               verify,
                ee_bench_result_t *res)
{
    uint32_t *p_msglen = NULL;
    uint8_t  *p_msg    = NULL;
    uint32_t *p_publen = NULL;
    uint8_t  *p_pub    = NULL;
    uint32_t *p_siglen = NULL;
    uint8_t  *p_sig    = NULL;
    uint32_t  dt       = 0;
    uint8_t  *p_pass   = NULL;

    p_msglen = (uint32_t *)th_buffer_address();
    CHECK_RANGE(*p_msglen = EE_FIX_ENDIAN(*p_msglen));
    p_msg    = th_buffer_address() + 4 /* msglen is 32b */;
    p_publen = (uint32_t *)(p_msg + *p_msglen);
    CHECK_RANGE(*p_publen = EE_FIX_ENDIAN(*p_publen));
    p_pub    = (uint8_t *)p_publen + sizeof(uint32_t);
    p_siglen = (uint32_t *)(p_pub + *p_publen);
    CHECK_RANGE(*p_siglen = EE_FIX_ENDIAN(*p_siglen));
    p_sig  = (uint8_t *)p_siglen + sizeof(uint32_t);
    p_pass = p_sig + *p_siglen;
    if (alg < EE_DSA_ALG_RSA2048)
    {
        ee_ecc_group_t g = (ee_ecc_group_t)alg; /* See notes in enum above */
        AUTOTUNE(dt = ee_core_ecdsa_verify(g,
                                           p_pub,
                                           *p_publen,
                                           p_msg,
                                           *p_msglen,
                                           p_sig,
                                           *p_siglen,
                                           (bool *)p_pass,
                                           i));
    }
    else
    {
        /* See notes in enum above regarding math */
        ee_rsa_id_t id = (ee_rsa_id_t)alg - (ee_rsa_id_t)EE_DSA_ALG_RSA2048;
        AUTOTUNE(dt = ee_core_rsa_verify(id,
                                         p_pub,
                                         *p_publen,
                                         p_msg,
                                         *p_msglen,
                                         p_sig,
                                         *p_siglen,
                                         (bool *)p_pass,
                                         i));
    }
    if (verify)
    {
        if (alg < EE_DSA_ALG_RSA2048)
        {
            th_printf(
                "m-bench-prim[verify]-group[%s]-siglen[%d]-publen[%d]\r\n",
                ee_ecdh_group_names[alg],
                *p_siglen,
                *p_publen);
        }
        else
        {
            th_printf(
                "m-bench-prim[verify]-group[rsa]-siglen[%d]-publen[%d]\r\n",
                *p_siglen,
                *p_publen);
        }
        th_printf("m-bench-msg[");
        ee_hextotxt(p_msg, *p_msglen);
        th_printf("]\r\n");
        th_printf("m-bench-pub[");
        ee_hextotxt(p_pub, *p_publen);
        th_printf("]\r\n");
        th_printf("m-bench-sig[");
        ee_hextotxt(p_sig, *p_siglen);
        th_printf("]\r\n");
        th_printf("m-bench-pass[%d]\r\n", *p_pass);
    }
    res->iter = i;
    res->dt   = dt;
}

static uint32_t
ee_core_entropy_latency(uint32_t i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_rng_create(&p_context);
    th_printf("m-entropy_latency-iter[%d]\r\n", i);
    th_printf("m-entropy_latency-start\r\n");
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_rng_generate_entropy(p_context);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-entropy_latency-finish\r\n");
    th_rng_destroy(p_context);
    return t1 - t0;
}

void
ee_bench_var01(uint32_t i, ee_bench_result_t *res)
{
    uint32_t dt = 0;
    AUTOTUNE(dt = ee_variation_001(i));
    res->iter = i;
    res->dt   = dt;
}

void
ee_bench_entropy_latency(uint32_t i, ee_bench_result_t *res)
{
    uint32_t dt = 0;
    AUTOTUNE(dt = ee_core_entropy_latency(i));
    res->iter = i;
    res->dt   = dt;
}

static uint32_t
ee_core_drbg_throughput(uint8_t *p_bytes, uint32_t n, uint32_t i)
{
    ee_status_t ret       = EE_STATUS_OK;
    void       *p_context = NULL;
    uint32_t    t0        = 0;
    uint32_t    t1        = 0;

    th_rng_create(&p_context);
    th_printf("m-drbg_throughput-iter[%d]\r\n", i);
    th_printf("m-drbg_throughput-start\r\n");
    t0 = th_timestamp();
    th_pre();
    do
    {
        ret = th_rng_drbg_getbits(p_context, p_bytes, n);
    } while (--i > 0 && ret == EE_STATUS_OK);
    th_post();
    t1 = th_timestamp();
    th_printf("m-drbg_throughput-finish\r\n");
    th_rng_destroy(p_context);
    return t1 - t0;
}

void
ee_bench_drbg_throughput(uint32_t i, bool verify, ee_bench_result_t *res)
{
    uint32_t  dt         = 0;
    uint32_t *p_numbytes = NULL;
    uint8_t  *p_bytes    = NULL;

    p_numbytes = (uint32_t *)th_buffer_address();
    CHECK_RANGE(*p_numbytes = EE_FIX_ENDIAN(*p_numbytes));
    p_bytes = (uint8_t *)p_numbytes + 4;
    if ((4 + *p_numbytes) > th_buffer_size())
    {
        th_printf("e-[Generic buffer size exceeded! (%d bytes)]\r\n",
                  th_buffer_size());
        return;
    }
    AUTOTUNE(dt = ee_core_drbg_throughput(p_bytes, *p_numbytes, i));
    if (verify)
    {
        th_printf("m-bench-rng[");
        ee_hextotxt(p_bytes, *p_numbytes);
        th_printf("]\r\n");
    }
    res->iter = i;
    res->dt   = dt;
}

arg_claimed_t
ee_bench_parse(char *p_command, bool verify)
{
    char             *p_subcmd;
    char             *p_iter;
    ee_bench_result_t res;
    uint32_t          i;

    if (th_strncmp(p_command, "bench", EE_CMD_SIZE) != 0)
    {
        return EE_ARG_UNCLAIMED;
    }
    /**
     * The `bench` command takes two paramters:
     * subcmd : the name of the primitive to benchmark
     * iter   : the decimal positive integer iteration count
     */
    p_subcmd = th_strtok(NULL, EE_CMD_DELIMITER);
    p_iter   = th_strtok(NULL, EE_CMD_DELIMITER);
    if (p_subcmd == NULL)
    {
        th_printf("e-[Command 'bench' takes a subcommand]\r\n");
        return EE_ARG_CLAIMED;
    }
    if (p_iter)
    {
        i = (uint32_t)th_atoi(p_iter);
        /* i = 0 means autotune to 10sec/10iter */
    }
    else
    {
        th_printf("e-[Benchmark iterations not specified]\r\n");
        return EE_ARG_CLAIMED;
    }
    if (th_strncmp(p_subcmd, "sha256", EE_CMD_SIZE) == 0)
    {
        ee_bench_sha(EE_SHA256, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "sha384", EE_CMD_SIZE) == 0)
    {
        ee_bench_sha(EE_SHA384, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_ECB, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_ECB, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CTR, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CTR, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CCM, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CCM, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_GCM, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes128-gcm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_GCM, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_ECB, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ecb-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_ECB, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CTR, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ctr-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CTR, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CCM, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-ccm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_CCM, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-gcm-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_GCM, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "aes256-gcm-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(EE_CIPHER_AES_GCM, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-enc", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(
            EE_CIPHER_CHACHAPOLY, EE_CIPHER_FUNC_ENC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "chachapoly-dec", EE_CMD_SIZE) == 0)
    {
        ee_bench_cipher(
            EE_CIPHER_CHACHAPOLY, EE_CIPHER_FUNC_DEC, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdh-p256", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_ECC_GROUP_P256R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdh-p384", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_ECC_GROUP_P384R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdh-x25519", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdh(EE_ECC_GROUP_C25519, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p256-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_ECC_GROUP_P256R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p256-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_ECDSA_P256R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_ECC_GROUP_P384R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-p384-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_ECDSA_P384R1, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-sign", EE_CMD_SIZE) == 0)
    {
        ee_bench_ecdsa_sign(EE_ECC_GROUP_ED25519, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "ecdsa-ed25519-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_ED25519, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "rsa2048-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_RSA2048, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "rsa3072-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_RSA3072, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "rsa4096-verify", EE_CMD_SIZE) == 0)
    {
        ee_bench_verify(EE_DSA_ALG_RSA4096, i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "entropy_latency", EE_CMD_SIZE) == 0)
    {
        ee_bench_entropy_latency(i, &res);
    }
    else if (th_strncmp(p_subcmd, "drbg_throughput", EE_CMD_SIZE) == 0)
    {
        ee_bench_drbg_throughput(i, verify, &res);
    }
    else if (th_strncmp(p_subcmd, "var01", EE_CMD_SIZE) == 0)
    {
        ee_bench_var01(i, &res);
    }
    else
    {
        th_printf("e-[Unknown benchmark subcommand: %s]\r\n", p_subcmd);
    }
    return EE_ARG_CLAIMED;
}
