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

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "ee_rng.h"

ee_status_t
th_rng_create(void **pp_context)
{
    int ret = 0;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    char *personalization = "Tempus unum hominem manet.";

    mbedtls_ctr_drbg_context *ptr = (mbedtls_ctr_drbg_context *)th_malloc(
        sizeof(mbedtls_ctr_drbg_context));

    if (NULL == ptr)
    {
        th_printf("e-[th_rng_create: Malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    mbedtls_ctr_drbg_init(ptr);
    ret = mbedtls_ctr_drbg_seed(ptr,
                                mbedtls_entropy_func,
                                &entropy,
                                (const unsigned char *)personalization,
                                strlen(personalization));
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ctr_drbg_seed: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    *pp_context = ptr;
    return EE_STATUS_OK;
}

ee_status_t
th_rng_generate_entropy(void *p_context)
{
    mbedtls_ctr_drbg_context *p_ctx = (mbedtls_ctr_drbg_context *)p_context;
    int                       ret   = 0;

    ret = mbedtls_ctr_drbg_reseed(p_ctx, NULL, 0);

    if (ret != 0)
    {
        th_printf("e-[mbedtls_ctr_drbg_reseed: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_rng_drbg_getbits(void *p_context, uint8_t *p_bytes, uint32_t numbytes)
{
    mbedtls_ctr_drbg_context *p_ctx = (mbedtls_ctr_drbg_context *)p_context;
    int                       ret   = 0;

    ret = mbedtls_ctr_drbg_random(p_ctx, p_bytes, numbytes);

    if (ret != 0)
    {
        th_printf("e-[mbedtls_ctr_drbg_random: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rng_destroy(void *p_context)
{
    mbedtls_ctr_drbg_context *p_ctx = (mbedtls_ctr_drbg_context *)p_context;
    mbedtls_ctr_drbg_free(p_ctx);
    return EE_STATUS_OK;
}
