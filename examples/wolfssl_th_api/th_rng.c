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

#include "ee_rng.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

/* can be set for static memory use */
#define HEAP_HINT NULL
/* used with crypto callbacks and async */
#define DEVID -1

ee_status_t
th_rng_create(void **pp_context)
{
    int ret = 0;

    *pp_context = (WC_RNG *)th_malloc(sizeof(WC_RNG));

    if (NULL == *pp_context)
    {
        th_printf("e-[th_rng_create: Malloc fail]\r\n");
        return EE_STATUS_ERROR;
    }
    if ((ret = wc_InitRng_ex(*pp_context, HEAP_HINT, DEVID)) != 0)
    {
        th_printf("e-[wc_InitRng_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rng_generate_entropy(void *p_context)
{
    WC_RNG rng;
    int    ret = 0;

    if ((ret = wc_InitRng_ex(&rng, HEAP_HINT, DEVID)) != 0)
    {
        th_printf("e-[wc_InitRng_ex: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    /* We cannot use WOLFSSL_NO_MALLOC due to ECC, so we need to free */
    wc_FreeRng(&rng);

    return EE_STATUS_OK;
}

ee_status_t
th_rng_drbg_getbits(void *p_context, uint8_t *p_bytes, uint32_t numbytes)
{
    WC_RNG *rng = (WC_RNG *)p_context;
    int     ret = 0;

    if ((ret = wc_RNG_GenerateBlock(rng, p_bytes, numbytes)) != 0)
    {
        th_printf("e-[wc_RNG_GenerateBlock: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rng_destroy(void *p_context)
{
    WC_RNG *rng = (WC_RNG *)p_context;
    wc_FreeRng(rng);
    return EE_STATUS_OK;
}
