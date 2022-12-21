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

#include "mbedtls/chachapoly.h"
#include "ee_chachapoly.h"

ee_status_t
th_chachapoly_create(void **pp_context)
{
    *pp_context = (mbedtls_chachapoly_context *)th_malloc(
        sizeof(mbedtls_chachapoly_context));
    return EE_STATUS_OK;
}

ee_status_t
th_chachapoly_init(void *p_context, const uint8_t *p_key, uint32_t keylen)
{

    int                         ret;
    mbedtls_chachapoly_context *context
        = (mbedtls_chachapoly_context *)p_context;
    mbedtls_chachapoly_init(context);
    ret = mbedtls_chachapoly_setkey(p_context, p_key);
    if (ret != 0)
    {
        th_printf("e-[mbedtls failed to set ChaChaPoly key: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

void
th_chachapoly_deinit(void *p_context)
{

    mbedtls_chachapoly_free((mbedtls_chachapoly_context *)p_context);
}

ee_status_t
th_chachapoly_encrypt(void          *p_context,
                      const uint8_t *p_pt,
                      uint32_t       ptlen,
                      uint8_t       *p_ct,
                      uint8_t       *p_tag,
                      uint32_t       taglen,
                      uint8_t       *p_iv,
                      uint32_t       ivlen)
{
    return mbedtls_chachapoly_encrypt_and_tag(
               (mbedtls_chachapoly_context *)p_context,
               ptlen,
               p_iv,
               NULL,
               0,
               p_pt,
               p_ct,
               p_tag)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_chachapoly_decrypt(void          *p_context,
                      const uint8_t *p_ct,
                      uint32_t       ctlen,
                      uint8_t       *p_pt,
                      uint8_t       *p_tag,
                      uint32_t       taglen,
                      uint8_t       *p_iv,
                      uint32_t       ivlen)
{
    return mbedtls_chachapoly_auth_decrypt(
               (mbedtls_chachapoly_context *)p_context,
               ctlen,
               p_iv,
               NULL,
               0,
               p_tag,
               p_ct,
               p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

void
th_chachapoly_destroy(void *p_context)
{
    mbedtls_chachapoly_free((mbedtls_chachapoly_context *)p_context);
    th_free(p_context);
}
