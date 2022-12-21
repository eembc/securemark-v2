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

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "ee_main.h"

ee_status_t
th_rsa_create(void **pp_context)
{
    mbedtls_pk_context *p_ctx;

    p_ctx = (mbedtls_pk_context *)th_malloc(sizeof(mbedtls_pk_context));
    if (NULL == p_ctx)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        return EE_STATUS_ERROR;
    }
    mbedtls_pk_init(p_ctx);
    *pp_context = p_ctx;
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_set_public_key(void *p_context, const uint8_t *p_pub, uint32_t publen)
{
    mbedtls_pk_context *p_ctx = (mbedtls_pk_context *)p_context;
    int                 ret   = 0;

    ret = mbedtls_pk_parse_public_key(p_ctx, p_pub, publen);

    if (ret != 0)
    {
        th_printf("e-[mbedtls_pk_parse_public_key: %d]\r\n", ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_verify(void    *p_context,
              uint8_t *p_msg,
              uint32_t msglen,
              uint8_t *p_sig,
              uint32_t slen,
              bool    *p_pass)
{
    mbedtls_pk_context *p_ctx = (mbedtls_pk_context *)p_context;
    int                 ret   = 0;

    *p_pass = true;

    ret = mbedtls_pk_verify(p_ctx, MBEDTLS_MD_NONE, p_msg, msglen, p_sig, slen);

    if (ret == MBEDTLS_ERR_RSA_VERIFY_FAILED)
    {
        *p_pass = false;
    }
    else if (ret != 0)
    {
        th_printf("e-[mbedtls_pk_verify: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_destroy(void *p_context)
{
    mbedtls_pk_context *p_ctx = (mbedtls_pk_context *)p_context;
    mbedtls_pk_free(p_ctx);
    return EE_STATUS_OK;
}

#if 0
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

#include "mbedtls/rsa.h"
#include "ee_main.h"

ee_status_t
th_rsa_create(void **pp_context)
{
    mbedtls_rsa_context *p_ctx;
    int ret = 0;

    p_ctx = (mbedtls_rsa_context *)th_malloc(sizeof(mbedtls_rsa_context));
    if (NULL == p_ctx)
    {
        th_printf("e-[th_rsa_create failed to malloc]\r\n");
        return EE_STATUS_ERROR;
    }
    mbedtls_rsa_init(p_ctx);
    *pp_context = p_ctx;
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_set_public_key(void *         p_context,
                      const uint8_t *p_pub,
                      uint32_t  publen)
{
#warning "th_rsa_set_public_key not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_verify(void *        p_context,
              uint8_t *     p_msg,
              uint32_t      msglen,
              uint8_t *     p_sig,
              uint32_t      slen,
              uint8_t *     p_verify)
{
    mbedtls_rsa_context *p_ctx = (mbedtls_rsa_context *)p_context;
    int ret = 0;

    ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(p_ctx,
                                              MBEDTLS_MD_SHA256,
                                              msglen,
                                              p_msg,
                                              p_sig);

    if (ret != 0)
    {
        th_printf("e-[mbedtls_rsa_rsassa_pkcs1_v15_verify -%08x\n", -ret);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_destroy(void *p_context)
{
    mbedtls_rsa_context *p_ctx = (mbedtls_rsa_context *)p_context;
    mbedtls_rsa_free(p_ctx);
    return EE_STATUS_OK;
}
#endif
