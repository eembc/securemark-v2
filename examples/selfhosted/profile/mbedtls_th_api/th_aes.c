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
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/gcm.h"
#include "ee_aes.h"

#define CHECK_NULL_CTX(PCTX)                                     \
    if (NULL == PCTX)                                                        \
    {                                                                        \
        th_printf("e-[NULL pointer caught, %s:%d]\r\n", __FILE__, __LINE__); \
        return EE_STATUS_ERROR;                                          \
    }

#define CHECK_NULL_CTX_NORET(PCTX)                                     \
    if (NULL == PCTX)                                                        \
    {                                                                        \
        th_printf("e-[NULL pointer caught, %s:%d]\r\n", __FILE__, __LINE__); \
        return;                                                              \
    }


typedef struct
{
    ee_aes_mode_t aes_mode;
    union
    {
        mbedtls_aes_context aes_ctx;
        mbedtls_ccm_context ccm_ctx;
        mbedtls_gcm_context gcm_ctx;
    } ctx;
    union
    {
        struct
        {
            unsigned char nonce_counter[16];
            unsigned char stream_block[16];
            size_t        nc_off;
        } aes_ctr;
    } additional_ctx;
} th_mbedtls_aes_context_t;

ee_status_t
th_aes_create(void **p_context, ee_aes_mode_t mode)
{
    *p_context = (th_mbedtls_aes_context_t *)th_malloc(
        sizeof(th_mbedtls_aes_context_t));
    if (mode == EE_AES_ECB || mode == EE_AES_CTR || mode == EE_AES_CCM
        || mode == EE_AES_GCM)
    {
        ((th_mbedtls_aes_context_t *)(*p_context))->aes_mode = mode;
    }
    else
    {
        th_free(*p_context);
        th_printf("e-[Unknown mode in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    if (*p_context == NULL)
    {
        th_printf("e-[malloc() fail in th_aes128_create]\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_aes_init(void          *p_context,
            const uint8_t *p_key,
            uint32_t       keylen,
            const uint8_t *iv,
            ee_aes_func_t  func,
            ee_aes_mode_t  mode)
{
    (void)iv;
    int                  ret;
    int                  keybits;
    mbedtls_aes_context *p_ecb;
    mbedtls_ccm_context *p_ccm;
    mbedtls_gcm_context *p_gcm;

    CHECK_NULL_CTX(p_context);

    keybits = keylen * 8;

    if (mode != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    if (mode == EE_AES_ECB || mode == EE_AES_CTR)
    {
        p_ecb = &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx;
        mbedtls_aes_init(p_ecb);
        if (func == EE_AES_ENC)
        {
            ret = mbedtls_aes_setkey_enc(p_ecb, p_key, keybits);
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB ENC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        else if (func == EE_AES_DEC)
        {
            if (mode == EE_AES_CTR)
            {
                ret = mbedtls_aes_setkey_enc(p_ecb, p_key, keybits);
            }
            else
            {
                ret = mbedtls_aes_setkey_dec(p_ecb, p_key, keybits);
            }
            if (ret != 0)
            {
                th_printf("e-[Failed to set ECB DEC key: -0x%04x]\r\n", -ret);
                return EE_STATUS_ERROR;
            }
        }
        if (mode == EE_AES_CTR)
        {
            th_memcpy(((th_mbedtls_aes_context_t *)p_context)
                          ->additional_ctx.aes_ctr.nonce_counter,
                      iv,
                      EE_AES_CTR_IVLEN);
            th_memset(((th_mbedtls_aes_context_t *)p_context)
                          ->additional_ctx.aes_ctr.stream_block,
                      0,
                      16);
            ((th_mbedtls_aes_context_t *)p_context)
                ->additional_ctx.aes_ctr.nc_off
                = 0;
        }
    }
    else if (mode == EE_AES_CCM)
    {
        p_ccm = &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx;
        mbedtls_ccm_init(p_ccm);
        ret = mbedtls_ccm_setkey(p_ccm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set CCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else if (mode == EE_AES_GCM)
    {
        p_gcm = &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx;
        mbedtls_gcm_init(p_gcm);
        ret = mbedtls_gcm_setkey(p_gcm, MBEDTLS_CIPHER_ID_AES, p_key, keybits);
        if (ret != 0)
        {
            th_printf("e-[Failed to set GCM key: -0x%04x]\r\n", -ret);
            return EE_STATUS_ERROR;
        }
    }
    else
    {
        th_printf("e-[Unknown mode in th_aes128_init]\r\n");
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

void
th_aes_deinit(void *p_context)
{
    CHECK_NULL_CTX_NORET(p_context);

    if (EE_AES_CCM == ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        mbedtls_ccm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx);
    }
    else if (EE_AES_GCM == ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        mbedtls_gcm_free(&((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx);
    }
}

ee_status_t
th_aes_ecb_encrypt(void          *p_context,
                   const uint8_t *p_pt,
                   uint32_t       ptlen,
                   uint8_t       *p_ct)
{
    int            ret;
    uint32_t       numblocks = ptlen >> 4;
    const uint8_t *in        = p_pt;
    uint8_t       *out       = p_ct;

    CHECK_NULL_CTX(p_context);

    if (EE_AES_ECB != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    for (uint32_t i = 0; i < numblocks; ++i)
    {
        ret = mbedtls_aes_crypt_ecb(
            &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
            MBEDTLS_AES_ENCRYPT,
            p_pt,
            p_ct);
        if (ret != 0)
        {
            th_printf("e-[mbedtls_aes_crypt_ecb: %d]\r\n", ret);
            return EE_STATUS_ERROR;
        }
        in += 16;
        out += 16;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ecb_decrypt(void          *p_context,
                   const uint8_t *p_ct,
                   uint32_t       ctlen,
                   uint8_t       *p_pt)
{
    int            ret;
    uint32_t       numblocks = ctlen / 16;
    const uint8_t *in        = p_ct;
    uint8_t       *out       = p_pt;
    for (uint32_t i = 0; i < numblocks; ++i)
    {
        ret = mbedtls_aes_crypt_ecb(
            &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
            MBEDTLS_AES_DECRYPT,
            p_ct,
            p_pt);
        if (ret != 0)
        {
            th_printf("e-[mbedtls_aes_crypt_ecb: %d]\r\n", ret);
            return EE_STATUS_ERROR;
        }
        in += 16;
        out += 16;
    }
    return EE_STATUS_OK;
}

ee_status_t
th_aes_ctr_encrypt(void          *p_context,
                   const uint8_t *p_pt,
                   uint32_t       ptlen,
                   uint8_t       *p_ct)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_CTR != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ctr(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
               ptlen,
               &((th_mbedtls_aes_context_t *)p_context)
                    ->additional_ctx.aes_ctr.nc_off,
               ((th_mbedtls_aes_context_t *)p_context)
                   ->additional_ctx.aes_ctr.nonce_counter,
               ((th_mbedtls_aes_context_t *)p_context)
                   ->additional_ctx.aes_ctr.stream_block,
               p_pt,
               p_ct)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_aes_ctr_decrypt(void          *p_context,
                   const uint8_t *p_ct,
                   uint32_t       ctlen,
                   uint8_t       *p_pt)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_CTR != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_aes_crypt_ctr(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.aes_ctx,
               ctlen,
               &((th_mbedtls_aes_context_t *)p_context)
                    ->additional_ctx.aes_ctr.nc_off,
               ((th_mbedtls_aes_context_t *)p_context)
                   ->additional_ctx.aes_ctr.nonce_counter,
               ((th_mbedtls_aes_context_t *)p_context)
                   ->additional_ctx.aes_ctr.stream_block,
               p_ct,
               p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_aes_ccm_encrypt(void          *p_context,
                   const uint8_t *p_pt,
                   uint32_t       ptlen,
                   uint8_t       *p_ct,
                   uint8_t       *p_tag,
                   uint32_t       taglen,
                   const uint8_t *p_iv,
                   uint32_t       ivlen)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_CCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_ccm_encrypt_and_tag(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx,
               ptlen,
               p_iv,
               ivlen,
               NULL,
               0,
               p_pt,
               p_ct,
               p_tag,
               taglen)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform a CCM decrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_ccm_decrypt(void          *p_context,
                   const uint8_t *p_ct,
                   uint32_t       ctlen,
                   uint8_t       *p_pt,
                   const uint8_t *p_tag,
                   uint32_t       taglen,
                   const uint8_t *p_iv,
                   uint32_t       ivlen)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_CCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_ccm_auth_decrypt(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.ccm_ctx,
               ctlen,
               p_iv,
               ivlen,
               NULL,
               0,
               p_ct,
               p_pt,
               p_tag,
               taglen)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

/**
 * Perform an AES/GCM encrypt.
 *
 * Return EE_STATUS_OK or EE_STATUS_ERROR.
 */
ee_status_t
th_aes_gcm_encrypt(void          *p_context,
                   const uint8_t *p_pt,
                   uint32_t       ptlen,
                   uint8_t       *p_ct,
                   uint8_t       *p_tag,
                   uint32_t       taglen,
                   const uint8_t *p_iv,
                   uint32_t       ivlen)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_GCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_gcm_crypt_and_tag(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx,
               MBEDTLS_GCM_ENCRYPT,
               ptlen,
               p_iv,
               ivlen,
               NULL,
               0,
               p_pt,
               p_ct,
               taglen,
               p_tag)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

ee_status_t
th_aes_gcm_decrypt(void          *p_context,
                   const uint8_t *p_ct,
                   uint32_t       ctlen,
                   uint8_t       *p_pt,
                   const uint8_t *p_tag,
                   uint32_t       taglen,
                   const uint8_t *p_iv,
                   uint32_t       ivlen)
{
    CHECK_NULL_CTX(p_context);

    if (EE_AES_GCM != ((th_mbedtls_aes_context_t *)p_context)->aes_mode)
    {
        return EE_STATUS_ERROR;
    }

    return mbedtls_gcm_auth_decrypt(
               &((th_mbedtls_aes_context_t *)p_context)->ctx.gcm_ctx,
               ctlen,
               p_iv,
               ivlen,
               NULL,
               0,
               p_tag,
               taglen,
               p_ct,
               p_pt)
                   == 0
               ? EE_STATUS_OK
               : EE_STATUS_ERROR;
}

void
th_aes_destroy(void *p_context)
{
    CHECK_NULL_CTX_NORET(p_context);

    th_mbedtls_aes_context_t *p_ctx = (th_mbedtls_aes_context_t *)p_context;

    if (p_ctx->aes_mode == EE_AES_CCM || p_ctx->aes_mode == EE_AES_CTR)
    {
        mbedtls_aes_free(&(p_ctx->ctx.aes_ctx));
    }
    else if (p_ctx->aes_mode == EE_AES_CCM)
    {
        mbedtls_ccm_free(&(p_ctx->ctx.ccm_ctx));
    }
    else if (p_ctx->aes_mode == EE_AES_GCM)
    {
        mbedtls_gcm_free(&(p_ctx->ctx.gcm_ctx));
    }
    th_free(p_context);
}
