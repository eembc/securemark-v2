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
#include "mbedtls/ecdsa.h"
#include "ee_ecdsa.h"
#include "th_util.h"

typedef struct
{
    mbedtls_ecp_group_id  group;
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_ecp_keypair   our_key;
} th_mbedtls_ecdsa_t;

ee_status_t
th_ecdsa_create(void **pp_context, ee_ecc_group_t group)
{
    th_mbedtls_ecdsa_t  *p_ecdsa;
    mbedtls_ecp_group_id group_id;
    int                  result;

    switch (group)
    {
        case EE_ECC_GROUP_P256R1:
            group_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case EE_ECC_GROUP_P384R1:
            group_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        default:
            th_printf("e-[unsupported curve in th_ecdsa_create]\r\n");
            return EE_STATUS_ERROR;
    }

    p_ecdsa = (th_mbedtls_ecdsa_t *)th_malloc(sizeof(th_mbedtls_ecdsa_t));
    if (p_ecdsa == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdsa_create]\r\n");
        return EE_STATUS_ERROR;
    }

    mbedtls_ecp_keypair_init(&p_ecdsa->our_key);
    result = mbedtls_ecp_gen_key(
        group_id, &p_ecdsa->our_key, mbedtls_fake_random, NULL);

    if (result != 0)
    {
        th_printf("e-[cannot create key in th_ecdsa_create]\r\n");
        mbedtls_ecp_keypair_free(&p_ecdsa->our_key);
        th_free(p_ecdsa);
        return EE_STATUS_ERROR;
    }

    mbedtls_ecdsa_init(&p_ecdsa->ecdsa_ctx);
    result = mbedtls_ecdsa_from_keypair(&p_ecdsa->ecdsa_ctx, &p_ecdsa->our_key);
    if (result != 0)
    {
        th_printf("e-[cannot create key in th_ecdsa_create]\r\n");
        mbedtls_ecdsa_free(&p_ecdsa->ecdsa_ctx);
        mbedtls_ecp_keypair_free(&p_ecdsa->our_key);
        th_free(p_ecdsa);
        return EE_STATUS_ERROR;
    }

    p_ecdsa->group = group_id;

    *pp_context = (void *)p_ecdsa;
    return EE_STATUS_OK;
}

void
th_ecdsa_destroy(void *p_context)
{
    mbedtls_ecp_keypair_free(&((th_mbedtls_ecdsa_t *)p_context)->our_key);
    mbedtls_ecdsa_free(&((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx);
    th_free(p_context);
}

ee_status_t
th_ecdsa_get_public_key(void *p_context, uint8_t *p_out, uint32_t *p_outlen)
{
    mbedtls_ecp_keypair *p_our_key
        = &((th_mbedtls_ecdsa_t *)p_context)->our_key;
    int    ret;
    size_t olen;

    ret = mbedtls_ecp_point_write_binary(&p_our_key->MBEDTLS_PRIVATE(grp),
                                         &p_our_key->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen,
                                         p_out,
                                         *p_outlen);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_point_write_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    *p_outlen = olen;

    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_set_public_key(void *p_context, uint8_t *p_pub, uint32_t publen)
{
    mbedtls_ecdsa_context *p_ecdsa
        = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    mbedtls_ecp_group_id group_id = ((th_mbedtls_ecdsa_t *)p_context)->group;
    int                  ret;
    mbedtls_ecp_keypair  their_key;

    mbedtls_ecp_keypair_init(&their_key);

    ret = mbedtls_ecp_group_load(&their_key.MBEDTLS_PRIVATE(grp), group_id);
    if (ret != 0)
    {
        mbedtls_ecp_keypair_free(&their_key);
        th_printf("e-[mbedtls_ecp_group_load: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecp_point_read_binary(&their_key.MBEDTLS_PRIVATE(grp),
                                        &their_key.MBEDTLS_PRIVATE(Q),
                                        p_pub,
                                        publen);
    if (ret != 0)
    {
        mbedtls_ecp_keypair_free(&their_key);
        th_printf("e-[mbedtls_ecp_point_read_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    ret = mbedtls_ecdsa_from_keypair(p_ecdsa, &their_key);
    mbedtls_ecp_keypair_free(&their_key);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_get_params: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_sign(void     *p_context,
              uint8_t  *p_msg,
              uint32_t  msglen,
              uint8_t  *p_sig,
              uint32_t *p_siglen)
{
    mbedtls_ecdsa_context *p_ecdsa
        = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    mbedtls_ecp_group_id group_id = ((th_mbedtls_ecdsa_t *)p_context)->group;
    mbedtls_md_type_t    md_type;
    int                  result;
    size_t               olen;

    switch (group_id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            md_type = MBEDTLS_MD_SHA256;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            md_type = MBEDTLS_MD_SHA384;
            break;
        default:
            th_printf("e-[Unsupported curve in th_ecdsa_sign]\r\n");
            return EE_STATUS_ERROR;
    }

    result = mbedtls_ecdsa_write_signature(p_ecdsa,
                                           md_type,
                                           p_msg,
                                           msglen,
                                           p_sig,
                                           *p_siglen,
                                           &olen,
                                           mbedtls_fake_random,
                                           NULL);
    if (result != 0)
    {
        th_printf("e-[mbedtls_ecdsa_write_signature: -0x%04x]\r\n", -result);
        return EE_STATUS_ERROR;
    }
    *p_siglen = olen;
    return EE_STATUS_OK;
}

ee_status_t
th_ecdsa_verify(void    *p_context,
                uint8_t *p_msg,
                uint32_t msglen,
                uint8_t *p_sig,
                uint32_t siglen,
                bool    *p_pass)
{
    mbedtls_ecdsa_context *p_ecdsa
        = &((th_mbedtls_ecdsa_t *)p_context)->ecdsa_ctx;
    int res;
    *p_pass = true;

    res = mbedtls_ecdsa_read_signature(p_ecdsa, p_msg, msglen, p_sig, siglen);

    if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED)
    {
        *p_pass = false;
    }
    else if (res != 0)
    {
        th_printf("e-[mbedtls_ecdsa_read_signature: -0x%04x]\r\n", -res);
        return EE_STATUS_ERROR;
    }
    return EE_STATUS_OK;
}
