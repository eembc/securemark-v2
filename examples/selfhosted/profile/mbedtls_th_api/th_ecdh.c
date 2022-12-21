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
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "th_util.h"

#include "ee_ecdh.h"

typedef struct
{
    mbedtls_ecp_group_id group;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ecp_keypair  our_key;
} th_mbedtls_ecdh_t;

ee_status_t
th_ecdh_create(void **p_context, ee_ecc_group_t group)
{
    int                  result = -1;
    mbedtls_ecp_group_id group_id;
    th_mbedtls_ecdh_t   *p_ecdh;

    if (group == EE_ECC_GROUP_P256R1)
    {
        group_id = MBEDTLS_ECP_DP_SECP256R1;
    }
    else if (group == EE_ECC_GROUP_P384R1)
    {
        group_id = MBEDTLS_ECP_DP_SECP384R1;
    }
    else if (group == EE_ECC_GROUP_C25519)
    {
        group_id = MBEDTLS_ECP_DP_CURVE25519;
    }
    else
    {
        th_printf("e-[unsupported curve in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }

    p_ecdh = (th_mbedtls_ecdh_t *)th_malloc(sizeof(th_mbedtls_ecdh_t));
    if (p_ecdh == NULL)
    {
        th_printf("e-[malloc() fail in th_ecdh_create]\r\n");
        return EE_STATUS_ERROR;
    }

    p_ecdh->group = group_id;

    mbedtls_ecdh_init(&p_ecdh->ecdh_ctx);
    result = mbedtls_ecdh_setup(&p_ecdh->ecdh_ctx, p_ecdh->group);

    if (result != 0)
    {
        th_printf("e-[unsupported curve in th_ecdh_create]\r\n");
        mbedtls_ecdh_free(&p_ecdh->ecdh_ctx);
        th_free(p_ecdh);
        return EE_STATUS_ERROR;
    }

    mbedtls_ecp_keypair_init(&p_ecdh->our_key);
    result = mbedtls_ecp_gen_key(
        group_id, &p_ecdh->our_key, mbedtls_fake_random, NULL);

    if (result != 0)
    {
        th_printf("e-[cannot create key in th_ecdh_create]\r\n");
        mbedtls_ecp_keypair_free(&p_ecdh->our_key);
        mbedtls_ecdh_free(&p_ecdh->ecdh_ctx);
        th_free(p_ecdh);
        return EE_STATUS_ERROR;
    }

    result = mbedtls_ecdh_get_params(
        &p_ecdh->ecdh_ctx, &p_ecdh->our_key, MBEDTLS_ECDH_OURS);

    if (result != 0)
    {
        th_printf("e-[cannot import key in th_ecdh_create]\r\n");
        mbedtls_ecp_keypair_free(&p_ecdh->our_key);
        mbedtls_ecdh_free(&p_ecdh->ecdh_ctx);
        th_free(p_ecdh);
        return EE_STATUS_ERROR;
    }

    *p_context = (void *)p_ecdh;
    return EE_STATUS_OK;
}

ee_status_t
th_ecdh_set_peer_public_key(void *p_context, uint8_t *p_pub, uint32_t publen)
{
    mbedtls_ecdh_context *p_ecdh = &((th_mbedtls_ecdh_t *)p_context)->ecdh_ctx;
    mbedtls_ecp_group_id  group_id = ((th_mbedtls_ecdh_t *)p_context)->group;
    int                   ret;
    mbedtls_ecp_keypair   their_key;

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

    /*
    ret = mbedtls_ecp_check_pubkey(&their_key.MBEDTLS_PRIVATE(grp),
    &their_key.MBEDTLS_PRIVATE(Q)); if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_check_pubkey: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }
    */

    ret = mbedtls_ecdh_get_params(p_ecdh, &their_key, MBEDTLS_ECDH_THEIRS);
    mbedtls_ecp_keypair_free(&their_key);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_get_params: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    return EE_STATUS_OK;
}

ee_status_t
th_ecdh_get_public_key(void *p_context, uint8_t *p_pub, uint32_t *p_publen)
{
    mbedtls_ecp_keypair *p_our_key = &((th_mbedtls_ecdh_t *)p_context)->our_key;
    int                  ret;
    size_t               olen;

    ret = mbedtls_ecp_point_write_binary(&p_our_key->MBEDTLS_PRIVATE(grp),
                                         &p_our_key->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen,
                                         p_pub,
                                         *p_publen);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecp_point_write_binary: -0x%04x]\r\n", -ret);
        return EE_STATUS_ERROR;
    }

    *p_publen = olen;

    return EE_STATUS_OK;
}

ee_status_t
th_ecdh_calc_secret(void *p_context, uint8_t *p_secret, uint32_t *p_seclen)
{
    mbedtls_ecdh_context *p_ecdh;
    size_t                olen;
    int                   ret;

    p_ecdh = &((th_mbedtls_ecdh_t *)p_context)->ecdh_ctx;

    ret = mbedtls_ecdh_calc_secret(
        p_ecdh, &olen, p_secret, *p_seclen, mbedtls_fake_random, NULL);
    if (ret != 0)
    {
        th_printf("e-[mbedtls_ecdh_calc_secret: 0x%04x]\r\n", ret);
        return EE_STATUS_ERROR;
    }

    *p_seclen = olen;

    return EE_STATUS_OK;
}

void
th_ecdh_destroy(void *p_context)
{
    mbedtls_ecp_keypair_free(&((th_mbedtls_ecdh_t *)p_context)->our_key);
    mbedtls_ecdh_free(&((th_mbedtls_ecdh_t *)p_context)->ecdh_ctx);
    th_free(p_context);
}
