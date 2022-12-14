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

#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

ee_status_t
th_rsa_create(void **pp_context)
{
#warning "th_rsa_create not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_set_public_key(void *p_context, const uint8_t *p_pub, uint32_t publen)
{
#warning "th_rsa_set_public_key not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_verify(void    *p_context,
              uint8_t *p_msg,
              uint32_t mlen,
              uint8_t *p_sig,
              uint32_t slen,
              bool    *p_pass)
{
#warning "th_rsa_sign not implemented"
    return EE_STATUS_OK;
}

ee_status_t
th_rsa_destroy(void *p_context)
{
#warning "th_rsa_destroy not implemented"
    return EE_STATUS_OK;
}
