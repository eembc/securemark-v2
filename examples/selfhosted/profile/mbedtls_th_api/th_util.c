/*
 * Copyright (C) 2015-2017 EEMBC(R). All Rights Reserved
 *
 * All EEMBC Benchmark Software are products of EEMBC and are provided under the
 * terms of the EEMBC Benchmark License Agreements. The EEMBC Benchmark Software
 * are proprietary intellectual properties of EEMBC and its Members and is
 * protected under all applicable laws, including all applicable copyright laws.
 *
 * If you received this EEMBC Benchmark Software without having a currently
 * effective EEMBC Benchmark License Agreement, you must discontinue use.
 */

#include "th_util.h"

static unsigned char g_generic_buffer[BUFFER_SIZE];

void
th_pre(void)
{
}

void
th_post(void)
{
}

void
th_buffer_initialize(void)
{
}

unsigned char *
th_buffer_address(void)
{
    return g_generic_buffer;
}

uint32_t
th_buffer_size(void)
{
    return BUFFER_SIZE;
}

static const uint8_t random_bytes[]
    = { 0xde, 0xa5, 0xe4, 0x5d, 0x0e, 0xa3, 0x7f, 0xc5, 0xf3, 0x66, 0x23,
        0x2a, 0x50, 0x8f, 0x4a, 0xd2, 0x0e, 0xa1, 0x3d, 0x47, 0xe4, 0xbf,
        0x5f, 0xa4, 0xd5, 0x4a, 0x57, 0xa0, 0xba, 0x01, 0x20, 0x42, 0x08,
        0x70, 0x97, 0x49, 0x6e, 0xfc, 0x58, 0x3f, 0xed, 0x8b, 0x24, 0xa5,
        0xb9, 0xbe, 0x9a, 0x51, 0xde, 0x06, 0x3f, 0x5a, 0x00, 0xa8, 0xb6,
        0x98, 0xa1, 0x6f, 0xd7, 0xf2, 0x9b, 0x54, 0x85 };

int
mbedtls_fake_random(void *rng_state, unsigned char *output, size_t len)
{
    (void)rng_state;
    size_t i;

    /* Requesting more random data than available. */
    if (len > sizeof(random_bytes))
    {
        return 1;
    }

    for (i = 0; i < len; ++i)
    {
        output[i] = random_bytes[i % sizeof(random_bytes)];
    }

    return 0;
}

ee_status_t
th_profile_initialize(void)
{

    return EE_STATUS_OK;
}
