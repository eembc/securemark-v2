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

#ifndef __EE_RNG_H
#define __EE_RNG_H

#include "ee_main.h"

/**
 * @brief Creates a context.
 *
 * @param pp_context - A pointer to a context pointer to be created
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rng_create(void **pp_context);

/**
 * @brief Reseed the DRBG by creating & conditioning new entropy.
 *
 * @param p_context - The context from the `create` function
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rng_generate_entropy(void *p_context);

/**
 * @brief Generate a number of random bytes.
 *
 * @param p_context - The context from the `create` function
 * @param p_bytes - Pointer to memory to receive the bytes
 * @param numbytes - Number if bytes to generate
 * @return ee_status_t - EE_STATUS_OK or EE_STATUS_ERROR
 */
ee_status_t th_rng_drbg_getbits(void    *p_context,
                                uint8_t *p_bytes,
                                uint32_t numbytes);

/**
 * @brief Deallocate/destroy the context.
 *
 * @param p_context - The context from the `create` function
 */
ee_status_t th_rng_destroy(void *p_context);

#endif /* __EE_RNG_H */
