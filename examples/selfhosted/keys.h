#include <stdint.h>

/**
 * @brief These are pre-made keys for the self-hosted version of the benchmark
 * in order to generate the proper CRC final checks. In the official version
 * of the benchmark, random keys are generated.
 */

#ifndef __KEYS_H
#define __KEYS_H

static const unsigned char g_ecc_public_key_prime256v1_der[]
    = { 0x04, 0x11, 0xca, 0x9a, 0xff, 0xb3, 0xae, 0x07, 0xf1, 0xdd, 0x4d,
        0xf2, 0x4f, 0x2c, 0xe7, 0x82, 0x00, 0x2e, 0x4b, 0x20, 0xe2, 0x46,
        0xd1, 0x25, 0x89, 0x0c, 0x2b, 0xc0, 0x08, 0xa0, 0xdd, 0x28, 0x71,
        0xdd, 0xea, 0xff, 0xa4, 0x48, 0xcb, 0xfb, 0x50, 0xcc, 0xc9, 0x37,
        0xcb, 0x33, 0xb8, 0xd5, 0x36, 0xec, 0x2e, 0x73, 0xb1, 0x51, 0xe8,
        0x2f, 0xc8, 0xdb, 0xb0, 0x68, 0x10, 0x88, 0x93, 0x4b, 0x77 };
static const unsigned int g_ecc_public_key_prime256v1_der_len = 65;

static const unsigned char g_ecc_signature_prime256v1_sig[]
    = { 0x30, 0x44, 0x02, 0x20, 0x7e, 0x49, 0x2b, 0x00, 0x19, 0x72, 0xf5, 0xcd,
        0xcd, 0x58, 0xab, 0x99, 0x59, 0x16, 0x03, 0x29, 0x68, 0x01, 0xb9, 0xc4,
        0x23, 0x6c, 0xb7, 0x22, 0x5a, 0x46, 0x4d, 0x0c, 0x6d, 0x3b, 0xdc, 0x66,
        0x02, 0x20, 0x30, 0x5e, 0xfe, 0x30, 0xfd, 0x22, 0xc0, 0x83, 0xbc, 0x72,
        0x18, 0x06, 0x2d, 0x4e, 0xfb, 0x4a, 0x47, 0x9d, 0x07, 0xc4, 0x8c, 0x1c,
        0xe7, 0xd6, 0xc0, 0x7c, 0xb0, 0xf3, 0x08, 0xc7, 0x7c, 0x5b };
static const unsigned int g_ecc_signature_prime256v1_sig_len = 70;

static const unsigned char g_ecc_public_key_secp384r1_der[]
    = { 0x04, 0x70, 0x6a, 0x87, 0x82, 0x9c, 0x8c, 0x92, 0x31, 0x8d, 0xf7,
        0xec, 0x73, 0xbd, 0x80, 0xf3, 0xfa, 0xca, 0x65, 0x00, 0x41, 0x66,
        0x8a, 0x6f, 0x14, 0x94, 0x1a, 0x48, 0xb1, 0x5a, 0x12, 0x51, 0x44,
        0x42, 0xe4, 0xf5, 0x22, 0x9d, 0x08, 0x8f, 0x43, 0xe5, 0x0e, 0xa4,
        0xfc, 0x5d, 0x49, 0xf3, 0x15, 0x8c, 0x0d, 0x7e, 0x12, 0x13, 0x62,
        0x61, 0xea, 0x8b, 0x32, 0xc1, 0x72, 0x32, 0xf1, 0x76, 0x8a, 0x77,
        0x7d, 0x2d, 0xef, 0xa6, 0x62, 0xbe, 0x11, 0xf2, 0xb5, 0x94, 0x33,
        0x6d, 0xe2, 0x87, 0xa4, 0x2f, 0x5d, 0x5d, 0x93, 0xb8, 0x2d, 0xad,
        0xe2, 0xca, 0x43, 0x5f, 0x87, 0x1f, 0x3c, 0x85, 0xd2 };
static const unsigned int g_ecc_public_key_secp384r1_der_len = 97;

static const unsigned char g_ecc_signature_secp384r1_sig[]
    = { 0x30, 0x66, 0x02, 0x31, 0x00, 0x99, 0x08, 0xb4, 0xf3, 0xc2, 0x8b, 0x9c,
        0x75, 0xb8, 0x5e, 0xdb, 0x5e, 0x58, 0x04, 0xf4, 0x84, 0x6f, 0xce, 0xdb,
        0x52, 0x57, 0x25, 0xf1, 0xc2, 0xb3, 0xd4, 0x77, 0xb9, 0xcc, 0xe5, 0xff,
        0x4a, 0xcd, 0x23, 0x50, 0x85, 0x9b, 0x8f, 0x1b, 0x0f, 0xcb, 0x40, 0xea,
        0x48, 0xa9, 0x52, 0xbc, 0x07, 0x02, 0x31, 0x00, 0xdb, 0xdd, 0x8c, 0x4d,
        0xa6, 0x53, 0x6d, 0x3f, 0xb1, 0x1d, 0x14, 0x7d, 0x65, 0x02, 0xca, 0x80,
        0x77, 0x59, 0x53, 0x6d, 0xc0, 0x42, 0xac, 0xa3, 0xa1, 0x7a, 0x96, 0xf0,
        0xc6, 0x86, 0x3f, 0x3f, 0xa2, 0x7c, 0x82, 0xb1, 0x32, 0xe7, 0x8d, 0xf4,
        0x0f, 0xe0, 0xe6, 0x16, 0x99, 0x53, 0x23, 0x4c };
static const unsigned int g_ecc_signature_secp384r1_sig_len = 104;

static const unsigned char g_ecc_public_key_ed25519_der[]
    = { 0xf4, 0x53, 0x8c, 0xa7, 0xfa, 0x01, 0x69, 0xd0, 0x50, 0xb4, 0x57,
        0x3d, 0x72, 0x7a, 0x32, 0x14, 0xe7, 0x6b, 0x9e, 0xc1, 0x31, 0x96,
        0x97, 0xdd, 0xc0, 0x04, 0xae, 0xa6, 0xbe, 0xb2, 0xdd, 0x75 };
static const unsigned int g_ecc_public_key_ed25519_der_len = 32;

static const unsigned char g_ecc_signature_ed25519_sig[]
    = { 0xf8, 0x10, 0x10, 0x7d, 0x54, 0x8e, 0x66, 0xcf, 0xf4, 0x89, 0x7f,
        0xa4, 0x31, 0x57, 0x8c, 0xff, 0xea, 0x76, 0xc5, 0xdc, 0x1d, 0x7a,
        0x57, 0x0a, 0x45, 0x97, 0xa7, 0x64, 0x7f, 0x16, 0xe9, 0x49, 0xe8,
        0x76, 0x2b, 0xc2, 0x77, 0x59, 0x79, 0x2b, 0x20, 0x67, 0xc5, 0x23,
        0x92, 0x6f, 0x55, 0x16, 0xb1, 0x8c, 0xe1, 0x2d, 0x57, 0x4c, 0x82,
        0xb9, 0x80, 0x53, 0xa4, 0xa4, 0x37, 0x8d, 0x29, 0x05 };
static const unsigned int g_ecc_signature_ed25519_sig_len = 64;

static const unsigned char g_rsa_public_key_2048_der[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xac, 0xd3, 0xf5,
    0x48, 0xed, 0xe2, 0x14, 0xda, 0x54, 0x09, 0xe7, 0xcc, 0xc1, 0xc0, 0xbf,
    0xc5, 0x50, 0x33, 0x78, 0x49, 0x5b, 0xb1, 0x03, 0x2f, 0x4f, 0xcb, 0x03,
    0x81, 0xe9, 0x33, 0x7f, 0xbe, 0xcd, 0x5a, 0x4d, 0x6a, 0x3c, 0xaa, 0x12,
    0xe4, 0x98, 0xf2, 0xe4, 0x37, 0x72, 0x38, 0x69, 0x47, 0x12, 0xa7, 0xbf,
    0x7e, 0x66, 0xec, 0xbd, 0x4b, 0xa1, 0x0b, 0x52, 0xfd, 0xa5, 0xff, 0x62,
    0x3f, 0x35, 0xc7, 0x96, 0x3f, 0x5c, 0xe2, 0xb0, 0xde, 0x16, 0x44, 0xdd,
    0x00, 0xae, 0x74, 0xfe, 0xd1, 0xb0, 0x2f, 0x15, 0xd7, 0x4a, 0x6a, 0xcb,
    0xff, 0x99, 0x56, 0xdb, 0x46, 0xbc, 0x86, 0xaf, 0x6b, 0xb9, 0xdd, 0x93,
    0xf5, 0xa8, 0xd1, 0x98, 0xe5, 0xd7, 0x11, 0xf6, 0x99, 0x79, 0x8c, 0xe3,
    0x32, 0xa8, 0x72, 0xf8, 0x5c, 0xff, 0x45, 0x3d, 0xcf, 0x52, 0x48, 0xa3,
    0xb8, 0x5e, 0x71, 0xf1, 0x09, 0x3a, 0x97, 0xcb, 0x33, 0x14, 0xac, 0x75,
    0xd3, 0xaa, 0xd6, 0x84, 0x07, 0x1a, 0x6c, 0x16, 0x97, 0x60, 0xac, 0xf9,
    0xf8, 0xeb, 0xe6, 0xea, 0xe7, 0xd6, 0x3a, 0xb8, 0xf3, 0x83, 0xe4, 0x3c,
    0x0d, 0x99, 0x79, 0xd5, 0x5b, 0x1a, 0x77, 0xee, 0x7f, 0xf3, 0x92, 0xac,
    0x9f, 0x20, 0x9d, 0x3e, 0x60, 0x66, 0xae, 0xdb, 0xda, 0xb8, 0x99, 0x27,
    0x66, 0xe5, 0xb1, 0xd7, 0x15, 0xa5, 0x01, 0x97, 0xd2, 0x74, 0x29, 0xae,
    0x10, 0x21, 0xad, 0x4a, 0x15, 0x9b, 0xbe, 0x8b, 0x19, 0xd8, 0x97, 0x0d,
    0x9c, 0xa2, 0x4a, 0x5e, 0xc0, 0xa7, 0x3f, 0xb4, 0x05, 0xd9, 0xbd, 0xdf,
    0x14, 0x7c, 0xbe, 0xa2, 0x68, 0x3b, 0xc1, 0x70, 0x12, 0xa8, 0x0c, 0xf2,
    0x18, 0xe0, 0x48, 0xb7, 0x9c, 0x7c, 0x3e, 0xab, 0x5c, 0xfa, 0x43, 0x05,
    0x0e, 0x65, 0x06, 0x50, 0x72, 0x94, 0xa7, 0x4b, 0x9c, 0xa2, 0x9e, 0x5a,
    0x0f, 0x02, 0x03, 0x01, 0x00, 0x01,
};
static const unsigned int g_rsa_public_key_2048_der_len = 294;

static const unsigned char g_rsa_sig_2048_der[] = {
    0x27, 0x75, 0x84, 0x27, 0x13, 0xee, 0x8e, 0x0a, 0x3e, 0xb5, 0x52, 0x9b,
    0xe3, 0x3a, 0x8f, 0xd6, 0x1f, 0x60, 0xe8, 0x68, 0x80, 0xcf, 0xcd, 0x25,
    0x0f, 0x6d, 0xe5, 0xf8, 0xb5, 0xef, 0x16, 0x93, 0x63, 0xbb, 0xe2, 0xea,
    0xc6, 0x3a, 0x94, 0x36, 0x94, 0x2b, 0x55, 0x07, 0x88, 0x86, 0x6c, 0x93,
    0x69, 0x0a, 0x37, 0xe7, 0x45, 0x14, 0x46, 0x9b, 0xa3, 0x66, 0x15, 0x75,
    0xfb, 0xe1, 0x7f, 0xaf, 0x54, 0x43, 0xea, 0x85, 0x45, 0xae, 0xd9, 0x75,
    0xcd, 0x6c, 0x8b, 0xf7, 0xda, 0x54, 0x3a, 0x57, 0xf8, 0x9b, 0x70, 0xc0,
    0x81, 0xbd, 0xea, 0x3a, 0xfe, 0xe4, 0xf0, 0x26, 0x9b, 0x45, 0xca, 0xfd,
    0xaa, 0x8d, 0x3f, 0x5d, 0xdb, 0x51, 0x5b, 0xea, 0x5f, 0x2c, 0xb5, 0xab,
    0xf4, 0x83, 0x2b, 0x45, 0xfa, 0x27, 0xd1, 0xd2, 0x96, 0xa1, 0x52, 0xed,
    0x09, 0x84, 0x1c, 0x2a, 0x1a, 0x57, 0xcd, 0x85, 0x89, 0xd7, 0xb7, 0x42,
    0xb1, 0xc7, 0x94, 0xaf, 0x36, 0x63, 0xb3, 0x23, 0x2a, 0xa3, 0x6d, 0x84,
    0xd1, 0x26, 0x5e, 0xe9, 0x56, 0x7e, 0x2d, 0x73, 0x3e, 0x2e, 0x2d, 0xd0,
    0x52, 0xfc, 0x1b, 0x2a, 0x94, 0x1a, 0x2e, 0xae, 0x09, 0x95, 0x5f, 0x54,
    0x0c, 0x0f, 0xa4, 0x42, 0xe7, 0x76, 0x21, 0x5a, 0x1d, 0x93, 0x30, 0xd6,
    0xd6, 0x83, 0x05, 0x45, 0xb7, 0x5c, 0x08, 0x65, 0xd5, 0xa2, 0xbe, 0xcb,
    0x31, 0xa3, 0xb5, 0xbe, 0xd0, 0xa2, 0x5e, 0xa7, 0xcb, 0xa5, 0x4d, 0x8d,
    0x87, 0x5e, 0x71, 0xb4, 0x8b, 0xf6, 0x5d, 0xef, 0x12, 0xbb, 0xd5, 0x79,
    0xc1, 0xd9, 0x02, 0xea, 0x45, 0x0f, 0x5b, 0xad, 0x17, 0x3b, 0x2d, 0x9e,
    0x9f, 0x0f, 0x64, 0xec, 0x0e, 0xb5, 0x73, 0xbc, 0xa9, 0x90, 0xc8, 0x38,
    0x73, 0xc8, 0x08, 0xf0, 0xb4, 0x62, 0x63, 0x97, 0x94, 0x6f, 0xb0, 0x3a,
    0xe0, 0xac, 0xe9, 0xa8,

};
static const unsigned int g_rsa_sig_2048_der_len = 256;

static const unsigned char g_rsa_public_key_3072_der[] = {
    0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00,
    0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81, 0x00, 0xb0, 0x4e, 0x2f,
    0xf6, 0x4d, 0xaf, 0x2f, 0xb0, 0x80, 0x99, 0xff, 0xfa, 0x23, 0x26, 0xeb,
    0xd1, 0xee, 0x43, 0x6e, 0x6a, 0x10, 0xce, 0xcf, 0x8d, 0x65, 0x79, 0xc0,
    0xc7, 0xa3, 0xf2, 0xa4, 0x9a, 0x54, 0xd4, 0xb8, 0xdc, 0xd3, 0xb7, 0x23,
    0x72, 0xec, 0xd3, 0x97, 0x6f, 0x0b, 0x5f, 0xe8, 0xdc, 0x37, 0xec, 0xca,
    0x73, 0xf8, 0x5e, 0x2b, 0xea, 0x95, 0x60, 0xab, 0x20, 0x1a, 0xb9, 0xf9,
    0x60, 0xbd, 0x66, 0x6b, 0x5f, 0xd8, 0x12, 0xda, 0x10, 0xcc, 0x1a, 0xb7,
    0xe8, 0xab, 0xf6, 0x8d, 0xd5, 0xb2, 0xa9, 0xda, 0x78, 0xea, 0xa3, 0xe5,
    0x74, 0xab, 0xa9, 0x9b, 0x14, 0x08, 0x3c, 0x9e, 0xae, 0xf7, 0xf1, 0x38,
    0xb6, 0x7d, 0x6c, 0xaa, 0x82, 0x58, 0x2d, 0x31, 0xd1, 0x0f, 0x76, 0xd1,
    0x09, 0xe2, 0xc4, 0x2b, 0x42, 0x36, 0xdb, 0xb9, 0xbe, 0x7a, 0x4c, 0xc8,
    0x22, 0xea, 0x17, 0xd1, 0x9c, 0x6d, 0xc7, 0x2e, 0xd8, 0x41, 0x6e, 0xaa,
    0xfd, 0x59, 0x64, 0x0c, 0xfa, 0x3a, 0xe0, 0x62, 0x0b, 0x15, 0x29, 0xf3,
    0x20, 0x81, 0xb7, 0xe6, 0xc0, 0xed, 0x1d, 0xfb, 0xdf, 0xc2, 0x48, 0x58,
    0xba, 0xee, 0x7b, 0xdc, 0x4f, 0x8e, 0xac, 0x69, 0xab, 0x43, 0x11, 0x26,
    0x14, 0x4b, 0xaa, 0xc9, 0x93, 0x72, 0x87, 0x43, 0xd3, 0xfb, 0x0f, 0x08,
    0x65, 0xa9, 0x2e, 0x3c, 0xab, 0x8f, 0x87, 0xec, 0x05, 0x06, 0x0a, 0xf4,
    0x97, 0x01, 0x46, 0x5e, 0x7b, 0xd4, 0xe4, 0x67, 0x18, 0x78, 0xc8, 0x87,
    0xa1, 0x5f, 0x42, 0x68, 0xdf, 0xa1, 0x6e, 0x4e, 0xb0, 0x51, 0xe5, 0x97,
    0x19, 0x18, 0x8f, 0xe3, 0x56, 0xd6, 0x5a, 0x38, 0x21, 0xe5, 0xbc, 0x34,
    0x78, 0x73, 0x90, 0x99, 0x40, 0x9c, 0xa8, 0xf8, 0xa0, 0x25, 0xfa, 0x52,
    0xa3, 0x5e, 0x8c, 0x39, 0xba, 0xa5, 0x48, 0x75, 0xb0, 0xb7, 0x33, 0x3a,
    0x51, 0x62, 0xc7, 0xcb, 0x54, 0x4d, 0x5e, 0x1a, 0xa5, 0xe7, 0x4e, 0x8f,
    0x74, 0xf0, 0x19, 0x27, 0xb7, 0x6c, 0xe6, 0xa1, 0x4d, 0xd9, 0x3e, 0xd4,
    0x7a, 0x21, 0x69, 0xf8, 0x98, 0xd0, 0x12, 0x56, 0xef, 0x1d, 0x07, 0x3f,
    0xcb, 0x53, 0x46, 0xc6, 0x65, 0x9e, 0x57, 0x06, 0x54, 0xb4, 0x98, 0x05,
    0x12, 0x54, 0xf4, 0xd3, 0x69, 0x26, 0x7a, 0x08, 0x35, 0xc2, 0x22, 0xc6,
    0xcd, 0x34, 0x3a, 0x3a, 0x1e, 0xa7, 0xa7, 0x0b, 0x5e, 0x53, 0xf2, 0x07,
    0x02, 0x33, 0xed, 0x45, 0x2b, 0xff, 0x9a, 0x81, 0xe3, 0x5b, 0xf9, 0x49,
    0x24, 0x2d, 0xf0, 0x55, 0x3d, 0x89, 0xdc, 0x42, 0xe9, 0x41, 0x72, 0xf7,
    0x2a, 0x19, 0x04, 0xb3, 0xc1, 0x1e, 0x50, 0x52, 0x12, 0xd1, 0x51, 0x57,
    0xc1, 0x0c, 0x58, 0x7c, 0x06, 0x88, 0x72, 0x5e, 0x35, 0x87, 0x3a, 0xff,
    0x66, 0x2d, 0x1c, 0x25, 0x4d, 0xb8, 0x91, 0xa9, 0xb7, 0x02, 0x03, 0x01,
    0x00, 0x01,
};
static const unsigned int g_rsa_public_key_3072_der_len = 422;

static const unsigned char g_rsa_sig_3072_der[] = {
    0x91, 0x7f, 0xd4, 0x7d, 0x93, 0x17, 0xb1, 0xd7, 0xb7, 0xcc, 0xb8, 0x93,
    0x89, 0x80, 0x65, 0x3b, 0xc6, 0x7a, 0x2c, 0x8c, 0xb8, 0x66, 0x5a, 0x98,
    0xa1, 0xc1, 0x18, 0x9a, 0xee, 0x20, 0xa6, 0x45, 0x2d, 0x40, 0xbb, 0x97,
    0xea, 0x84, 0xfd, 0xa9, 0xb4, 0x2f, 0x81, 0xa4, 0x41, 0x79, 0xf7, 0x1e,
    0x62, 0xe0, 0x04, 0x4e, 0x79, 0x15, 0xfa, 0x15, 0x56, 0x18, 0xc1, 0x77,
    0xe9, 0xc6, 0x90, 0x76, 0x1a, 0xaa, 0x4a, 0xd7, 0x60, 0x9b, 0x6b, 0xb5,
    0xf6, 0x0e, 0x60, 0xf9, 0xc7, 0xfe, 0x12, 0x6b, 0x08, 0x09, 0xd8, 0x28,
    0xed, 0x60, 0xad, 0xdf, 0x34, 0xa9, 0xea, 0xdc, 0xfa, 0xcf, 0xa3, 0x03,
    0xe8, 0xd7, 0xd0, 0x5e, 0xd1, 0xf5, 0x2a, 0xf7, 0x63, 0xe0, 0xed, 0x20,
    0x0c, 0x3f, 0xf7, 0x78, 0x20, 0xf8, 0x0a, 0x60, 0x3c, 0x24, 0xbe, 0x53,
    0xc9, 0x55, 0x53, 0x92, 0x04, 0x07, 0x10, 0x7b, 0x0b, 0x2b, 0x2a, 0xca,
    0x11, 0x56, 0x61, 0x16, 0x9c, 0xdd, 0xbc, 0xbb, 0xad, 0x6d, 0xed, 0x66,
    0x87, 0xb1, 0x5a, 0xfc, 0xf2, 0xbe, 0x00, 0xc4, 0x40, 0x53, 0xd4, 0xb6,
    0x1b, 0x62, 0xec, 0x15, 0xb5, 0xa9, 0x69, 0xaf, 0x0d, 0x20, 0xd0, 0xeb,
    0xf4, 0x3c, 0xaa, 0xc5, 0x81, 0x5a, 0xaf, 0x99, 0xd5, 0x2e, 0x04, 0x6d,
    0x42, 0xc4, 0x67, 0x21, 0xfc, 0x9d, 0x66, 0xdb, 0xc5, 0x91, 0xcc, 0xca,
    0x17, 0x1b, 0x05, 0x0a, 0xba, 0xf5, 0xff, 0xe0, 0x6b, 0xe7, 0x2a, 0x20,
    0x7a, 0xaf, 0x16, 0x0f, 0xda, 0x48, 0x24, 0x77, 0x99, 0x5a, 0x1e, 0x6d,
    0x84, 0x2d, 0x07, 0x30, 0x46, 0x18, 0x10, 0x78, 0x26, 0x58, 0xb7, 0xc1,
    0xe2, 0x43, 0x44, 0xaa, 0x5d, 0x37, 0xfa, 0x45, 0x4d, 0x17, 0xc8, 0x5a,
    0x4a, 0x6c, 0x00, 0x1a, 0x4a, 0x82, 0x58, 0xbe, 0x9f, 0xd0, 0x8d, 0x18,
    0x4d, 0x05, 0x15, 0x0d, 0x6c, 0x54, 0x88, 0x47, 0x6d, 0x9d, 0x24, 0x59,
    0x99, 0x64, 0x66, 0xd2, 0x05, 0x84, 0x46, 0x21, 0x5d, 0x0e, 0xe8, 0x61,
    0x60, 0x01, 0x03, 0x19, 0x13, 0x19, 0x96, 0x59, 0x50, 0x84, 0x5f, 0xf7,
    0xae, 0x49, 0xa2, 0xa0, 0x1c, 0x21, 0xc3, 0x05, 0x5e, 0xb3, 0xde, 0x57,
    0xad, 0x31, 0x45, 0x85, 0xd3, 0x3f, 0x88, 0x3a, 0x4e, 0x49, 0x14, 0x00,
    0xc9, 0x1a, 0xf8, 0x4e, 0x3e, 0x8f, 0x10, 0xae, 0xaa, 0x7a, 0x3e, 0xfc,
    0x47, 0x87, 0x82, 0x8f, 0x1d, 0xa0, 0xfe, 0xd4, 0x40, 0x03, 0xf5, 0xe2,
    0xfc, 0xd7, 0x86, 0x7c, 0x6c, 0x46, 0xd1, 0x28, 0x20, 0xe7, 0xc3, 0x58,
    0x1b, 0x8b, 0xe7, 0x34, 0x66, 0xbb, 0xf1, 0xe7, 0x2d, 0x0d, 0xba, 0x1d,
    0x85, 0xc7, 0x9d, 0x13, 0x1f, 0x2f, 0x5b, 0xda, 0xde, 0x0f, 0x9e, 0x54,
    0x38, 0x55, 0xff, 0x69, 0xc3, 0xc8, 0x94, 0xdd, 0xb0, 0x69, 0x67, 0x96,

};
static const unsigned int g_rsa_sig_3072_der_len = 384;

static const unsigned char g_rsa_public_key_4096_der[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
    0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xb7, 0x1c, 0x76,
    0x66, 0xd6, 0x15, 0x00, 0xa8, 0xa5, 0xe3, 0xc4, 0xf5, 0x45, 0x08, 0x68,
    0xa6, 0xa2, 0xb5, 0xb1, 0x11, 0xf5, 0x07, 0x12, 0xb4, 0xac, 0xd5, 0x06,
    0xa9, 0x6e, 0x11, 0x06, 0x10, 0x3d, 0x90, 0x62, 0x8b, 0xd6, 0x25, 0xe5,
    0x6d, 0xbd, 0x9d, 0xdd, 0x29, 0x8d, 0xa2, 0xc0, 0xa2, 0xda, 0x8c, 0x0b,
    0x16, 0x4b, 0x8c, 0x13, 0x62, 0xcd, 0x98, 0xb7, 0xfd, 0xad, 0x63, 0x53,
    0x2b, 0x7b, 0xa4, 0xa0, 0x7d, 0x87, 0xee, 0xd9, 0xa6, 0xb2, 0xf2, 0xc2,
    0x98, 0xe7, 0x02, 0x3c, 0x44, 0x61, 0x79, 0x40, 0x32, 0x1c, 0x52, 0xa6,
    0x27, 0x67, 0xce, 0x99, 0x6b, 0x3f, 0xdd, 0x56, 0x90, 0xe5, 0x7e, 0xef,
    0x5d, 0x13, 0xaf, 0x2b, 0x35, 0xf4, 0x00, 0xb5, 0x86, 0x3b, 0xd3, 0x2b,
    0x39, 0xf6, 0xe7, 0xe0, 0xbb, 0xb5, 0x86, 0xfb, 0xfe, 0xb9, 0x5d, 0x37,
    0xd2, 0xa6, 0xde, 0x3f, 0xba, 0xea, 0x71, 0x4f, 0x25, 0xaf, 0x8b, 0x33,
    0x66, 0x9a, 0x64, 0x20, 0x88, 0x02, 0x8a, 0x5d, 0xc2, 0x25, 0x56, 0xaa,
    0xed, 0x60, 0x1d, 0x9e, 0xf0, 0x58, 0x44, 0x31, 0xd4, 0x86, 0x02, 0x32,
    0x1e, 0x56, 0xed, 0x8e, 0xcb, 0x79, 0x64, 0x12, 0xf9, 0x79, 0x96, 0xb8,
    0x68, 0x0f, 0xba, 0xf8, 0xd9, 0x6d, 0x48, 0x88, 0x5b, 0xa2, 0x48, 0x12,
    0xac, 0xb8, 0x5c, 0xc7, 0xf7, 0x0d, 0x8e, 0x92, 0x75, 0x42, 0xa4, 0x66,
    0x50, 0x02, 0x78, 0xb1, 0x3f, 0x31, 0xbb, 0xed, 0xe5, 0x2c, 0xb3, 0xc6,
    0x20, 0xa8, 0x66, 0x29, 0xeb, 0x80, 0xc4, 0xf8, 0x2d, 0xc4, 0x26, 0x79,
    0xde, 0x73, 0x99, 0x3b, 0xa7, 0xa0, 0x7e, 0x2d, 0x2e, 0x27, 0x59, 0xc7,
    0x27, 0xc7, 0x4f, 0x08, 0x4e, 0xbd, 0x70, 0x98, 0x31, 0x1f, 0x9a, 0x57,
    0x5c, 0x0a, 0x4a, 0x72, 0xcd, 0x10, 0x1f, 0x41, 0x2e, 0x49, 0x56, 0x5e,
    0xa5, 0x03, 0x95, 0x6d, 0x28, 0xb1, 0x4b, 0x60, 0xb2, 0x7a, 0xac, 0x6a,
    0x96, 0xf3, 0xaf, 0x4d, 0x1a, 0x36, 0xc1, 0xb4, 0x77, 0x6e, 0x2c, 0xb2,
    0x75, 0xf0, 0xa1, 0xe8, 0xcc, 0xf2, 0x40, 0xcd, 0x53, 0x0a, 0x00, 0x2d,
    0x8b, 0x6b, 0xb6, 0x50, 0x1d, 0xb5, 0x80, 0xd3, 0x56, 0x9c, 0xde, 0x9a,
    0x97, 0xf3, 0xbd, 0xee, 0x5c, 0x10, 0x79, 0x5f, 0xfc, 0x95, 0xb4, 0x8b,
    0x7f, 0x5a, 0x48, 0xdd, 0xcd, 0x54, 0x60, 0x9c, 0x98, 0x69, 0x27, 0xe1,
    0x72, 0x24, 0x57, 0x67, 0x7d, 0x40, 0x47, 0x66, 0xe7, 0xe2, 0x19, 0x0a,
    0xa4, 0x80, 0x53, 0x59, 0x43, 0x06, 0x3d, 0x82, 0x05, 0xd6, 0xba, 0x15,
    0xd2, 0xe1, 0x6b, 0x53, 0x25, 0x03, 0x17, 0xb2, 0xaa, 0xce, 0xd0, 0xc0,
    0x4d, 0xbe, 0xed, 0xdc, 0x2e, 0x8c, 0x99, 0x4c, 0x82, 0xa1, 0x73, 0x95,
    0xb0, 0x82, 0xb8, 0x88, 0x47, 0x84, 0x25, 0xb2, 0x15, 0xaa, 0x76, 0x14,
    0x8b, 0xda, 0x40, 0x9b, 0x41, 0x87, 0x5c, 0x0a, 0x8b, 0x5a, 0x37, 0xcf,
    0xbc, 0x47, 0x30, 0x58, 0x51, 0xfe, 0x1d, 0x34, 0x6a, 0xfe, 0x1e, 0xa4,
    0x1a, 0xa3, 0x53, 0x35, 0x0c, 0x39, 0x21, 0x39, 0xaa, 0xbb, 0xd1, 0x02,
    0xc6, 0x51, 0xc5, 0xe4, 0x0e, 0xc5, 0x6a, 0x5f, 0x71, 0x56, 0xa3, 0x21,
    0x80, 0x37, 0xb2, 0xe4, 0xd7, 0x3c, 0x59, 0x2d, 0xde, 0x36, 0x9d, 0x33,
    0xb9, 0x47, 0x51, 0xc3, 0x78, 0x62, 0x1c, 0xe5, 0xf5, 0x1c, 0xc4, 0x7b,
    0x1d, 0xfe, 0x59, 0x3c, 0xeb, 0xe9, 0xe9, 0xf2, 0xa3, 0xa1, 0x0b, 0x3c,
    0xd2, 0xec, 0x1e, 0x13, 0x77, 0xb8, 0x7d, 0xaa, 0x90, 0x9c, 0x42, 0x10,
    0x0c, 0x40, 0x6f, 0xd2, 0x9e, 0x0d, 0xdb, 0x65, 0x62, 0x1b, 0xa5, 0xf4,
    0xb2, 0x22, 0x3c, 0xc3, 0xea, 0x40, 0xcd, 0xe7, 0x85, 0x4a, 0xc0, 0x56,
    0xd3, 0xff, 0xa6, 0xa4, 0x37, 0x02, 0x03, 0x01, 0x00, 0x01,
};
static const unsigned int g_rsa_public_key_4096_der_len = 550;

static const unsigned char g_rsa_sig_4096_der[] = {
    0x3a, 0x62, 0x63, 0x55, 0x0e, 0x07, 0x18, 0xc5, 0xbc, 0x43, 0xe0, 0xfd,
    0x44, 0x25, 0x11, 0x6e, 0x15, 0xf0, 0xa5, 0x7b, 0x67, 0xe2, 0x48, 0x69,
    0x04, 0x6a, 0x90, 0xfc, 0x5d, 0xa0, 0x5f, 0xfa, 0xc1, 0x7a, 0x40, 0x5a,
    0xb9, 0xcb, 0x1b, 0x95, 0xbb, 0xb1, 0xa0, 0x25, 0x0e, 0xb1, 0x21, 0xa6,
    0xe0, 0x29, 0xfd, 0xb9, 0xc9, 0xd7, 0x2d, 0x04, 0x8c, 0x52, 0x12, 0xd4,
    0xb0, 0x04, 0x93, 0xea, 0xf5, 0x4d, 0x07, 0x8a, 0xb6, 0x1f, 0x1a, 0xce,
    0xbc, 0x3b, 0xc2, 0x11, 0xba, 0xe3, 0x56, 0xb5, 0x74, 0xb9, 0x8b, 0xb5,
    0x38, 0x80, 0x84, 0xe1, 0x2a, 0x8d, 0xc3, 0x96, 0x88, 0x2e, 0xbc, 0x37,
    0x24, 0xf7, 0xc6, 0x07, 0x59, 0x78, 0x62, 0x0d, 0x31, 0x01, 0xee, 0x17,
    0x4e, 0x07, 0xe7, 0x8f, 0xe6, 0xaf, 0x4d, 0xfd, 0xa7, 0xb8, 0xbc, 0xf6,
    0x0e, 0x3a, 0xeb, 0x13, 0xdf, 0xb4, 0x5f, 0xd8, 0x9d, 0x7a, 0x08, 0xb5,
    0xbb, 0xec, 0xcf, 0xa5, 0xac, 0xc3, 0x67, 0x0f, 0xb9, 0x90, 0xe7, 0x7d,
    0xcd, 0xbf, 0x43, 0x16, 0x9c, 0x33, 0xa4, 0x77, 0xa1, 0xbf, 0x15, 0xb4,
    0x65, 0x9a, 0xcf, 0xad, 0xc2, 0x82, 0xc3, 0x03, 0x7c, 0xda, 0x28, 0x4e,
    0x22, 0xf5, 0x9f, 0xd3, 0xc0, 0xa1, 0xee, 0x72, 0xd6, 0x33, 0xb6, 0xfa,
    0xa2, 0x39, 0xd4, 0x50, 0x3f, 0xf6, 0xfd, 0xea, 0x1c, 0xb4, 0x4a, 0x82,
    0xc0, 0x0f, 0xde, 0x81, 0x51, 0x5d, 0x8e, 0x63, 0xb5, 0x23, 0x43, 0xd6,
    0x0b, 0x86, 0x7b, 0x17, 0x18, 0x0b, 0xed, 0x90, 0x50, 0x5f, 0x10, 0x35,
    0x68, 0xdd, 0x05, 0x18, 0x26, 0xb1, 0x3e, 0xf2, 0x46, 0xad, 0xb8, 0xf9,
    0x48, 0x3d, 0xab, 0xc2, 0xf2, 0xe8, 0xd0, 0x53, 0x91, 0x65, 0x89, 0xb3,
    0x2f, 0xe5, 0xaa, 0xcf, 0x42, 0x74, 0xc8, 0x68, 0xb4, 0xa5, 0x48, 0xae,
    0xf2, 0x4e, 0x83, 0x08, 0x06, 0x70, 0xd9, 0x4c, 0xcd, 0x54, 0x7a, 0xbd,
    0xe2, 0xa9, 0xc9, 0xab, 0x93, 0x7d, 0xbf, 0x86, 0x45, 0xe3, 0x02, 0x7b,
    0x34, 0x1a, 0x0c, 0x7e, 0xb6, 0x9c, 0xba, 0x80, 0x10, 0x81, 0xe6, 0xab,
    0x19, 0x41, 0x88, 0xa8, 0x2b, 0x16, 0x95, 0xe4, 0x4c, 0x3b, 0x90, 0xdb,
    0x2d, 0xa9, 0xe0, 0x27, 0xad, 0x6a, 0xaf, 0x1d, 0xc7, 0x37, 0x09, 0x4f,
    0x5e, 0x9d, 0x39, 0x2e, 0x2f, 0xf5, 0xc5, 0x28, 0x3b, 0x1b, 0x51, 0x13,
    0xe8, 0xa7, 0x32, 0xa3, 0x1d, 0xd5, 0x4a, 0xa8, 0x2c, 0x90, 0x86, 0x24,
    0x33, 0xb5, 0x93, 0x54, 0xeb, 0x97, 0xaa, 0xcf, 0xcd, 0xd0, 0xff, 0x51,
    0xec, 0xe0, 0x41, 0xa4, 0x21, 0x50, 0x72, 0x7f, 0xc8, 0x8b, 0x77, 0xf4,
    0xee, 0x64, 0xe8, 0x52, 0x94, 0x61, 0x5a, 0xf3, 0x08, 0xd3, 0xeb, 0xd4,
    0xda, 0xfa, 0xa2, 0xea, 0x80, 0x5f, 0xba, 0x38, 0x29, 0x5a, 0x65, 0x0f,
    0x4b, 0xd1, 0xbd, 0x4f, 0xd2, 0x28, 0xfc, 0x77, 0x5e, 0xdf, 0xc4, 0x9f,
    0xd7, 0x8d, 0x0e, 0xa7, 0x8d, 0x45, 0x1f, 0x6a, 0xe9, 0x20, 0xcd, 0x9f,
    0xb6, 0xf6, 0xcf, 0xae, 0x8c, 0xaa, 0x8f, 0x36, 0x91, 0x51, 0x24, 0xac,
    0xa8, 0x2c, 0xf2, 0xed, 0x6b, 0x89, 0x49, 0x5f, 0x95, 0xe3, 0x73, 0x91,
    0x29, 0x0d, 0x6a, 0x6a, 0xda, 0x1f, 0x7d, 0x4e, 0xb3, 0x25, 0x49, 0x11,
    0x8f, 0x93, 0x7a, 0x29, 0xec, 0x23, 0xe3, 0xb9, 0xb7, 0x62, 0x4a, 0x01,
    0x26, 0xdd, 0x7a, 0x70, 0x60, 0xdc, 0x5f, 0xfb, 0x6b, 0xdd, 0x52, 0x20,
    0x14, 0xa9, 0xcd, 0x1b, 0x8f, 0x18, 0x8a, 0x30, 0x3e, 0x4d, 0x95, 0xe2,
    0x5e, 0xac, 0xd6, 0x83, 0xd4, 0x92, 0x43, 0xa6, 0xb6, 0x8a, 0x8e, 0x06,
    0xcf, 0x01, 0x50, 0x91, 0x54, 0x3c, 0x12, 0x0c, 0x03, 0xc0, 0x62, 0x93,
    0xf9, 0x56, 0x76, 0xff, 0x00, 0xe4, 0x01, 0xa5,
};
static const unsigned int g_rsa_sig_4096_der_len = 512;

uint8_t g_ecc_public_key_c25519[] = {
    // LITTLE-ENDIAN
    0xf8, 0x5d, 0x06, 0x5d, 0xd7, 0xa4, 0xe2, 0xb8, 0x72, 0x27, 0xf2,
    0x38, 0x2b, 0x44, 0x4b, 0xf5, 0xd2, 0x29, 0x60, 0x70, 0x3c, 0xdc,
    0x86, 0xc0, 0xef, 0xd2, 0xd3, 0x4d, 0x5d, 0xe1, 0xdb, 0x26,
};

/* see ee_dsa_alg_t in ee_bench.h */
const uint8_t *g_public_keys[] = {
    g_ecc_public_key_prime256v1_der, g_ecc_public_key_secp384r1_der,
    g_ecc_public_key_c25519,         g_ecc_public_key_ed25519_der,
    g_rsa_public_key_2048_der,       g_rsa_public_key_3072_der,
    g_rsa_public_key_4096_der,
};

/* see ee_dsa_alg_t in ee_bench.h */
const uint32_t g_public_key_sizes[] = {
    g_ecc_public_key_prime256v1_der_len,
    g_ecc_public_key_secp384r1_der_len,
    32,
    g_ecc_public_key_ed25519_der_len,
    g_rsa_public_key_2048_der_len,
    g_rsa_public_key_3072_der_len,
    g_rsa_public_key_4096_der_len,
};

/* see ee_dsa_alg_t in ee_bench.h */
const uint8_t *g_dsa_signatures[] = {
    g_ecc_signature_prime256v1_sig,
    g_ecc_signature_secp384r1_sig,
    0,
    g_ecc_signature_ed25519_sig,
    g_rsa_sig_2048_der,
    g_rsa_sig_3072_der,
    g_rsa_sig_4096_der,
};

/* see ee_dsa_alg_t in ee_bench.h */
const uint32_t g_dsa_signature_sizes[] = {
    g_ecc_signature_prime256v1_sig_len,
    g_ecc_signature_secp384r1_sig_len,
    0,
    g_ecc_signature_ed25519_sig_len,
    g_rsa_sig_2048_der_len,
    g_rsa_sig_3072_der_len,
    g_rsa_sig_4096_der_len,
};

uint8_t g_dsa_message[] = {
    /* SHA256(`Tempus unum hominem manet.`) */
    0xb7, 0x03, 0xb9, 0xc0, 0x84, 0xbe, 0xe8, 0xa2, 0x78, 0xa9, 0x56,
    0x53, 0x48, 0x44, 0xd7, 0xfa, 0x40, 0x10, 0xa5, 0x86, 0x8c, 0x0c,
    0x82, 0xa4, 0x50, 0x6b, 0xf8, 0x1c, 0x36, 0x21, 0x8d, 0xe1,
};

#endif /* __KEYS_H */
