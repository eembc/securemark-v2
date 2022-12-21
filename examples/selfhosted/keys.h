#include <stdint.h>

/**
 * @brief These are pre-made keys for the self-hosted version of the benchmark
 * in order to generate the proper CRC final checks. In the official version
 * of the benchmark, random keys are generated.
 */

#ifndef __KEYS_H
#define __KEYS_H

// clang-format off

uint8_t g_ecc_public_key_p256r1[] =
{
0x04,
0x75,0x64,0xfd,0x3f,0x96,0xe8,0x79,0x84,0x9b,0xf9,0x7c,0xc8,0xbb,0x28,0x5d,0xa1,
0x27,0x01,0xfb,0x4f,0xd5,0xff,0x4b,0xab,0x7e,0x52,0x17,0xbf,0x09,0x15,0xe9,0x48,
0xb0,0x54,0xbe,0x64,0x70,0xe5,0x28,0xd9,0xe1,0x45,0xfc,0xbc,0xdc,0x01,0x6f,0x6a,
0x4a,0xa1,0x55,0x8b,0x89,0xc8,0xe1,0x6f,0x90,0x1e,0xe1,0xc3,0xd4,0x60,0xa8,0xcc,
};

uint8_t g_ecc_public_key_p384[] =
{
0x04,
0xee,0x98,0xe9,0xaa,0x26,0x71,0xe8,0x72,0xcd,0x80,0xa9,0x6b,0x26,0x1f,0xb5,0x8d,
0xcf,0x8d,0xe8,0x21,0xd9,0xf8,0x51,0x50,0x3e,0xdc,0x5a,0xa8,0xf6,0x50,0xee,0x7e,
0x11,0xc2,0x24,0x9b,0xe6,0xde,0xe1,0xf3,0x43,0x1d,0x44,0x43,0xd9,0xd7,0x24,0xbf,
0xb3,0xd9,0xea,0xd8,0xd7,0x57,0x4c,0xbc,0x8e,0x6b,0xfa,0x5d,0xb8,0xda,0x9e,0xe6,
0x10,0x91,0x99,0x5d,0x73,0xd4,0x0e,0x4b,0x12,0xa5,0x42,0x9f,0xdc,0xff,0x2b,0x52,
0x55,0xa3,0xf9,0x9f,0x00,0xec,0x9b,0x1b,0x25,0x2d,0xb3,0xaa,0xd7,0x50,0x8b,0x36,
};

uint8_t g_ecc_public_key_c25519[] =
{
// LITTLE-ENDIAN
0xf8,0x5d,0x06,0x5d,0xd7,0xa4,0xe2,0xb8,0x72,0x27,0xf2,0x38,0x2b,0x44,0x4b,0xf5,
0xd2,0x29,0x60,0x70,0x3c,0xdc,0x86,0xc0,0xef,0xd2,0xd3,0x4d,0x5d,0xe1,0xdb,0x26,
};

uint8_t g_ecc_public_key_ed25519[] =
{
// LITTLE-ENDIAN
0x77,0xee,0xaf,0x7f,0x13,0x65,0xcc,0x5f,0x60,0xcf,0x3d,0x7e,0x08,0xa6,0x2f,0xf0,
0xf8,0x18,0x1a,0xc8,0x1c,0x21,0x29,0xe8,0xf9,0x12,0x7f,0x44,0x26,0xfe,0x58,0x32,
};

uint8_t g_rsa_public_key_2048[] = 
{
// ASN.1/DER
0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,
0x00,0xc0,0xa3,0x67,0x5d,0xd5,0x76,0xa3,0x9f,0xc7,0x53,0x3a,0x6b,0x83,0x76,0x5f,
0xf7,0x1d,0x0d,0xe3,0x55,0x19,0xaa,0x95,0x71,0x09,0x22,0x88,0x11,0x5d,0x17,0x73,
0x7b,0xcf,0x09,0xb1,0xe0,0xff,0xee,0xe4,0x6b,0x1e,0x72,0x23,0xeb,0x36,0x68,0x05,
0xbb,0xdf,0x0e,0x17,0x29,0xc0,0x9e,0x07,0x8c,0xb9,0xf7,0x79,0x32,0x79,0x73,0x67,
0x19,0x35,0x17,0xe4,0xd9,0x3d,0x8e,0x95,0x95,0xcb,0xc4,0xa6,0x0b,0x78,0x48,0x1b,
0xf7,0x11,0x48,0xbc,0xfd,0x57,0xd7,0x57,0xbd,0x19,0x2d,0x0e,0x31,0x50,0xef,0x00,
0xfa,0x20,0xe6,0xf1,0xfb,0xef,0x10,0xae,0x37,0x83,0x4a,0x19,0x4c,0x58,0xc3,0xce,
0x7e,0xc5,0xeb,0xe0,0xbd,0x5a,0x36,0x49,0xa5,0xda,0x46,0x68,0x3e,0x3e,0x6b,0x40,
0x5b,0x60,0xd8,0x84,0x19,0xf1,0xc9,0xb2,0xe8,0x4e,0x10,0x07,0x5e,0xed,0xb9,0xad,
0x6d,0x30,0xd7,0x16,0x51,0xa9,0xdf,0xe9,0x40,0xc9,0x89,0xfc,0x78,0x81,0xbe,0x94,
0x51,0x6a,0x04,0x9d,0xff,0x5d,0xc1,0xab,0x4a,0xa2,0x3f,0x7d,0xb9,0x1f,0x98,0xbc,
0xa1,0xc0,0xf2,0xee,0xe1,0x90,0x28,0xff,0xab,0x86,0xec,0x05,0x3c,0xe6,0x6b,0x31,
0x02,0x59,0xf6,0xab,0x65,0x42,0x25,0x5b,0xfb,0xea,0x11,0x2a,0xc4,0x10,0xc7,0xca,
0x85,0xe2,0x74,0x19,0x2a,0xd5,0x9d,0x9d,0x5d,0xee,0x84,0xce,0x8b,0xe8,0x28,0x68,
0xcb,0x16,0xe2,0xde,0xfb,0x04,0x81,0x58,0x0d,0x01,0xfa,0x09,0xc2,0x09,0x69,0x1d,
0xf3,0x67,0x40,0x17,0xe3,0xb3,0xb1,0x1c,0xdc,0xfe,0xb7,0xa5,0xde,0x3a,0xa4,0x01,
0xc9,0x02,0x03,0x01,0x00,0x01,
};

uint8_t g_rsa_public_key_3072[] = 
{
// ASN.1/DER
0x30,0x82,0x01,0xa2,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
0x01,0x05,0x00,0x03,0x82,0x01,0x8f,0x00,0x30,0x82,0x01,0x8a,0x02,0x82,0x01,0x81,
0x00,0x9a,0xf8,0x55,0xb6,0x91,0x97,0x09,0x5f,0x3d,0x76,0x8f,0x8d,0x1f,0x9d,0x18,
0x34,0x61,0x04,0x8b,0x2c,0x7f,0x77,0xf0,0x98,0xc4,0xf1,0x8d,0xc3,0xd1,0x8a,0x92,
0x26,0x01,0xb8,0xba,0x54,0xfb,0xc8,0x53,0x4f,0x99,0xed,0x30,0x0f,0xd5,0x5d,0xc8,
0x4c,0x50,0x66,0x18,0xa2,0xad,0xc8,0x22,0xb4,0x49,0x68,0xc1,0x3a,0x4b,0xaf,0x7a,
0xd0,0xae,0x21,0x70,0xba,0xd0,0xed,0xa5,0x58,0x56,0xeb,0x9c,0x69,0x13,0x1f,0xd5,
0x10,0xf2,0x35,0xff,0xf9,0xac,0x79,0xb4,0x10,0x6d,0xef,0xed,0x21,0xe6,0xf0,0x25,
0x0d,0xec,0xe7,0xc7,0x61,0x34,0xb0,0xec,0xe9,0x67,0x43,0x3a,0x8f,0x70,0xa3,0x05,
0x0c,0xb5,0x3a,0x3a,0xb7,0x12,0x31,0xbb,0x85,0xad,0x77,0x47,0xc1,0xb8,0xcd,0x06,
0xf6,0x9b,0xee,0x1f,0x61,0x8a,0xb5,0x7c,0x7a,0x1a,0x62,0x52,0xfe,0x84,0x1d,0x9a,
0x1f,0x8a,0x72,0x10,0x03,0xd1,0xca,0x85,0xff,0x35,0x56,0x07,0x3c,0xc9,0x9e,0x9e,
0x3f,0x8d,0xee,0x13,0xce,0xf1,0xac,0x1a,0xdf,0x30,0xce,0xc2,0x10,0xab,0x0c,0x61,
0x17,0x74,0xf3,0xf6,0x11,0x4f,0xd0,0x1b,0x90,0x7f,0x55,0x52,0x94,0x30,0xf4,0xb8,
0x12,0xd3,0x41,0xe5,0x9c,0x8a,0x8d,0x06,0x55,0xe9,0x96,0xf6,0x6c,0x27,0x56,0x32,
0x40,0xbd,0x84,0xe7,0xe3,0xbd,0x92,0x30,0x18,0x00,0xf2,0xf9,0xd1,0xdc,0xcf,0xe8,
0x6b,0x85,0x9e,0x07,0x7b,0x60,0xda,0x40,0xf6,0x3b,0x93,0x5e,0x09,0xec,0xd8,0x21,
0x40,0x88,0xd1,0x82,0x34,0x3a,0xef,0x21,0x49,0x52,0x37,0x89,0xc6,0x81,0x84,0x37,
0x84,0x2f,0x56,0x6a,0x37,0xb6,0x66,0x31,0xf2,0xce,0xcd,0x8d,0x30,0xfb,0xe3,0x0b,
0x88,0xa8,0xcc,0x11,0xea,0x0b,0x20,0xfc,0x97,0x91,0x1f,0x97,0xce,0xb4,0xf1,0x32,
0xff,0x3e,0xcd,0xed,0xd7,0xf7,0x70,0x0b,0x23,0x4a,0x50,0x63,0x0e,0x10,0x12,0x2f,
0xae,0x0e,0x9f,0x51,0x25,0x90,0x89,0x22,0x8e,0x2a,0x08,0x86,0x96,0xfe,0x89,0x25,
0x7f,0xa2,0x1e,0xd8,0xeb,0xcd,0xf5,0x07,0x2c,0x50,0x2d,0xb5,0x51,0xbf,0x9e,0x6c,
0x57,0xea,0x0f,0x01,0x3c,0x8c,0x9e,0x32,0x48,0xc3,0x4b,0xd9,0x1a,0xa8,0xe9,0x25,
0xf9,0xc7,0xda,0xd7,0x16,0x12,0x06,0x33,0x1d,0xfc,0xfa,0x34,0x74,0x48,0x2f,0x0e,
0x70,0x3a,0x94,0xff,0x3c,0xe2,0x7a,0x20,0x3d,0xc5,0x79,0x81,0x0a,0x7f,0xb0,0x4d,
0xfd,0x02,0x03,0x01,0x00,0x01,
};

uint8_t g_rsa_public_key_4096[] = 
{
// ASN.1/DER
0x30,0x82,0x02,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
0x01,0x05,0x00,0x03,0x82,0x02,0x0f,0x00,0x30,0x82,0x02,0x0a,0x02,0x82,0x02,0x01,
0x00,0xc3,0x3d,0x92,0x63,0x9d,0x26,0x28,0x16,0x42,0x15,0xec,0xcd,0xd9,0x48,0xd5,
0x33,0x78,0xf2,0x33,0x05,0x8d,0x3b,0x10,0x1b,0x9e,0x4c,0x9d,0xda,0x00,0x97,0xa8,
0x9c,0xcb,0x95,0xf5,0x70,0x68,0x66,0xed,0xa0,0x07,0xcf,0x00,0xde,0x37,0x0d,0xef,
0x17,0xa6,0x33,0x96,0xcb,0x6c,0x2e,0x96,0xc4,0x58,0x64,0x45,0x27,0x54,0xee,0x0d,
0xaf,0xac,0x80,0xfe,0x51,0x7a,0x5c,0x2e,0x0c,0xea,0xef,0xea,0xeb,0xc3,0xd1,0x0b,
0x60,0xe2,0x46,0xfe,0x50,0x01,0x01,0xa7,0xf8,0x11,0x12,0xf7,0xc2,0xdc,0x71,0xb7,
0x32,0xd5,0x6a,0x09,0xf7,0x3c,0x11,0x91,0xda,0xf0,0x52,0xaa,0x9b,0x78,0x50,0xf8,
0x45,0xd0,0xd6,0xf5,0xf8,0x61,0xef,0x0c,0xda,0x9e,0x46,0x34,0xc5,0x33,0x81,0x16,
0xf0,0x4f,0xda,0x9d,0x9a,0x2b,0xc1,0x38,0x84,0x31,0x41,0x66,0xe0,0x64,0x40,0x14,
0x6a,0x1f,0xba,0x0e,0x73,0xec,0xe0,0x61,0xd0,0x7a,0x81,0x10,0x9e,0x2a,0x35,0xcc,
0x92,0x14,0x58,0xda,0x83,0x65,0xc2,0x28,0x44,0xe8,0xc6,0x4f,0x0a,0x31,0xac,0x74,
0x0c,0x59,0x2d,0x4a,0x59,0x2a,0xf2,0x20,0x84,0xc3,0xd1,0x13,0x5a,0x04,0x87,0x78,
0xf4,0xee,0xef,0xf9,0xe2,0xd2,0xe0,0x6a,0x1c,0x67,0x92,0xf0,0x59,0x9a,0x55,0x95,
0x3d,0x30,0x14,0xeb,0x2e,0xdc,0x78,0x3e,0xf5,0xe3,0x1d,0x37,0xd1,0x6c,0xd8,0x41,
0xb2,0x39,0x53,0x98,0xa7,0x60,0xf8,0x18,0xb9,0x73,0x54,0xa3,0x49,0x4a,0xfa,0x00,
0x00,0xf8,0x68,0x3c,0x4f,0xd1,0xad,0xdb,0xbe,0x46,0xfe,0x7c,0x25,0xf6,0xb7,0x1d,
0xaf,0xfe,0xf6,0xb0,0xec,0x1a,0x14,0x22,0xbd,0x34,0x85,0xad,0x32,0xef,0x92,0x40,
0xb3,0x4e,0x07,0x53,0xc6,0xc4,0xa1,0xac,0xaa,0x4c,0x7c,0xa7,0xe4,0x47,0xf0,0xaf,
0xb6,0xd9,0x3f,0xd1,0x34,0xb4,0x08,0x3e,0x74,0xb9,0xa9,0xb3,0x02,0xb9,0x57,0x80,
0x20,0x8f,0x37,0x55,0x39,0xe2,0xbd,0x4b,0x85,0xe7,0x3a,0x73,0xb9,0x2d,0x5e,0xd6,
0xfb,0x50,0x8e,0x80,0xa7,0x79,0xd8,0x4a,0x09,0xc9,0x1c,0xf6,0xd6,0x82,0xea,0x55,
0x87,0xe2,0x38,0x53,0x31,0xda,0x7c,0x0f,0x49,0xc5,0xca,0xad,0xc4,0x05,0x2b,0x41,
0x76,0x1f,0x81,0xc6,0x3d,0x6e,0x67,0xc7,0x06,0x22,0x0f,0xd9,0x72,0x80,0xad,0x87,
0x20,0x7b,0x52,0xe4,0x6b,0xa9,0xb9,0x08,0xf4,0x55,0x4e,0x06,0xfc,0x02,0xc9,0xc8,
0x4c,0xf7,0x59,0x4b,0x61,0xe4,0x40,0xda,0xc3,0x29,0x27,0x62,0x2b,0xed,0x04,0xb9,
0x8d,0x75,0x03,0xe0,0x1c,0xa3,0x27,0x7e,0x58,0x3b,0x29,0x3d,0xae,0xd7,0x59,0xad,
0xba,0x54,0x62,0xba,0x95,0xaf,0xfa,0x9d,0x3e,0xe7,0x96,0xa9,0x46,0xc9,0x39,0xf3,
0xef,0x26,0xab,0x46,0xdf,0x6f,0x79,0x3e,0x93,0xff,0x8b,0x6a,0x27,0xa7,0x54,0x90,
0xe6,0x49,0xdb,0xec,0x74,0x9e,0x2e,0xae,0x5f,0x7b,0xdb,0x9c,0x20,0x38,0x9f,0x84,
0x4a,0x53,0x96,0xc1,0x1b,0xec,0xd6,0x4e,0xad,0xdd,0x84,0xae,0x90,0x78,0xa4,0xc1,
0xf2,0xa3,0x6e,0x4c,0x4a,0xd1,0x98,0xcc,0xf9,0x76,0x7f,0x8a,0x3e,0xa5,0x60,0xeb,
0x55,0x4d,0xa5,0x36,0x1d,0x24,0x8a,0x9b,0x3f,0x3e,0xfb,0xe9,0xd7,0xdb,0x29,0xfb,
0x9b,0x02,0x03,0x01,0x00,0x01,
};

uint8_t g_dsa_message[] =
{
/* SHA256 of "Tempus unum hominem manet." */
0xb7,0x03,0xb9,0xc0,0x84,0xbe,0xe8,0xa2,0x78,0xa9,0x56,0x53,0x48,0x44,0xd7,0xfa,
0x40,0x10,0xa5,0x86,0x8c,0x0c,0x82,0xa4,0x50,0x6b,0xf8,0x1c,0x36,0x21,0x8d,0xe1,
};

// Signed with g_ecc_private_key_p256r1 DetK, HMAC_SHA256, ASN.1
uint8_t g_ecc_signature_p256r1[] =
{
0x30,0x45,0x02,0x21,0x00,0xaa,0x14,0x5c,0xc9,0x9f,0xc3,0x7b,0x77,0xa5,0xb8,0x54,
0xd8,0xe7,0xab,0x5e,0x92,0x52,0xcf,0xf2,0x5f,0xf6,0x12,0x7b,0x55,0x68,0xd7,0x1e,
0x06,0xbe,0x00,0xe6,0x01,0x02,0x20,0x64,0x58,0x99,0x0c,0xdd,0x99,0x9f,0x06,0x21,
0xb7,0x98,0x12,0x05,0x86,0x42,0xa4,0x11,0x89,0x28,0xd5,0x91,0x6a,0xf6,0x4b,0x0e,
0x0d,0x22,0xdb,0x73,0x3a,0xef,0x6e,
};

// Signed with g_ecc_private_key_p384r1 DetK, HMAC_SHA256 [sic], ASN.1
uint8_t g_ecc_signature_p384[] =
{
0x30,0x66,0x02,0x31,0x00,0xe3,0x4b,0xad,0x5d,0x67,0xda,0x72,0x57,0x84,0xec,0xb4,
0x04,0xd3,0xf2,0x49,0xd8,0xaf,0xf5,0x07,0x67,0xb3,0xc0,0x89,0xd8,0xc6,0x6c,0x70,
0x6d,0x44,0x8e,0xc1,0x70,0x30,0x62,0x18,0x17,0x9f,0x20,0xcd,0x76,0xbd,0x7b,0x7d,
0x46,0xca,0x0b,0x4a,0x9e,0x02,0x31,0x00,0xb4,0x91,0x58,0xdf,0x87,0xeb,0x9f,0x3b,
0xb1,0x85,0xf7,0x13,0x58,0x51,0xc4,0x09,0x0e,0x93,0xd3,0x06,0x3a,0x94,0x15,0x9c,
0x34,0x16,0x69,0x2b,0xeb,0x42,0x04,0xf4,0x16,0x0b,0x58,0xc8,0xe4,0xf9,0xa4,0x42,
0xe7,0x1b,0x9a,0xff,0xcc,0x7d,0x82,0xef,
};

// Signed with g_ecc_private_key_ed25519, Raw { R | S } little endian
uint8_t g_ecc_signature_ed25519[] =
{
0xdf,0x49,0x7d,0x8d,0xf9,0xfe,0x67,0x89,0x58,0x5d,0x4c,0xed,0x09,0x61,0x7d,0x38,
0x17,0xda,0xb8,0xcc,0x16,0x0a,0x79,0xbd,0x72,0x60,0x3d,0x56,0xaa,0x87,0x21,0x2e,
0x0f,0x3d,0x7c,0xb2,0xc2,0xb5,0x58,0xc3,0x9f,0xc9,0xe4,0x49,0x22,0x8d,0x78,0xf7,
0xbf,0x96,0x8a,0x3f,0xba,0xa8,0xf0,0x15,0xe8,0x5b,0xce,0xce,0xca,0x01,0x1d,0x0f,
};


// Always 256 bytes
uint8_t g_rsa_sig_2048[] =
{
0x94,0x57,0xc5,0x10,0x90,0x14,0xc6,0x5b,0x59,0xbb,0x8c,0x17,0xb7,0x27,0xde,0xe5,
0xbe,0x45,0x93,0x7c,0x00,0xfa,0xd1,0x7e,0xe7,0x6d,0x7e,0x88,0x28,0x0c,0x55,0x70,
0x95,0x3e,0xaa,0xbe,0x68,0x2f,0x77,0x1e,0x0a,0xb0,0x3d,0xba,0xa7,0x15,0x7c,0x6e,
0xa4,0xa2,0xb3,0xe3,0x43,0x8a,0x23,0x1e,0xf2,0x39,0xb7,0xcf,0x69,0xa9,0xf0,0xd2,
0x24,0x93,0x52,0xdb,0xa3,0x74,0x49,0xf4,0x7c,0x45,0xcc,0xe9,0x7c,0xdc,0x66,0xdb,
0xa3,0x68,0x03,0xcd,0xb8,0x92,0x2d,0xfa,0x78,0x52,0xe7,0x2c,0x6c,0xd2,0x60,0x46,
0x53,0x28,0x81,0x6e,0x1c,0xdf,0x0f,0x7a,0x23,0xa7,0xdc,0x8f,0xb8,0xb1,0x7c,0x1f,
0x61,0x8f,0x1e,0x69,0xaa,0x4a,0x7e,0x90,0x50,0x27,0x62,0xa2,0x5f,0xd0,0x54,0xb3,
0xc8,0x0b,0xa2,0xa0,0x27,0xfb,0xd6,0xf4,0x71,0xab,0x55,0x5c,0xae,0x2d,0x20,0x4a,
0x34,0xa2,0x6c,0x13,0x84,0xe3,0xfb,0x94,0x39,0xdd,0x43,0x7e,0x5d,0xf9,0xb0,0xfb,
0x89,0x85,0x50,0x43,0xd4,0x9d,0xeb,0x32,0x42,0xac,0x79,0x28,0x3d,0xac,0xff,0xde,
0xc4,0xd8,0xd2,0x29,0x37,0x2f,0xc0,0xf4,0x31,0xf4,0x6b,0xce,0x10,0xd6,0xc7,0xed,
0x2c,0x6f,0xd1,0x41,0x32,0xbf,0xfb,0xca,0x88,0xfb,0x8d,0x25,0x8d,0x60,0xe2,0x06,
0xb5,0x4b,0xf9,0xe3,0xa3,0xf5,0xeb,0x52,0x24,0x0c,0x6e,0xd7,0x85,0xb7,0x27,0x68,
0x86,0x19,0x14,0x24,0x2f,0xc7,0xd2,0x65,0x2e,0x0c,0x1c,0x1f,0xd2,0x4b,0x2b,0x49,
0xbe,0x5f,0x5e,0x72,0xa1,0x3f,0x47,0xd8,0x90,0x37,0xa4,0xaf,0x56,0x65,0x51,0x9e,
};

// Always 384 bytes
uint8_t g_rsa_sig_3072[] =
{
0x2d,0x26,0x39,0xb1,0x3c,0x5b,0xe5,0x12,0xf4,0x07,0x87,0x69,0xc8,0xec,0xfc,0xef,
0x19,0x0d,0x87,0xed,0x6c,0x72,0x42,0xa1,0xc2,0x09,0x0d,0x17,0x4a,0xbb,0xd8,0x81,
0x16,0xe9,0x80,0x86,0x95,0x5f,0x96,0x48,0x65,0xfd,0x27,0xe0,0x7e,0x5c,0xfa,0x3e,
0x42,0x96,0x2c,0x43,0x81,0x41,0x71,0xc1,0xd1,0x58,0xb8,0xb6,0x87,0x04,0xfc,0x37,
0x45,0x50,0xa6,0x3d,0xff,0x9c,0xb1,0xff,0x83,0xd5,0x33,0xd3,0x0c,0xce,0xc8,0x3f,
0xcc,0x51,0x00,0x50,0xdf,0xfa,0xe1,0x0a,0x10,0x7f,0xaf,0xae,0x63,0x9f,0xcc,0x47,
0xea,0x8e,0x19,0x38,0x6e,0xbc,0xde,0xec,0x01,0x6c,0x13,0xb9,0xdf,0x06,0xb8,0x69,
0x5a,0xea,0xad,0x52,0x0a,0xcc,0xb3,0xf1,0xe2,0xbb,0x91,0x74,0xf2,0x80,0x00,0xf1,
0xc9,0xe5,0x95,0xd1,0x6a,0x0a,0xbc,0x31,0x5e,0x6d,0x31,0x2c,0x08,0x3e,0xf2,0x63,
0x2c,0x19,0x23,0x09,0x25,0xab,0x49,0x01,0x3a,0x4c,0xb8,0x2b,0xde,0xa7,0x7c,0xad,
0x8a,0x64,0x36,0x56,0x29,0x0a,0x0d,0xed,0x8a,0xd7,0xe5,0xd5,0x22,0xe1,0xe9,0xcb,
0xbf,0xb0,0x6c,0x13,0x6b,0xce,0x4b,0x52,0xa6,0x77,0x84,0x4f,0x4e,0x3b,0xec,0x92,
0x68,0xd5,0x37,0x37,0x4f,0xba,0xe6,0x9d,0x4a,0xf1,0x2c,0xdc,0xa4,0x58,0x0f,0x99,
0xfa,0x1b,0x7a,0x50,0xcc,0x71,0x1c,0xac,0x43,0xfe,0x5d,0x66,0xa4,0x30,0x45,0x61,
0x7b,0x5e,0xc9,0x3f,0xa9,0x12,0xfc,0x71,0x2c,0xf6,0x1a,0x0b,0xf6,0x19,0x87,0x0a,
0x28,0x70,0x3d,0xfa,0x93,0x00,0xea,0x79,0x47,0x9e,0x4a,0x03,0xfa,0xb8,0xcf,0x34,
0xe7,0x96,0xc2,0x8a,0x20,0x21,0x4e,0xfc,0x03,0xff,0x4a,0xc7,0xa8,0xf4,0xff,0x4f,
0x56,0xda,0x6b,0xf2,0x80,0x19,0x43,0x41,0x58,0xe1,0x5f,0x25,0xe9,0x9f,0x0d,0x0f,
0xb6,0x63,0xf9,0xad,0x89,0xa5,0x95,0xab,0x89,0x60,0xe7,0xda,0x7a,0xac,0xd4,0x7c,
0x06,0x2d,0xcf,0x61,0x6c,0x99,0x8e,0xf2,0x84,0x08,0x30,0x3a,0xff,0x8c,0x1c,0x5b,
0xca,0xd5,0x75,0x25,0x2f,0x76,0x1d,0x4f,0x23,0xe2,0x0d,0x30,0x24,0xef,0x85,0x7b,
0x46,0x85,0x65,0xaa,0x4e,0xd3,0x21,0x50,0x0a,0x25,0x7f,0xb4,0x82,0x7e,0xf7,0x27,
0x37,0x8f,0xb7,0x94,0xe7,0x07,0x0b,0x81,0xa4,0x13,0xa4,0x31,0x2f,0xc1,0xf2,0x9a,
0x29,0x70,0x05,0x67,0xa5,0xeb,0x09,0xf4,0x5c,0xdd,0x45,0x85,0xe4,0xda,0x60,0xe1,
};

// Always 512 bytes
uint8_t g_rsa_sig_4096[] =
{
0x9f,0x30,0xd3,0xe2,0xba,0x89,0x5a,0x43,0x99,0x7b,0x84,0x6f,0x7b,0x26,0x33,0x1f,
0xb2,0x52,0x74,0x79,0x45,0x49,0xe6,0x82,0x33,0xa3,0x19,0x24,0x14,0x20,0x61,0xd3,
0x6f,0x89,0x76,0xb2,0x28,0x7f,0xf0,0x03,0x5e,0x12,0x75,0x13,0x81,0x32,0x2e,0xb5,
0x6a,0x60,0x2b,0xcd,0xe1,0x5c,0xc9,0x9e,0xe0,0xee,0x44,0xb8,0xee,0x50,0x74,0x80,
0xfc,0x68,0x60,0x6a,0xcf,0xf9,0x10,0x4e,0x97,0xaf,0xf4,0x42,0xcb,0x71,0x84,0x98,
0x55,0x8b,0x61,0x65,0xfd,0x9b,0x99,0xbe,0xd3,0xf9,0xc7,0x19,0x3c,0x15,0x3a,0xa4,
0x3d,0x7a,0xeb,0x0b,0x81,0x8b,0x86,0x5a,0xb4,0x25,0x68,0xe5,0x40,0x64,0xa7,0x2e,
0xc3,0x5e,0x6c,0x72,0xba,0x7f,0xcb,0xfd,0x91,0x9c,0x69,0x20,0x46,0xef,0xc5,0xd2,
0x73,0x30,0x43,0x6d,0x89,0x91,0xbf,0x41,0x99,0x81,0xfb,0xbc,0xcb,0xe1,0x9c,0xb1,
0x62,0x5a,0x41,0x3f,0xd6,0xb9,0xe2,0xd1,0x90,0xe1,0xd2,0x77,0xf4,0xde,0xcf,0xc1,
0xf0,0x62,0xf8,0x46,0x7e,0x8e,0xfc,0x43,0xe4,0xa3,0x75,0x49,0x1c,0xd7,0x02,0x72,
0x17,0xb8,0x7b,0x71,0x50,0x1c,0xda,0xef,0x4c,0x3d,0x85,0x7b,0xd1,0x27,0x25,0x60,
0x3a,0xb2,0x0f,0x2b,0x7b,0xc2,0x65,0x9b,0xef,0x63,0x25,0xe2,0xfe,0x42,0x70,0xc7,
0x8d,0x40,0xb0,0xd9,0xba,0x94,0xd3,0x9b,0x1c,0x33,0x7d,0x54,0x3d,0xf8,0x30,0xaf,
0x98,0x11,0x6e,0x2d,0x8a,0x21,0xd6,0x1a,0xa7,0x22,0x1e,0x05,0xde,0xb3,0x66,0x04,
0x2c,0x20,0xf6,0xc6,0xb5,0xf7,0x40,0x58,0x50,0xe5,0xf8,0x9b,0xf9,0x11,0x1a,0x2e,
0x41,0x61,0x40,0xa9,0xca,0x3f,0x4e,0xe0,0xee,0x1c,0x3b,0xae,0x73,0x10,0xaa,0xdf,
0x94,0xd4,0xd8,0x49,0x30,0xc7,0x61,0x5b,0x67,0x80,0x5b,0x2b,0xa2,0x14,0x46,0x67,
0xe7,0x8c,0x11,0xc4,0xfc,0x00,0xd5,0xf3,0x99,0xfb,0x00,0x04,0x12,0x72,0x0c,0x23,
0xf5,0xc6,0xa1,0xaf,0xfa,0x27,0x7a,0xb8,0xb8,0xef,0x5c,0x05,0x95,0x9c,0x09,0xa5,
0xf5,0x90,0x56,0x70,0x4f,0xf9,0x17,0x06,0xa4,0xad,0x65,0x91,0x14,0x20,0x46,0x39,
0x2a,0xe0,0xaf,0xbe,0xab,0x14,0xf4,0x14,0x6d,0xa6,0x34,0xfc,0x5c,0xd7,0x9e,0xad,
0x59,0x8e,0x84,0xfc,0xe2,0x99,0x0c,0x7f,0x46,0xfd,0x28,0x50,0xa0,0x55,0x51,0x74,
0xc8,0x2f,0x47,0x00,0x7a,0x24,0x31,0x97,0x74,0xdd,0xb6,0x06,0x8b,0xce,0xcf,0x20,
0x35,0x2e,0x2b,0x9d,0x28,0x7c,0x8a,0xf5,0x02,0x0f,0xb3,0xb8,0x71,0x9d,0xc3,0xed,
0x97,0x2b,0xf7,0x88,0x87,0xa9,0x91,0xd4,0x26,0x38,0xdc,0x04,0xfb,0x2b,0x6e,0xae,
0xc4,0x1e,0x14,0x75,0xa3,0xa4,0xb5,0xd9,0xa6,0xe2,0xf0,0xb5,0xdb,0xab,0xa3,0x56,
0x6d,0x21,0xb4,0x71,0xd4,0x20,0xf3,0xfe,0x82,0xfb,0x09,0x5d,0x6d,0xc3,0x22,0x87,
0x7e,0xa9,0x92,0x62,0xf3,0x49,0x8c,0x88,0x17,0x7e,0xf3,0x76,0x12,0x7d,0x36,0x09,
0x97,0xdc,0x28,0x2a,0x73,0xe6,0x91,0xcb,0x0b,0xbc,0x4d,0xe3,0x7f,0x91,0xad,0x8c,
0x99,0x47,0x51,0x70,0x12,0x6f,0x58,0x55,0x5b,0xc2,0x43,0xa8,0xf8,0xc8,0xa3,0xb2,
0x63,0x59,0xa6,0x36,0xd8,0x53,0x1c,0x2a,0xa0,0x94,0xb4,0x0e,0x36,0x0d,0x5a,0x68,
};

/* see ee_dsa_alg_t in ee_bench.h */
uint8_t *g_public_keys[] = {
    g_ecc_public_key_p256r1,
    g_ecc_public_key_p384,
    g_ecc_public_key_c25519,
    g_ecc_public_key_ed25519,
    g_rsa_public_key_2048,
    g_rsa_public_key_3072,
    g_rsa_public_key_4096,
};

/* see ee_dsa_alg_t in ee_bench.h */
uint32_t g_public_key_sizes[] = {
    64 + 1,
    96 + 1,
    32,
    32,
    /* Yes, these are ASN.1 so we could extract size, but this is quicker. */
    294,
    422,
    550,
};

/* see ee_dsa_alg_t in ee_bench.h */
uint8_t *g_dsa_signatures[] = {
    g_ecc_signature_p256r1,
    g_ecc_signature_p384,
    0,
    g_ecc_signature_ed25519,
    g_rsa_sig_2048,
    g_rsa_sig_3072,
    g_rsa_sig_4096,
};

/* see ee_dsa_alg_t in ee_bench.h */
uint32_t g_dsa_signature_sizes[] = {
    71,
    104,
    0,
    64,
    256,
    384,
    512
};

// clang-format on

#endif /* __KEYS_H */
