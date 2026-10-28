/*
 * PS3 AES primitives
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AES-128 is here because the SPU mask ROM's container opener is built around
 * it: the ROM expands the channel-66 half into a key, encrypts one block to
 * unwrap the container key, then runs CBC-MAC and CTR over the header.  The
 * AES-256 CBC and XTS below are the HDD side: lv1ldr turns the console's EID
 * root key into ATA data and tweak keys, and those encrypt every sector.
 */

#include "qemu/osdep.h"
#include "ps3_aes.h"
#include "aes.h"

/* ---------------------------------------------------------------------- */
/* AES-128, encryption direction only: the boot ROM only ever encrypts.    */

static const uint8_t ps3_aes_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static const uint8_t ps3_aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
};

static void ps3_aes_xtime(uint8_t *b)
{
    uint8_t hi = *b & 0x80;

    *b <<= 1;

    if (hi) {
        *b ^= 0x1B;
    }
}

void ps3_aes_expand_key(const uint8_t key[16], uint8_t rk[176])
{
    int i;
    uint8_t t[4];

    memcpy(rk, key, 16);

    for (i = 4; i < 44; i++) {
        memcpy(t, rk + (i - 1) * 4, 4);

        if ((i % 4) == 0) {
            uint8_t first = t[0];

            t[0] = ps3_aes_sbox[t[1]];
            t[1] = ps3_aes_sbox[t[2]];
            t[2] = ps3_aes_sbox[t[3]];
            t[3] = ps3_aes_sbox[first];
            t[0] ^= ps3_aes_rcon[i / 4];
        }

        rk[i * 4 + 0] = rk[(i - 4) * 4 + 0] ^ t[0];
        rk[i * 4 + 1] = rk[(i - 4) * 4 + 1] ^ t[1];
        rk[i * 4 + 2] = rk[(i - 4) * 4 + 2] ^ t[2];
        rk[i * 4 + 3] = rk[(i - 4) * 4 + 3] ^ t[3];
    }
}

void ps3_aes_encrypt(const uint8_t rk[176], const uint8_t in[16],
                     uint8_t out[16])
{
    uint8_t state[16];
    int round, i;

    memcpy(state, in, 16);

    for (i = 0; i < 16; i++) {
        state[i] ^= rk[i];
    }

    for (round = 1; round <= 10; round++) {
        uint8_t tmp[16];

        /* SubBytes and ShiftRows (row r rotates left by r).  The state is
         * column-major, so the flat index of (row r, column c) is 4*c + r. */
        for (i = 0; i < 16; i++) {
            int row = i % 4;
            int col = i / 4;

            tmp[i] = ps3_aes_sbox[state[((col + row) % 4) * 4 + row]];
        }

        if (round != 10) {
            /* MixColumns. */
            for (i = 0; i < 4; i++) {
                uint8_t a0 = tmp[i * 4 + 0];
                uint8_t a1 = tmp[i * 4 + 1];
                uint8_t a2 = tmp[i * 4 + 2];
                uint8_t a3 = tmp[i * 4 + 3];
                uint8_t x0 = a0, x1 = a1, x2 = a2, x3 = a3;
                uint8_t m0, m1, m2, m3;

                ps3_aes_xtime(&x0);
                ps3_aes_xtime(&x1);
                ps3_aes_xtime(&x2);
                ps3_aes_xtime(&x3);

                m0 = x0 ^ x1 ^ a1 ^ a2 ^ a3;
                m1 = a0 ^ x1 ^ x2 ^ a2 ^ a3;
                m2 = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                m3 = x0 ^ a0 ^ a1 ^ a2 ^ x3;
                tmp[i * 4 + 0] = m0;
                tmp[i * 4 + 1] = m1;
                tmp[i * 4 + 2] = m2;
                tmp[i * 4 + 3] = m3;
            }
        }

        for (i = 0; i < 16; i++) {
            state[i] = tmp[i] ^ rk[round * 16 + i];
        }
    }

    memcpy(out, state, 16);
}

void ps3_aes_ctr_block(const uint8_t rk[176], uint32_t counter,
                       const uint8_t suffix[12], uint8_t out[16])
{
    uint8_t block[16];

    block[0] = counter >> 24;
    block[1] = counter >> 16;
    block[2] = counter >> 8;
    block[3] = counter;
    memcpy(block + 4, suffix, 12);
    ps3_aes_encrypt(rk, block, out);
}

/* ---------------------------------------------------------------------- */
/* AES-256 CBC: the key ladder, and the ATA keys lv1ldr derives from PCK1. */

void ps3_aes_cbc256_encrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    aes_context ctxt;
    uint8_t chain[16];

    if ((len & 15) || !len) {
        return;
    }

    if (aes_setkey_enc(&ctxt, key, 256) != 0) {
        memset(out, 0, len);
        return;
    }

    memcpy(chain, iv, 16);
    aes_crypt_cbc(&ctxt, AES_ENCRYPT, len, chain, in, out);
}

void ps3_aes_cbc256_decrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len)
{
    aes_context ctxt;
    uint8_t chain[16];

    if ((len & 15) || !len) {
        return;
    }

    if (aes_setkey_dec(&ctxt, key, 256) != 0) {
        memset(out, 0, len);
        return;
    }

    memcpy(chain, iv, 16);
    aes_crypt_cbc(&ctxt, AES_DECRYPT, len, chain, in, out);
}

/*
 * The four seeds in the order `ps3_ladder_seeds' hands them back, which is also
 * the order lv1ldr carries them: encdec data, SB indiv data, encdec tweak, SB
 * indiv tweak.  This is the model's copy, used when no loader image is given.
 */
static const uint8_t ps3_ladder_default[128] = {
    /* encdec data (ks_1) */
    0xE2, 0xD0, 0x5D, 0x40, 0x71, 0x94, 0x5B, 0x01,
    0xC3, 0x6D, 0x51, 0x51, 0xE8, 0x8C, 0xB8, 0x33,
    0x4A, 0xAA, 0x29, 0x80, 0x81, 0xD8, 0xC4, 0x4F,
    0x18, 0x5D, 0xC6, 0x60, 0xED, 0x57, 0x56, 0x86,
    /* SB indiv data (ATA data) */
    0xD9, 0x2D, 0x65, 0xDB, 0x05, 0x7D, 0x49, 0xE1,
    0xA6, 0x6F, 0x22, 0x74, 0xB8, 0xBA, 0xC5, 0x08,
    0x83, 0x84, 0x4E, 0xD7, 0x56, 0xCA, 0x79, 0x51,
    0x63, 0x62, 0xEA, 0x8A, 0xDA, 0xC6, 0x03, 0x26,
    /* encdec tweak (ks_3) */
    0x02, 0x08, 0x32, 0x92, 0xC3, 0x05, 0xD5, 0x38,
    0xBC, 0x50, 0xE6, 0x99, 0x71, 0x0C, 0x0A, 0x3E,
    0x55, 0xF5, 0x1C, 0xBA, 0xA5, 0x35, 0xA3, 0x80,
    0x30, 0xB6, 0x7F, 0x79, 0xC9, 0x05, 0xBD, 0xA3,
    /* SB indiv tweak (ATA tweak) */
    0xC3, 0xB3, 0xB5, 0xAA, 0xCC, 0x74, 0xCD, 0x6A,
    0x48, 0xEF, 0xAB, 0xF4, 0x4D, 0xCD, 0xF1, 0x6E,
    0x37, 0x9F, 0x55, 0xF5, 0x77, 0x7D, 0x09, 0xFB,
    0xEE, 0xDE, 0x07, 0x05, 0x8E, 0x94, 0xBE, 0x08,
};

/*
 * The two layouts the loaders are seen to carry: the four blocks back to back,
 * the ATA pair and the encdec pair in one order or the other.  A block is
 * recognised by its *content*, so no offset is assumed anywhere.
 */
static void ps3_ladder_views(const uint8_t *seeds[2][4])
{
    seeds[0][0] = ps3_ladder_default + 0x00;      /* encdec data  */
    seeds[0][1] = ps3_ladder_default + 0x20;      /* sb indiv data*/
    seeds[0][2] = ps3_ladder_default + 0x40;      /* encdec tweak */
    seeds[0][3] = ps3_ladder_default + 0x60;      /* sb indiv tweak*/
    seeds[1][0] = ps3_ladder_default + 0x20;      /* the other interleave */
    seeds[1][1] = ps3_ladder_default + 0x00;
    seeds[1][2] = ps3_ladder_default + 0x60;
    seeds[1][3] = ps3_ladder_default + 0x40;
}

bool ps3_ladder_seeds(const uint8_t *img, size_t len, uint8_t seeds[128],
                      size_t *off, char *why, size_t why_len)
{
    const uint8_t *views[2][4];
    size_t i;

    ps3_ladder_views(views);

    if (len < 128) {
        snprintf(why, why_len, "the image is shorter than one seed block");
        return false;
    }

    for (i = 0; i + 128 <= len; i += 4) {
        unsigned l;

        for (l = 0; l < 2; l++) {
            if (!memcmp(img + i, views[l][0], 32) &&
                !memcmp(img + i + 0x20, views[l][1], 32) &&
                !memcmp(img + i + 0x40, views[l][2], 32) &&
                !memcmp(img + i + 0x60, views[l][3], 32)) {
                memcpy(seeds + 0x00, views[l][0], 32);
                memcpy(seeds + 0x20, views[l][1], 32);
                memcpy(seeds + 0x40, views[l][2], 32);
                memcpy(seeds + 0x60, views[l][3], 32);
                if (off) {
                    *off = i;
                }
                return true;
            }
        }
    }

    snprintf(why, why_len, "no ladder seed block (the four published encdec / "
             "SB-indiv seeds) anywhere in the image");
    return false;
}

void ps3_ata_keys_seeds(const uint8_t erk[48], const uint8_t seeds[128],
                        uint8_t data_key[32], uint8_t tweak_key[32])
{
    ps3_aes_cbc256_encrypt(erk, erk + 32, seeds + 0x20, data_key, 32);
    ps3_aes_cbc256_encrypt(erk, erk + 32, seeds + 0x60, tweak_key, 32);
}

void ps3_encdec_keys_seeds(const uint8_t erk[48], const uint8_t seeds[128],
                           uint8_t data_key[32], uint8_t tweak_key[32])
{
    ps3_aes_cbc256_encrypt(erk, erk + 32, seeds + 0x00, data_key, 32);
    ps3_aes_cbc256_encrypt(erk, erk + 32, seeds + 0x40, tweak_key, 32);
}

void ps3_ata_keys(const uint8_t erk[48], uint8_t data_key[32],
                  uint8_t tweak_key[32])
{
    ps3_ata_keys_seeds(erk, ps3_ladder_default, data_key, tweak_key);
}

void ps3_encdec_keys(const uint8_t erk[48], uint8_t data_key[32],
                     uint8_t tweak_key[32])
{
    ps3_encdec_keys_seeds(erk, ps3_ladder_default, data_key, tweak_key);
}

/* ---------------------------------------------------------------------- */
/* XTS-AES over one sector: the HDD's data area and the eMMC's storage.     */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* Known answers, so a broken AES-256 or XTS path fails at boot, not later. */

bool ps3_aes_selftest(char *why, size_t why_len)
{
    static const uint8_t cbc_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    static const uint8_t cbc_pt[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    static const uint8_t cbc_ct[32] = {
        0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
        0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
        0xC7, 0x71, 0x47, 0xEB, 0xD5, 0x12, 0x1D, 0xE8,
        0xD0, 0xFA, 0xE7, 0x76, 0x24, 0x23, 0xB6, 0xBF,
    };
    /* ERK 00..2F -> ATA keys -> XTS of (i * 7 + 3) & 0xFF, sector 0. */
    static const uint8_t xts_ct[64] = {
        0x3A, 0x8C, 0x89, 0xCA, 0xB0, 0x36, 0x01, 0x2A,
        0x4E, 0xE8, 0x48, 0xE9, 0x81, 0x9C, 0x28, 0x1A,
        0x79, 0xBF, 0x4D, 0xA7, 0xD6, 0x4C, 0x91, 0x55,
        0xD0, 0xDB, 0xBF, 0x7A, 0x22, 0x52, 0x38, 0xAA,
        0xB4, 0xA2, 0x16, 0xE2, 0x05, 0xA1, 0xD6, 0x3A,
        0x07, 0x5A, 0x01, 0x30, 0xF4, 0x4F, 0x93, 0xB4,
        0xB1, 0x9B, 0xD2, 0x0B, 0x62, 0x06, 0x98, 0x71,
        0x9B, 0x8F, 0x9E, 0x44, 0x01, 0x98, 0x3B, 0xAF,
    };
    uint8_t zero_iv[16] = { 0 };
    uint8_t got[64], plain[64];
    uint8_t erk[48], data_key[32], tweak_key[32];
    unsigned i;

    ps3_aes_cbc256_encrypt(cbc_key, zero_iv, cbc_pt, got, sizeof(cbc_pt));
    if (memcmp(got, cbc_ct, sizeof(cbc_ct))) {
        snprintf(why, why_len, "AES-256-CBC known answer");
        return false;
    }

    for (i = 0; i < sizeof(erk); i++) {
        erk[i] = i;
    }
    for (i = 0; i < sizeof(plain); i++) {
        plain[i] = i * 7 + 3;
    }

    ps3_ata_keys(erk, data_key, tweak_key);
    memcpy(got, plain, sizeof(got));
    ps3_xts_crypt_sector(data_key, tweak_key, 0, got, sizeof(got), true);
    if (memcmp(got, xts_ct, sizeof(xts_ct))) {
        snprintf(why, why_len, "ATA derivation and XTS known answer");
        return false;
    }

    ps3_xts_crypt_sector(data_key, tweak_key, 0, got, sizeof(got), false);
    if (memcmp(got, plain, sizeof(got))) {
        snprintf(why, why_len, "XTS decrypt does not return the plaintext");
        return false;
    }

    /*
     * The loader-driven ladder: a block found in an image must derive exactly
     * the keys the model's own copy of the seeds derives, and an image without
     * the published seeds must not produce a block at all.  This is what keeps
     * `lv1ldr' honest - it can only ever supply the console's own seeds.
     */
    {
        uint8_t image[512], seeds[128], got_data[32], got_tweak[32];
        size_t off = 0;
        char sub[160];

        memset(image, 0x11, sizeof(image));
        memcpy(image + 200, ps3_ladder_default, sizeof(seeds));
        if (!ps3_ladder_seeds(image, sizeof(image), seeds, &off, sub,
                              sizeof(sub)) || off != 200 ||
            memcmp(seeds, ps3_ladder_default, sizeof(seeds))) {
            snprintf(why, why_len, "the seed block was not found where it was "
                     "planted (%s)", sub);
            return false;
        }
        ps3_ata_keys_seeds(erk, seeds, got_data, got_tweak);
        if (memcmp(got_data, data_key, 32) || memcmp(got_tweak, tweak_key, 32)) {
            snprintf(why, why_len, "the block's ATA keys differ from the "
                     "published seeds'");
            return false;
        }
        image[200 + 0x20] ^= 0x01;      /* one seed byte off: not a block */
        if (ps3_ladder_seeds(image, sizeof(image), seeds, &off, sub,
                             sizeof(sub))) {
            snprintf(why, why_len, "a corrupted seed block was accepted");
            return false;
        }
    }

    /* The eMMC path: the encdec ladder, then one whole sector each way. */
    {
        uint8_t sector_pt[512], sector_ct[512];

        for (i = 0; i < sizeof(sector_pt); i++) {
            sector_pt[i] = (i * 13 + 5) & 0xFF;
        }
        ps3_encdec_keys(erk, data_key, tweak_key);
        memcpy(sector_ct, sector_pt, sizeof(sector_ct));
        ps3_xts_crypt_sector(data_key, tweak_key, 9, sector_ct,
                             sizeof(sector_ct), true);
        if (!memcmp(sector_ct, sector_pt, sizeof(sector_ct))) {
            snprintf(why, why_len,
                     "the eMMC path did not encrypt the sector");
            return false;
        }
        ps3_xts_crypt_sector(data_key, tweak_key, 9, sector_ct,
                             sizeof(sector_ct), false);
        if (memcmp(sector_ct, sector_pt, sizeof(sector_ct))) {
            snprintf(why, why_len,
                     "the eMMC path does not return the plaintext");
            return false;
        }

        /* A different address has to move the ciphertext. */
        memcpy(sector_ct, sector_pt, sizeof(sector_ct));
        ps3_xts_crypt_sector(data_key, tweak_key, 10, sector_ct,
                             sizeof(sector_ct), true);
        ps3_xts_crypt_sector(data_key, tweak_key, 9, sector_ct,
                             sizeof(sector_ct), false);
        if (!memcmp(sector_ct, sector_pt, sizeof(sector_ct))) {
            snprintf(why, why_len,
                     "the eMMC sector number is not part of the tweak");
            return false;
        }
    }

    return true;
}

void ps3_xts_crypt_sector(const uint8_t data_key[32],
                          const uint8_t tweak_key[32], uint64_t sector,
                          uint8_t *buf, size_t len, bool encrypt)
{
    aes_context data, tweak_ctx;
    uint8_t tw[16], block[16];
    size_t off;
    unsigned i;

    if (!len || (len & 15)) {
        return;
    }

    if (aes_setkey_enc(&tweak_ctx, tweak_key, 256) != 0) {
        return;
    }
    if ((encrypt ? aes_setkey_enc(&data, data_key, 256)
                 : aes_setkey_dec(&data, data_key, 256)) != 0) {
        return;
    }

    /* The sector number is the tweak, little-endian in the first 8 bytes. */
    memset(tw, 0, sizeof(tw));
    for (i = 0; i < 8; i++) {
        tw[i] = (sector >> (8 * i)) & 0xFF;
    }
    aes_crypt_ecb(&tweak_ctx, AES_ENCRYPT, tw, tw);

    for (off = 0; off < len; off += 16) {
        uint8_t carry_in = 0, carry_out = 0;

        for (i = 0; i < 16; i++) {
            block[i] = buf[off + i] ^ tw[i];
        }

        aes_crypt_ecb(&data, encrypt ? AES_ENCRYPT : AES_DECRYPT, block,
                      block);

        for (i = 0; i < 16; i++) {
            buf[off + i] = block[i] ^ tw[i];
        }

        /* Advance the tweak: multiply by x in GF(2^128). */
        for (i = 0; i < 16; i++) {
            carry_out = (tw[i] >> 7) & 1;
            tw[i] = ((tw[i] << 1) + carry_in) & 0xFF;
            carry_in = carry_out;
        }
        if (carry_out) {
            tw[0] ^= 0x87;
        }
    }
}
