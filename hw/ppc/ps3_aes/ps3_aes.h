/*
 * PS3 AES primitives
 *
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The block cipher the boot ROM's container opener carries, plus the AES-256
 * CBC key ladder and the XTS-AES the console's HDD is encrypted with.  The
 * cipher itself is PolarSSL's (aes.c, GPLv2); this file is the PS3-specific
 * layer over it so the board model holds the device, not the maths.
 */

#ifndef PS3_AES_H
#define PS3_AES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * AES-128 in the shape the container opener uses: an expanded key is 176
 * bytes, and the CTR block is a 32-bit counter followed by twelve bytes of
 * the header (the ROM's own counter block layout).
 */
void ps3_aes_expand_key(const uint8_t key[16], uint8_t rk[176]);
void ps3_aes_encrypt(const uint8_t rk[176], const uint8_t in[16],
                     uint8_t out[16]);
void ps3_aes_ctr_block(const uint8_t rk[176], uint32_t counter,
                       const uint8_t suffix[12], uint8_t out[16]);

/*
 * AES-256-CBC both ways: the key ladder metldr runs (encrypt) and the
 * unwrapping of what the ladder sealed (decrypt), which is how the console's
 * HDD key sector and the wrapped per-console ERK are read back.
 */
void ps3_aes_cbc256_encrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len);
void ps3_aes_cbc256_decrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *in, uint8_t *out, size_t len);

/*
 * The console's ATA data and tweak keys, derived from its 48-byte EID root
 * key (PCK1: 32 bytes of key, then the 16-byte IV) with the static
 * "SB indiv" seeds.  PCK1 itself never encrypts disk data: these two keys do,
 * through XTS, which is what makes a console with its PCK1 able to read its
 * HDD however often it was reformatted.
 */
void ps3_ata_keys(const uint8_t erk[48], uint8_t data_key[32],
                  uint8_t tweak_key[32]);

/*
 * The same ladder over a 0x80-byte seed block the caller supplies, which is how
 * the loader runs it: lv1ldr carries the four seeds and feeds them through PCK1.
 * A block read out of the console's own lv1ldr therefore keys the disk from the
 * console's own image, with nothing baked into the model.  The block is in
 * `ps3_ladder_seeds' order, whatever order it was found in.
 */
void ps3_ata_keys_seeds(const uint8_t erk[48], const uint8_t seeds[128],
                        uint8_t data_key[32], uint8_t tweak_key[32]);
void ps3_encdec_keys_seeds(const uint8_t erk[48], const uint8_t seeds[128],
                           uint8_t data_key[32], uint8_t tweak_key[32]);

/*
 * Find the loader's ladder seed block in an image and hand it back in the
 * canonical order (encdec data, SB indiv data, encdec tweak, SB indiv tweak).
 * The four seeds are published constants, so a match is a real identification
 * of the block rather than a guess about a position: `off' receives where it
 * was, which is how a revision that moves it is noticed instead of assumed.
 * Returns false when the image has no such block.
 */
bool ps3_ladder_seeds(const uint8_t *img, size_t len, uint8_t seeds[128],
                      size_t *off, char *why, size_t why_len);

/*
 * The flash keys: the "encdec" half of the same ladder, which is what the
 * console encrypts its eMMC storage sectors with.  A superslim keeps its
 * firmware on eMMC instead of the NOR, so PCK1 has to yield these as well as
 * the ATA pair.  The eMMC's *flash* area is NAND and stays plaintext; only the
 * storage area past it is sealed under these keys.
 */
void ps3_encdec_keys(const uint8_t erk[48], uint8_t data_key[32],
                     uint8_t tweak_key[32]);

/*
 * XTS-AES over one sector with the ATA keys: 256-bit data and tweak keys,
 * the sizes naehrwert's ps3_decrypt_tools derive and the order the consoles'
 * ATA controllers use.  `sector` is the sector number; `len` must be a
 * multiple of 16 and no larger than a sector (512 bytes).  The eMMC's storage
 * area goes through this same function, with the encdec pair above instead:
 * one cipher, two ladders, exactly as the console's own encdec block does it.
 */
void ps3_xts_crypt_sector(const uint8_t data_key[32],
                          const uint8_t tweak_key[32], uint64_t sector,
                          uint8_t *buf, size_t len, bool encrypt);

/*
 * Known-answer check over the AES-256 CBC and XTS paths: the AES-256-CBC
 * vector is FIPS-197's key schedule over a fixed block, and the XTS one is
 * the ATA derivation of a test ERK followed by a sector encryption, both
 * cross-checked against an independent implementation.  Returns false and
 * fills `why` when a step disagrees.
 */
bool ps3_aes_selftest(char *why, size_t why_len);

#endif /* PS3_AES_H */
