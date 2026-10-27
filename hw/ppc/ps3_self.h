/*
 * SELF stage decryption for the PS3 boot path.
 *
 * Local research model, not intended for upstream QEMU contributions.
 *
 * The chain after lv0ldr.2 is delivered as SELF modules (lv1ldr, lv2ldr, appldr,
 * isoldr): a 0x20-byte certified-file header, an encrypted metadata block whose
 * keys are the loader ERK/RIV pairs, and AES-128-CTR sections after that.  This
 * is the same open the loader does on the console, written here so the stage
 * tests can feed the decrypted segments to the SPU model instead of checking
 * the containers structurally.
 *
 * The key candidates come from the loader ERK/RIV table (builtin_ldr_keys in
 * ps3tools, the same table scetool and readself search).  A candidate is only
 * accepted when the decrypted root header's two padding fields are zero, which
 * is what the loader's own check tests.
 *
 * The loader SELFs carved out of a decrypted lv0 are not all still sealed: some
 * have already been unselfed, and their section table keeps saying "encrypted"
 * while the bytes are the plaintext image.  The opener decides from the largest
 * section (an SPU image decodes as instructions almost word for word where
 * ciphertext manages a little over half by chance) and then treats the whole
 * file the same way, so such a carve is left as it is instead of being decrypted
 * a second time into noise.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* How many loader keysets the search covers. */
unsigned ps3_self_key_count(void);

/*
 * Decrypt the metadata and every section of `img` in place.  `img` must be
 * writable and hold the whole SELF.  Returns true when a keyset opened the
 * metadata; `why` receives a one-line description either way.
 */
bool ps3_self_decrypt(uint8_t *img, size_t len, char *why, size_t why_len);

/*
 * The application / VSH keyset, used by the SELF that appldr loads from
 * /dev_flash/vsh/module.  Same format as the loader table; kept separate so a
 * loader image never lands on an application key by accident.
 */
bool ps3_self_decrypt_app(uint8_t *img, size_t len, char *why, size_t why_len);

/* Open with one caller-supplied ERK/RIV pair (hex, 64 and 32 digits). */
bool ps3_self_decrypt_key(uint8_t *img, size_t len, const char *erk,
                          const char *riv, char *why, size_t why_len);

/*
 * The .2 loaders keep their ERK wrapped under the console's per-console root
 * key 2.  Unwrap it (32 bytes in, 32 out) and then open the SELF with it; both
 * steps run on the caller's own PCK2, never on a key compiled into the model.
 */
void ps3_self_unwrap_erk(const uint8_t wrapped[32], const uint8_t pck2[48],
                         uint8_t erk[32]);
bool ps3_self_decrypt_pck2(uint8_t *img, size_t len, const uint8_t pck2[48],
                           char *why, size_t why_len);

/*
 * Open `img` and hand back the ERK it was opened with (32 bytes of key, 16 of
 * RIV).  `erk_hex`/`riv_hex` are tried first and may be NULL; the loader table
 * follows.  `from_table` reports which won, so a caller that wants a per-console
 * key is never handed a published one without being told.
 */
bool ps3_self_decrypt_erk(uint8_t *img, size_t len, const char *erk_hex,
                          const char *riv_hex, uint8_t erk_out[48],
                          bool *from_table, char *why, size_t why_len);

/*
 * The .2 route to the same key: unwrap the wrapped ERK the loader carries with
 * the console's PCK2, confirmed by opening the loader with it.  Hands back the
 * unwrapped 48 bytes and, when `off_out` is given, where the wrapped value was.
 */
bool ps3_self_unwrap_erk_in_image(uint8_t *img, size_t len, const uint8_t pck2[48],
                                  uint8_t erk_out[48], size_t *off_out,
                                  char *why, size_t why_len);

/*
 * Decrypt `img`, then place its segments into `ls` at their link addresses and
 * return the entry point.  Segments with no file data are zero-filled, which is
 * what the loader does for .bss.  Returns 0 on success, 1 when no keyset opened
 * it, 2 when the image is not a SELF, 3 when a segment does not fit `ls`.
 */
int ps3_self_load_ls(uint8_t *img, size_t len, uint8_t *ls, size_t ls_size,
                     uint32_t *entry, unsigned *segments, char *why,
                     size_t why_len);
