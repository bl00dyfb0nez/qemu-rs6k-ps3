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
 * Decrypt `img`, then place its segments into `ls` at their link addresses and
 * return the entry point.  Segments with no file data are zero-filled, which is
 * what the loader does for .bss.  Returns 0 on success, 1 when no keyset opened
 * it, 2 when the image is not a SELF, 3 when a segment does not fit `ls`.
 */
int ps3_self_load_ls(uint8_t *img, size_t len, uint8_t *ls, size_t ls_size,
                     uint32_t *entry, unsigned *segments, char *why,
                     size_t why_len);
